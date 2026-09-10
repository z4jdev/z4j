"""Native Windows handle-relative I/O for the Boundary-F safe store.

Python exposes no ``dir_fd`` operations on Windows.  Opening child paths by
string after validating their parent would therefore reintroduce the parent
rename/reparse race that the safe store is meant to close.  This module keeps a
verified directory handle open and uses ``NtCreateFile`` with that handle as
``RootDirectory`` for every child open.  Replacement and deletion likewise use
held handles rather than reopening public pathnames.

The module is imported only on Windows.
"""

# ruff: noqa: N801

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import os
from collections.abc import Callable, Iterable, Iterator
from ctypes import wintypes
from pathlib import Path

if os.name != "nt":  # pragma: no cover - import contract
    raise ImportError("_windows_secure_io is available only on Windows")


class WindowsSecureIOError(OSError):
    """A native Windows safety or filesystem operation failed."""


INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
READ_CONTROL = 0x00020000
SYNCHRONIZE = 0x00100000
FILE_LIST_DIRECTORY = 0x0001
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
FILE_SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
OPEN_EXISTING = 3
FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_OPEN = 1
FILE_CREATE = 2
FILE_OPEN_IF = 3
FILE_DIRECTORY_FILE = 0x00000001
FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000
OBJ_CASE_INSENSITIVE = 0x00000040
FILE_DISPOSITION_INFO_CLASS = 4
NT_FILE_RENAME_INFORMATION_CLASS = 10
LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
SDDL_REVISION_1 = 1
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_ALREADY_EXISTS = 183
ERROR_FILE_EXISTS = 80
OWNER_RIGHTS_SID = "S-1-3-4"


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UNICODE_STRING)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class _IO_STATUS_VALUE(ctypes.Union):
    _fields_ = [
        ("Status", wintypes.LONG),
        ("Pointer", wintypes.LPVOID),
    ]


class _IO_STATUS_BLOCK(ctypes.Structure):
    _anonymous_ = ("value",)
    _fields_ = [
        ("value", _IO_STATUS_VALUE),
        ("Information", ctypes.c_size_t),
    ]


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _ACL(ctypes.Structure):
    _fields_ = [
        ("AclRevision", wintypes.BYTE),
        ("Sbz1", wintypes.BYTE),
        ("AclSize", wintypes.WORD),
        ("AceCount", wintypes.WORD),
        ("Sbz2", wintypes.WORD),
    ]


class _ACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("AceType", wintypes.BYTE),
        ("AceFlags", wintypes.BYTE),
        ("AceSize", wintypes.WORD),
    ]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", wintypes.LPVOID),
        ("Attributes", wintypes.DWORD),
    ]


class _TOKEN_USER_VALUE(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class _FILE_RENAME_INFO(ctypes.Structure):
    _fields_ = [
        ("ReplaceIfExists", wintypes.DWORD),
        ("RootDirectory", wintypes.HANDLE),
        ("FileNameLength", wintypes.DWORD),
        ("FileName", wintypes.WCHAR * 1),
    ]


class _FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
]
kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(_OVERLAPPED),
]
kernel32.ReadFile.restype = wintypes.BOOL
kernel32.WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(_OVERLAPPED),
]
kernel32.WriteFile.restype = wintypes.BOOL
kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
kernel32.FlushFileBuffers.restype = wintypes.BOOL
kernel32.SetFileInformationByHandle.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
]
kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
kernel32.LockFileEx.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(_OVERLAPPED),
]
kernel32.LockFileEx.restype = wintypes.BOOL
kernel32.UnlockFileEx.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(_OVERLAPPED),
]
kernel32.UnlockFileEx.restype = wintypes.BOOL
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CreateDirectoryW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(_SECURITY_ATTRIBUTES),
]
kernel32.CreateDirectoryW.restype = wintypes.BOOL
kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
kernel32.LocalFree.restype = wintypes.HLOCAL

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.GetSecurityInfo.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.LPVOID),
]
advapi32.GetSecurityInfo.restype = wintypes.DWORD
advapi32.GetAce.argtypes = [
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPVOID),
]
advapi32.GetAce.restype = wintypes.BOOL
advapi32.ConvertSidToStringSidW.argtypes = [
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.LPWSTR),
]
advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.ULONG),
]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
advapi32.GetSecurityDescriptorDacl.argtypes = [
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.BOOL),
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.POINTER(wintypes.BOOL),
]
advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
advapi32.SetNamedSecurityInfoW.argtypes = [
    wintypes.LPWSTR,
    ctypes.c_int,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.LPVOID,
]
advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

ntdll.NtCreateFile.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    ctypes.POINTER(_OBJECT_ATTRIBUTES),
    ctypes.POINTER(_IO_STATUS_BLOCK),
    ctypes.POINTER(ctypes.c_longlong),
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.LPVOID,
    wintypes.ULONG,
]
ntdll.NtCreateFile.restype = wintypes.LONG
ntdll.NtSetInformationFile.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_IO_STATUS_BLOCK),
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.ULONG,
]
ntdll.NtSetInformationFile.restype = wintypes.LONG
ntdll.RtlNtStatusToDosError.argtypes = [wintypes.LONG]
ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG


def _raise_last_error(operation: str) -> None:
    code = ctypes.get_last_error()
    raise WindowsSecureIOError(code, f"{operation}: {ctypes.FormatError(code)}")


def _raise_nt_error(status: int, operation: str) -> None:
    code = int(ntdll.RtlNtStatusToDosError(status))
    message = f"{operation}: {ctypes.FormatError(code)}"
    if code in {ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND}:
        raise FileNotFoundError(code, message)
    if code in {ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS}:
        raise FileExistsError(code, message)
    if code == ERROR_ACCESS_DENIED:
        raise PermissionError(code, message)
    raise WindowsSecureIOError(code, message)


def close_handle(handle: int) -> None:
    if (
        handle
        and handle != INVALID_HANDLE_VALUE
        and not kernel32.CloseHandle(wintypes.HANDLE(handle))
    ):
        _raise_last_error("CloseHandle")


def _handle_info(handle: int) -> _BY_HANDLE_FILE_INFORMATION:
    info = _BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(
        wintypes.HANDLE(handle),
        ctypes.byref(info),
    ):
        _raise_last_error("GetFileInformationByHandle")
    return info


def _info_identity(info: _BY_HANDLE_FILE_INFORMATION) -> tuple[int, int]:
    file_index = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
    return (int(info.dwVolumeSerialNumber), file_index)


def _info_size(info: _BY_HANDLE_FILE_INFORMATION) -> int:
    return (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)


def handle_identity(handle: int) -> tuple[int, int]:
    return _info_identity(_handle_info(handle))


def _sid_to_string(sid: int | wintypes.LPVOID) -> str:
    output = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(output)):
        _raise_last_error("ConvertSidToStringSidW")
    try:
        return str(output.value)
    finally:
        kernel32.LocalFree(output)


def _current_user_sid() -> str:
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        TOKEN_QUERY,
        ctypes.byref(token),
    ):
        _raise_last_error("OpenProcessToken")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            TOKEN_USER,
            None,
            0,
            ctypes.byref(needed),
        )
        if needed.value == 0:
            _raise_last_error("GetTokenInformation(size)")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            TOKEN_USER,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            _raise_last_error("GetTokenInformation")
        user = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_USER_VALUE)).contents
        return _sid_to_string(user.User.Sid)
    finally:
        close_handle(int(token.value))


def _new_private_file_security_descriptor() -> wintypes.LPVOID:
    """Allocate a protected user/SYSTEM/Administrators-only file DACL."""

    current = _current_user_sid()
    sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{current})"
    descriptor = wintypes.LPVOID()
    descriptor_size = wintypes.ULONG()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        _raise_last_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW(file)",
        )
    return descriptor


def validate_owner_private_handle(handle: int, label: str) -> None:
    """Require current-user ownership and no broad allow ACE."""

    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    result = advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise WindowsSecureIOError(
            int(result),
            f"GetSecurityInfo({label}): {ctypes.FormatError(result)}",
        )
    try:
        current = _current_user_sid()
        if _sid_to_string(owner) != current:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{label} is not owned by the current Windows user",
            )
        if not dacl:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{label} has a NULL DACL and is not owner-private",
            )
        # OWNER RIGHTS is a Windows well-known SID whose permissions apply
        # only to the object's current owner.  Windows Temp commonly uses it
        # instead of spelling out the owning user's SID; after the owner check
        # above it is therefore owner-equivalent, not a foreign trustee.
        allowed_sids = {
            current,
            OWNER_RIGHTS_SID,
            "S-1-5-18",
            "S-1-5-32-544",
        }
        acl = ctypes.cast(dacl, ctypes.POINTER(_ACL)).contents
        for index in range(int(acl.AceCount)):
            ace = wintypes.LPVOID()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                _raise_last_error(f"GetAce({label}, {index})")
            header = ctypes.cast(ace, ctypes.POINTER(_ACE_HEADER)).contents
            if header.AceType == ACCESS_DENIED_ACE_TYPE:
                continue
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE:
                raise WindowsSecureIOError(
                    ERROR_ACCESS_DENIED,
                    f"{label} has an unsupported allow-capable Windows ACE type "
                    f"{int(header.AceType)}",
                )
            sid_address = (
                int(ace.value)
                + ctypes.sizeof(_ACE_HEADER)
                + ctypes.sizeof(
                    wintypes.DWORD,
                )
            )
            trustee = _sid_to_string(wintypes.LPVOID(sid_address))
            if trustee not in allowed_sids:
                raise WindowsSecureIOError(
                    ERROR_ACCESS_DENIED,
                    f"{label} grants access to non-owner trustee {trustee}",
                )
    finally:
        if descriptor:
            kernel32.LocalFree(descriptor)


def protect_directory(path: Path) -> None:
    """Install a protected user/SYSTEM/Administrators-only inheritable DACL."""

    current = _current_user_sid()
    sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{current})"
    descriptor = wintypes.LPVOID()
    descriptor_size = wintypes.ULONG()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        _raise_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ):
            _raise_last_error("GetSecurityDescriptorDacl")
        if not present or not dacl:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                "constructed private Windows DACL is missing",
            )
        result = advapi32.SetNamedSecurityInfoW(
            str(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if result != 0:
            raise WindowsSecureIOError(
                int(result),
                f"SetNamedSecurityInfoW({path}): {ctypes.FormatError(result)}",
            )
    finally:
        kernel32.LocalFree(descriptor)


def ensure_private_directory(path: Path) -> None:
    """Create the final directory with a private DACL in the create syscall."""

    path.parent.mkdir(parents=True, exist_ok=True)
    current = _current_user_sid()
    sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{current})"
    descriptor = wintypes.LPVOID()
    descriptor_size = wintypes.ULONG()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        SDDL_REVISION_1,
        ctypes.byref(descriptor),
        ctypes.byref(descriptor_size),
    ):
        _raise_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        attributes = _SECURITY_ATTRIBUTES(
            nLength=ctypes.sizeof(_SECURITY_ATTRIBUTES),
            lpSecurityDescriptor=descriptor,
            bInheritHandle=False,
        )
        if not kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            code = ctypes.get_last_error()
            if code != ERROR_ALREADY_EXISTS:
                raise WindowsSecureIOError(
                    code,
                    f"CreateDirectoryW({path}): {ctypes.FormatError(code)}",
                )
        handle, _ = open_directory(path)
        close_handle(handle)
    finally:
        kernel32.LocalFree(descriptor)


def open_directory(
    path: Path,
    *,
    require_private: bool = True,
) -> tuple[int, tuple[int, int]]:
    handle = kernel32.CreateFileW(
        str(path),
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    raw_handle = int(handle) if handle else 0
    if raw_handle == INVALID_HANDLE_VALUE:
        _raise_last_error(f"CreateFileW({path})")
    try:
        info = _handle_info(raw_handle)
        if not info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
            raise WindowsSecureIOError(  # noqa: TRY301
                ERROR_ACCESS_DENIED,
                f"{path} is not a directory",
            )
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsSecureIOError(  # noqa: TRY301
                ERROR_ACCESS_DENIED,
                f"{path} is a Windows reparse point",
            )
        if require_private:
            validate_owner_private_handle(raw_handle, str(path))
        return raw_handle, _info_identity(info)
    except BaseException:
        close_handle(raw_handle)
        raise


def directory_path_identity(
    path: Path,
    *,
    require_private: bool = True,
) -> tuple[int, int]:
    handle, identity = open_directory(path, require_private=require_private)
    close_handle(handle)
    return identity


def _validate_relative_name(name: str) -> None:
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or Path(name).name != name
    ):
        raise WindowsSecureIOError(
            ERROR_ACCESS_DENIED,
            f"unsafe handle-relative filename {name!r}",
        )


def _open_relative(
    directory_handle: int,
    name: str,
    *,
    access: int,
    disposition: int,
    share_access: int = FILE_SHARE_ALL,
    private_create: bool = False,
) -> int:
    _validate_relative_name(name)
    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UNICODE_STRING(
        Length=encoded_length,
        MaximumLength=encoded_length + ctypes.sizeof(wintypes.WCHAR),
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    descriptor = _new_private_file_security_descriptor() if private_create else wintypes.LPVOID()
    try:
        attributes = _OBJECT_ATTRIBUTES(
            Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
            RootDirectory=wintypes.HANDLE(directory_handle),
            ObjectName=ctypes.pointer(unicode_name),
            Attributes=OBJ_CASE_INSENSITIVE,
            SecurityDescriptor=descriptor,
            SecurityQualityOfService=None,
        )
        io_status = _IO_STATUS_BLOCK()
        handle = wintypes.HANDLE()
        status = int(
            ntdll.NtCreateFile(
                ctypes.byref(handle),
                access,
                ctypes.byref(attributes),
                ctypes.byref(io_status),
                None,
                FILE_ATTRIBUTE_NORMAL,
                share_access,
                disposition,
                (FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT),
                None,
                0,
            ),
        )
    finally:
        if descriptor:
            kernel32.LocalFree(descriptor)
    if status < 0:
        _raise_nt_error(status, f"NtCreateFile({name})")
    return int(handle.value)


def _open_relative_directory(
    directory_handle: int,
    name: str,
    *,
    access: int,
    disposition: int,
    share_access: int = FILE_SHARE_READ | FILE_SHARE_WRITE,
) -> int:
    _validate_relative_name(name)
    name_buffer = ctypes.create_unicode_buffer(name)
    encoded_length = len(name.encode("utf-16-le"))
    unicode_name = _UNICODE_STRING(
        Length=encoded_length,
        MaximumLength=encoded_length + ctypes.sizeof(wintypes.WCHAR),
        Buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _OBJECT_ATTRIBUTES(
        Length=ctypes.sizeof(_OBJECT_ATTRIBUTES),
        RootDirectory=wintypes.HANDLE(directory_handle),
        ObjectName=ctypes.pointer(unicode_name),
        Attributes=OBJ_CASE_INSENSITIVE,
        SecurityDescriptor=None,
        SecurityQualityOfService=None,
    )
    io_status = _IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()
    status = int(
        ntdll.NtCreateFile(
            ctypes.byref(handle),
            access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            FILE_ATTRIBUTE_DIRECTORY,
            share_access,
            disposition,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        ),
    )
    if status < 0:
        _raise_nt_error(status, f"NtCreateFile(directory {name})")
    return int(handle.value)


def _validate_directory_handle(
    handle: int,
    label: str,
    *,
    require_private: bool,
) -> _BY_HANDLE_FILE_INFORMATION:
    info = _handle_info(handle)
    if not info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
        raise WindowsSecureIOError(
            ERROR_ACCESS_DENIED,
            f"{label} is not a directory",
        )
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsSecureIOError(
            ERROR_ACCESS_DENIED,
            f"{label} is a Windows reparse point",
        )
    if require_private:
        validate_owner_private_handle(handle, label)
    return info


def _validate_regular_handle(
    handle: int,
    label: str,
    *,
    require_private: bool,
) -> _BY_HANDLE_FILE_INFORMATION:
    info = _handle_info(handle)
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY:
        raise WindowsSecureIOError(
            ERROR_ACCESS_DENIED,
            f"{label} is not a regular file",
        )
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsSecureIOError(
            ERROR_ACCESS_DENIED,
            f"{label} is a Windows reparse point",
        )
    if require_private:
        validate_owner_private_handle(handle, label)
    return info


def read_relative(
    directory_handle: int,
    name: str,
    *,
    maximum_bytes: int,
    require_private: bool = True,
    private_decider: Callable[[bytes], bool] | None = None,
) -> tuple[bytes, tuple[int, int] | None]:
    if require_private and private_decider is not None:
        raise ValueError("choose require_private or private_decider, not both")
    try:
        handle = _open_relative(
            directory_handle,
            name,
            access=GENERIC_READ | READ_CONTROL | SYNCHRONIZE,
            disposition=FILE_OPEN,
        )
    except FileNotFoundError:
        return b"", None
    try:
        before = _validate_regular_handle(
            handle,
            name,
            require_private=require_private,
        )
        size = _info_size(before)
        if size > maximum_bytes:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} exceeds the configured safety bound",
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            buffer_size = min(65536, remaining)
            buffer = ctypes.create_string_buffer(buffer_size)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                wintypes.HANDLE(handle),
                buffer,
                buffer_size,
                ctypes.byref(read),
                None,
            ):
                _raise_last_error(f"ReadFile({name})")
            if read.value == 0:
                break
            chunks.append(buffer.raw[: read.value])
            remaining -= int(read.value)
        after = _handle_info(handle)
        if _info_identity(before) != _info_identity(after) or _info_size(
            before,
        ) != _info_size(after):
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} changed while it was read",
            )
        raw = b"".join(chunks)
        if len(raw) > maximum_bytes:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} exceeds the configured safety bound",
            )
        if private_decider is not None and private_decider(raw):
            validate_owner_private_handle(handle, name)
        return raw, _info_identity(after)
    finally:
        close_handle(handle)


def read_stable_path(
    path: Path,
    *,
    maximum_bytes: int,
    private_decider: Callable[[bytes], bool] | None = None,
) -> bytes | None:
    """Read one final path through a held, non-reparse parent handle."""

    before = directory_path_identity(path.parent, require_private=False)
    directory_handle, opened = open_directory(
        path.parent,
        require_private=False,
    )
    try:
        after_open = directory_path_identity(
            path.parent,
            require_private=False,
        )
        if before != opened or opened != after_open:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{path.parent} changed while its handle was acquired",
            )
        raw, file_identity = read_relative(
            directory_handle,
            path.name,
            maximum_bytes=maximum_bytes,
            require_private=False,
            private_decider=private_decider,
        )
        if file_identity is None:
            return None
        after_read = directory_path_identity(
            path.parent,
            require_private=False,
        )
        if after_read != opened:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{path.parent} changed while {path.name} was read",
            )
        return raw
    finally:
        close_handle(directory_handle)


def open_relative_file(
    directory_handle: int,
    name: str,
    *,
    require_private: bool = True,
) -> tuple[int, tuple[int, int], int] | None:
    """Open and hold one non-reparse relative file without delete sharing."""

    try:
        handle = _open_relative(
            directory_handle,
            name,
            access=(GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE),
            disposition=FILE_OPEN,
            share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    except FileNotFoundError:
        return None
    try:
        info = _validate_regular_handle(
            handle,
            name,
            require_private=require_private,
        )
        identity = _info_identity(info)
        if (
            relative_file_identity(
                directory_handle,
                name,
                require_private=require_private,
            )
            != identity
        ):
            raise WindowsSecureIOError(  # noqa: TRY301
                ERROR_ACCESS_DENIED,
                f"{name} pathname changed while its handle was acquired",
            )
        return handle, identity, _info_size(info)
    except BaseException:
        close_handle(handle)
        raise


def create_relative_stream_file(
    directory_handle: int,
    name: str,
    chunks: Iterable[bytes],
) -> tuple[int, tuple[int, int], int]:
    """Create, stream, flush, and hold one private relative file."""

    handle = _open_relative(
        directory_handle,
        name,
        access=GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_CREATE,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
        private_create=True,
    )
    try:
        _validate_regular_handle(handle, name, require_private=True)
        total = 0
        for chunk in chunks:
            offset = 0
            while offset < len(chunk):
                buffer = ctypes.create_string_buffer(chunk[offset:])
                written = wintypes.DWORD()
                if not kernel32.WriteFile(
                    wintypes.HANDLE(handle),
                    buffer,
                    len(chunk) - offset,
                    ctypes.byref(written),
                    None,
                ):
                    _raise_last_error(f"WriteFile({name})")
                if written.value <= 0:
                    raise WindowsSecureIOError(  # noqa: TRY301
                        ERROR_ACCESS_DENIED,
                        f"WriteFile({name}) made no progress",
                    )
                offset += int(written.value)
                total += int(written.value)
        if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
            _raise_last_error(f"FlushFileBuffers({name})")
        after = _validate_regular_handle(handle, name, require_private=True)
        identity = _info_identity(after)
        if _info_size(after) != total or relative_file_identity(directory_handle, name) != identity:
            raise WindowsSecureIOError(  # noqa: TRY301
                ERROR_ACCESS_DENIED,
                f"{name} changed while it was finalized",
            )
        return handle, identity, total
    except BaseException:
        with contextlib.suppress(OSError):
            delete_open_handle(handle)
        close_handle(handle)
        raise


def create_relative_file(
    directory_handle: int,
    name: str,
    payload: bytes,
) -> int:
    handle, _, _ = create_relative_stream_file(
        directory_handle,
        name,
        (payload,),
    )
    return handle


def copy_relative_file(
    source_directory_handle: int,
    source_name: str,
    destination_directory_handle: int,
    destination_name: str,
) -> tuple[int, str]:
    """Copy one stable private child into a newly created private child."""

    source_handle = _open_relative(
        source_directory_handle,
        source_name,
        access=GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    destination_handle = 0
    try:
        source_before = _validate_regular_handle(
            source_handle,
            source_name,
            require_private=True,
        )
        source_identity = _info_identity(source_before)
        source_size = _info_size(source_before)
        destination_handle = _open_relative(
            destination_directory_handle,
            destination_name,
            access=GENERIC_READ | GENERIC_WRITE | DELETE | READ_CONTROL | SYNCHRONIZE,
            disposition=FILE_CREATE,
            share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
            private_create=True,
        )
        _validate_regular_handle(
            destination_handle,
            destination_name,
            require_private=True,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            buffer = ctypes.create_string_buffer(1024 * 1024)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                wintypes.HANDLE(source_handle),
                buffer,
                len(buffer),
                ctypes.byref(read),
                None,
            ):
                _raise_last_error(f"ReadFile({source_name})")
            if read.value == 0:
                break
            payload = buffer.raw[: read.value]
            digest.update(payload)
            copied += len(payload)
            offset = 0
            while offset < len(payload):
                write_buffer = ctypes.create_string_buffer(payload[offset:])
                written = wintypes.DWORD()
                if not kernel32.WriteFile(
                    wintypes.HANDLE(destination_handle),
                    write_buffer,
                    len(payload) - offset,
                    ctypes.byref(written),
                    None,
                ):
                    _raise_last_error(f"WriteFile({destination_name})")
                if written.value <= 0:
                    raise WindowsSecureIOError(  # noqa: TRY301
                        ERROR_ACCESS_DENIED,
                        f"WriteFile({destination_name}) made no progress",
                    )
                offset += int(written.value)
        if not kernel32.FlushFileBuffers(wintypes.HANDLE(destination_handle)):
            _raise_last_error(f"FlushFileBuffers({destination_name})")
        source_after = _handle_info(source_handle)
        destination_after = _handle_info(destination_handle)
        if (
            _info_identity(source_after) != source_identity
            or _info_size(source_after) != source_size
            or copied != source_size
            or relative_file_identity(
                source_directory_handle,
                source_name,
            )
            != source_identity
            or relative_file_identity(
                destination_directory_handle,
                destination_name,
            )
            != _info_identity(destination_after)
            or _info_size(destination_after) != copied
        ):
            raise WindowsSecureIOError(  # noqa: TRY301
                ERROR_ACCESS_DENIED,
                "source or destination changed during secure copy",
            )
        return copied, digest.hexdigest()
    except BaseException:
        if destination_handle:
            with contextlib.suppress(OSError):
                delete_open_handle(destination_handle)
        raise
    finally:
        if destination_handle:
            close_handle(destination_handle)
        close_handle(source_handle)


def replace_open_handle(
    source_handle: int,
    directory_handle: int,
    destination_name: str,
    *,
    replace_existing: bool = True,
) -> None:
    _validate_relative_name(destination_name)
    encoded = destination_name.encode("utf-16-le")
    offset = _FILE_RENAME_INFO.FileName.offset
    buffer = ctypes.create_string_buffer(offset + len(encoded))
    info = ctypes.cast(buffer, ctypes.POINTER(_FILE_RENAME_INFO)).contents
    info.ReplaceIfExists = int(replace_existing)
    info.RootDirectory = wintypes.HANDLE(directory_handle)
    info.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
    io_status = _IO_STATUS_BLOCK()
    status = int(
        ntdll.NtSetInformationFile(
            wintypes.HANDLE(source_handle),
            ctypes.byref(io_status),
            buffer,
            len(buffer),
            NT_FILE_RENAME_INFORMATION_CLASS,
        ),
    )
    if status < 0:
        _raise_nt_error(status, f"NtSetInformationFile(rename {destination_name})")


def delete_open_handle(handle: int) -> None:
    disposition = _FILE_DISPOSITION_INFO(DeleteFile=True)
    if not kernel32.SetFileInformationByHandle(
        wintypes.HANDLE(handle),
        FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        _raise_last_error("SetFileInformationByHandle(delete)")


def delete_relative(
    directory_handle: int,
    name: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    handle = _open_relative(
        directory_handle,
        name,
        access=DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN,
    )
    try:
        info = _validate_regular_handle(handle, name, require_private=True)
        if expected_identity is not None and _info_identity(info) != expected_identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} identity changed before deletion",
            )
        delete_open_handle(handle)
    finally:
        close_handle(handle)


def relative_file_identity(
    directory_handle: int,
    name: str,
    *,
    require_private: bool = True,
) -> tuple[int, int] | None:
    """Return one non-reparse child's identity relative to a held directory."""

    try:
        handle = _open_relative(
            directory_handle,
            name,
            access=FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            disposition=FILE_OPEN,
        )
    except FileNotFoundError:
        return None
    try:
        info = _validate_regular_handle(
            handle,
            name,
            require_private=require_private,
        )
        return _info_identity(info)
    finally:
        close_handle(handle)


def relative_directory_identity(
    directory_handle: int,
    name: str,
    *,
    require_private: bool = True,
) -> tuple[int, int] | None:
    """Return one real child directory's identity under a held parent."""

    try:
        handle = _open_relative_directory(
            directory_handle,
            name,
            access=FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            disposition=FILE_OPEN,
        )
    except FileNotFoundError:
        return None
    try:
        info = _validate_directory_handle(
            handle,
            name,
            require_private=require_private,
        )
        return _info_identity(info)
    finally:
        close_handle(handle)


def create_relative_directory(directory_handle: int, name: str) -> tuple[int, int]:
    """Create one private child directory relative to a held parent."""

    handle = _open_relative_directory(
        directory_handle,
        name,
        access=FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_CREATE,
    )
    try:
        info = _validate_directory_handle(handle, name, require_private=True)
        identity = _info_identity(info)
        if relative_directory_identity(directory_handle, name) != identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} pathname changed after directory creation",
            )
        return identity
    finally:
        close_handle(handle)


def delete_relative_directory(
    directory_handle: int,
    name: str,
    *,
    expected_identity: tuple[int, int],
) -> None:
    """Remove one exact empty child directory through its held handle."""

    handle = _open_relative_directory(
        directory_handle,
        name,
        access=DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN,
    )
    try:
        info = _validate_directory_handle(handle, name, require_private=True)
        if _info_identity(info) != expected_identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} directory identity changed before deletion",
            )
        delete_open_handle(handle)
    finally:
        close_handle(handle)


def digest_relative_file(
    directory_handle: int,
    name: str,
    *,
    maximum_bytes: int | None = None,
) -> tuple[tuple[int, int], int, str, int]:
    """Hash one private regular child while denying pathname replacement."""

    handle = _open_relative(
        directory_handle,
        name,
        access=GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    try:
        before = _validate_regular_handle(handle, name, require_private=True)
        size = _info_size(before)
        if maximum_bytes is not None and size > maximum_bytes:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} exceeds the configured safety bound",
            )
        digest = hashlib.sha256()
        observed = 0
        while True:
            buffer = ctypes.create_string_buffer(1024 * 1024)
            read = wintypes.DWORD()
            if not kernel32.ReadFile(
                wintypes.HANDLE(handle),
                buffer,
                len(buffer),
                ctypes.byref(read),
                None,
            ):
                _raise_last_error(f"ReadFile({name})")
            if read.value == 0:
                break
            digest.update(buffer.raw[: read.value])
            observed += int(read.value)
        after = _handle_info(handle)
        identity = _info_identity(after)
        if (
            _info_identity(before) != identity
            or _info_size(after) != size
            or observed != size
            or relative_file_identity(directory_handle, name) != identity
        ):
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} changed while it was hashed",
            )
        return identity, size, digest.hexdigest(), int(after.nNumberOfLinks)
    finally:
        close_handle(handle)


def move_relative_file(
    source_directory_handle: int,
    source_name: str,
    destination_directory_handle: int,
    destination_name: str,
    *,
    expected_identity: tuple[int, int],
) -> None:
    """Rename one exact child between two held directories without overwrite."""

    handle = _open_relative(
        source_directory_handle,
        source_name,
        access=DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    try:
        info = _validate_regular_handle(
            handle,
            source_name,
            require_private=True,
        )
        if _info_identity(info) != expected_identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{source_name} identity changed before retirement move",
            )
        if (
            relative_file_identity(
                destination_directory_handle,
                destination_name,
            )
            is not None
        ):
            raise FileExistsError(
                ERROR_FILE_EXISTS,
                f"{destination_name} already exists",
            )
        replace_open_handle(
            handle,
            destination_directory_handle,
            destination_name,
            replace_existing=False,
        )
        if (
            relative_file_identity(source_directory_handle, source_name) is not None
            or relative_file_identity(
                destination_directory_handle,
                destination_name,
            )
            != expected_identity
        ):
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{source_name} retirement move did not preserve exact identity",
            )
    finally:
        close_handle(handle)


@contextlib.contextmanager
def hold_relative_file_stable(
    directory_handle: int,
    name: str,
    *,
    expected_identity: tuple[int, int],
) -> Iterator[None]:
    """Deny rename/unlink while a pathname consumer opens one exact child."""

    handle = _open_relative(
        directory_handle,
        name,
        access=FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    try:
        info = _validate_regular_handle(handle, name, require_private=True)
        if _info_identity(info) != expected_identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} identity changed before stable hold",
            )
        if relative_file_identity(directory_handle, name) != expected_identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} pathname changed before stable hold",
            )
        yield
        if (
            handle_identity(handle) != expected_identity
            or relative_file_identity(directory_handle, name) != expected_identity
        ):
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} pathname changed during stable hold",
            )
    finally:
        close_handle(handle)


@contextlib.contextmanager
def exclusive_relative_lock(  # noqa: PLR0912  native lock lifecycle
    directory_handle: int,
    name: str,
) -> Iterator[None]:
    handle = _open_relative(
        directory_handle,
        name,
        access=GENERIC_READ | GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE,
        disposition=FILE_OPEN_IF,
        share_access=FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
    overlapped = _OVERLAPPED()
    locked = False
    lock_identity: tuple[int, int] | None = None
    try:
        info = _validate_regular_handle(handle, name, require_private=True)
        lock_identity = _info_identity(info)
        if info.dwFileAttributes & FILE_ATTRIBUTE_READONLY:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} is read-only",
            )
        if not kernel32.LockFileEx(
            wintypes.HANDLE(handle),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            0xFFFFFFFF,
            0xFFFFFFFF,
            ctypes.byref(overlapped),
        ):
            _raise_last_error(f"LockFileEx({name})")
        locked = True
        if _info_size(info) == 0:
            byte = ctypes.create_string_buffer(b"\0")
            written = wintypes.DWORD()
            if not kernel32.WriteFile(
                wintypes.HANDLE(handle),
                byte,
                1,
                ctypes.byref(written),
                None,
            ):
                _raise_last_error(f"WriteFile({name})")
            if written.value != 1:
                raise WindowsSecureIOError(
                    ERROR_ACCESS_DENIED,
                    f"could not initialize {name}",
                )
            if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
                _raise_last_error(f"FlushFileBuffers({name})")
        if relative_file_identity(directory_handle, name) != lock_identity:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} pathname no longer names the locked file",
            )
        yield
    finally:
        pathname_changed = False
        if lock_identity is not None:
            try:
                pathname_changed = relative_file_identity(directory_handle, name) != lock_identity
            except OSError:
                pathname_changed = True
        if locked:
            with contextlib.suppress(OSError):
                if not kernel32.UnlockFileEx(
                    wintypes.HANDLE(handle),
                    0,
                    0xFFFFFFFF,
                    0xFFFFFFFF,
                    ctypes.byref(overlapped),
                ):
                    _raise_last_error(f"UnlockFileEx({name})")
        close_handle(handle)
        if pathname_changed:
            raise WindowsSecureIOError(
                ERROR_ACCESS_DENIED,
                f"{name} pathname changed while held",
            )


__all__ = [
    "WindowsSecureIOError",
    "close_handle",
    "copy_relative_file",
    "create_relative_directory",
    "create_relative_file",
    "create_relative_stream_file",
    "delete_open_handle",
    "delete_relative",
    "delete_relative_directory",
    "digest_relative_file",
    "directory_path_identity",
    "ensure_private_directory",
    "exclusive_relative_lock",
    "handle_identity",
    "hold_relative_file_stable",
    "move_relative_file",
    "open_directory",
    "open_relative_file",
    "protect_directory",
    "read_relative",
    "read_stable_path",
    "relative_directory_identity",
    "relative_file_identity",
    "replace_open_handle",
    "validate_owner_private_handle",
]
