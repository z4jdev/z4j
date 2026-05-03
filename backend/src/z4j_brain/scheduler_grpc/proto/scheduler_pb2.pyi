import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ListSchedulesRequest(_message.Message):
    __slots__ = ("project_id", "page_size")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    page_size: int
    def __init__(self, project_id: _Optional[str] = ..., page_size: _Optional[int] = ...) -> None: ...

class WatchSchedulesRequest(_message.Message):
    __slots__ = ("project_id", "resume_token")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    RESUME_TOKEN_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    resume_token: str
    def __init__(self, project_id: _Optional[str] = ..., resume_token: _Optional[str] = ...) -> None: ...

class Schedule(_message.Message):
    __slots__ = ("id", "project_id", "engine", "name", "task_name", "kind", "expression", "timezone", "queue", "args_json", "kwargs_json", "is_enabled", "catch_up", "source", "last_run_at", "next_run_at", "total_runs", "source_hash")
    ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    ENGINE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TASK_NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    EXPRESSION_FIELD_NUMBER: _ClassVar[int]
    TIMEZONE_FIELD_NUMBER: _ClassVar[int]
    QUEUE_FIELD_NUMBER: _ClassVar[int]
    ARGS_JSON_FIELD_NUMBER: _ClassVar[int]
    KWARGS_JSON_FIELD_NUMBER: _ClassVar[int]
    IS_ENABLED_FIELD_NUMBER: _ClassVar[int]
    CATCH_UP_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    TOTAL_RUNS_FIELD_NUMBER: _ClassVar[int]
    SOURCE_HASH_FIELD_NUMBER: _ClassVar[int]
    id: str
    project_id: str
    engine: str
    name: str
    task_name: str
    kind: str
    expression: str
    timezone: str
    queue: str
    args_json: bytes
    kwargs_json: bytes
    is_enabled: bool
    catch_up: str
    source: str
    last_run_at: _timestamp_pb2.Timestamp
    next_run_at: _timestamp_pb2.Timestamp
    total_runs: int
    source_hash: str
    def __init__(self, id: _Optional[str] = ..., project_id: _Optional[str] = ..., engine: _Optional[str] = ..., name: _Optional[str] = ..., task_name: _Optional[str] = ..., kind: _Optional[str] = ..., expression: _Optional[str] = ..., timezone: _Optional[str] = ..., queue: _Optional[str] = ..., args_json: _Optional[bytes] = ..., kwargs_json: _Optional[bytes] = ..., is_enabled: bool = ..., catch_up: _Optional[str] = ..., source: _Optional[str] = ..., last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., total_runs: _Optional[int] = ..., source_hash: _Optional[str] = ...) -> None: ...

class ScheduleEvent(_message.Message):
    __slots__ = ("kind", "schedule", "deleted_id", "resume_token")
    class Kind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CREATED: _ClassVar[ScheduleEvent.Kind]
        UPDATED: _ClassVar[ScheduleEvent.Kind]
        DELETED: _ClassVar[ScheduleEvent.Kind]
    CREATED: ScheduleEvent.Kind
    UPDATED: ScheduleEvent.Kind
    DELETED: ScheduleEvent.Kind
    KIND_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    DELETED_ID_FIELD_NUMBER: _ClassVar[int]
    RESUME_TOKEN_FIELD_NUMBER: _ClassVar[int]
    kind: ScheduleEvent.Kind
    schedule: Schedule
    deleted_id: str
    resume_token: str
    def __init__(self, kind: _Optional[_Union[ScheduleEvent.Kind, str]] = ..., schedule: _Optional[_Union[Schedule, _Mapping]] = ..., deleted_id: _Optional[str] = ..., resume_token: _Optional[str] = ...) -> None: ...

class FireScheduleRequest(_message.Message):
    __slots__ = ("schedule_id", "fire_id", "scheduled_for", "fired_at")
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    FIRE_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULED_FOR_FIELD_NUMBER: _ClassVar[int]
    FIRED_AT_FIELD_NUMBER: _ClassVar[int]
    schedule_id: str
    fire_id: str
    scheduled_for: _timestamp_pb2.Timestamp
    fired_at: _timestamp_pb2.Timestamp
    def __init__(self, schedule_id: _Optional[str] = ..., fire_id: _Optional[str] = ..., scheduled_for: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., fired_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class FireScheduleResponse(_message.Message):
    __slots__ = ("command_id", "error_code", "error_message", "buffered")
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    BUFFERED_FIELD_NUMBER: _ClassVar[int]
    command_id: str
    error_code: str
    error_message: str
    buffered: bool
    def __init__(self, command_id: _Optional[str] = ..., error_code: _Optional[str] = ..., error_message: _Optional[str] = ..., buffered: bool = ...) -> None: ...

class TriggerScheduleRequest(_message.Message):
    __slots__ = ("schedule_id", "user_id", "idempotency_key")
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    schedule_id: str
    user_id: str
    idempotency_key: str
    def __init__(self, schedule_id: _Optional[str] = ..., user_id: _Optional[str] = ..., idempotency_key: _Optional[str] = ...) -> None: ...

class TriggerScheduleResponse(_message.Message):
    __slots__ = ("command_id", "error_code", "error_message")
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    command_id: str
    error_code: str
    error_message: str
    def __init__(self, command_id: _Optional[str] = ..., error_code: _Optional[str] = ..., error_message: _Optional[str] = ...) -> None: ...

class AcknowledgeFireResultRequest(_message.Message):
    __slots__ = ("fire_id", "command_id", "status", "new_task_id", "error")
    FIRE_ID_FIELD_NUMBER: _ClassVar[int]
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    NEW_TASK_ID_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    fire_id: str
    command_id: str
    status: str
    new_task_id: str
    error: str
    def __init__(self, fire_id: _Optional[str] = ..., command_id: _Optional[str] = ..., status: _Optional[str] = ..., new_task_id: _Optional[str] = ..., error: _Optional[str] = ...) -> None: ...

class AcknowledgeFireResultResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PingResponse(_message.Message):
    __slots__ = ("brain_version", "brain_time")
    BRAIN_VERSION_FIELD_NUMBER: _ClassVar[int]
    BRAIN_TIME_FIELD_NUMBER: _ClassVar[int]
    brain_version: str
    brain_time: _timestamp_pb2.Timestamp
    def __init__(self, brain_version: _Optional[str] = ..., brain_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...
