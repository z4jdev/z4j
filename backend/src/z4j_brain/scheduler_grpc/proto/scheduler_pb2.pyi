import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FireDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FIRE_DISPOSITION_UNSPECIFIED: _ClassVar[FireDisposition]
    FIRE_ACCEPTED: _ClassVar[FireDisposition]
    FIRE_RETRYABLE_OR_AMBIGUOUS: _ClassVar[FireDisposition]
    FIRE_TERMINAL_QUARANTINED: _ClassVar[FireDisposition]
    FIRE_SLOT_RESOLVED_REFRESH: _ClassVar[FireDisposition]
    FIRE_STALE_CONTROL_REFRESH: _ClassVar[FireDisposition]
    FIRE_LEGACY_UPGRADE_REQUIRED: _ClassVar[FireDisposition]
    FIRE_CADENCE_SEMANTICS_MISMATCH: _ClassVar[FireDisposition]

class QuarantineOutcome(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    QUARANTINE_OUTCOME_UNSPECIFIED: _ClassVar[QuarantineOutcome]
    QUARANTINE_APPLIED: _ClassVar[QuarantineOutcome]
    QUARANTINE_ALREADY_APPLIED: _ClassVar[QuarantineOutcome]
    QUARANTINE_STALE_CONTROL: _ClassVar[QuarantineOutcome]
    QUARANTINE_NOT_FOUND: _ClassVar[QuarantineOutcome]

class CursorTransitionDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CURSOR_DISPOSITION_UNSPECIFIED: _ClassVar[CursorTransitionDisposition]
    CURSOR_APPLIED: _ClassVar[CursorTransitionDisposition]
    CURSOR_IDEMPOTENT: _ClassVar[CursorTransitionDisposition]
    CURSOR_SLOT_RESOLVED_REFRESH: _ClassVar[CursorTransitionDisposition]
    CURSOR_STALE_CONTROL_REFRESH: _ClassVar[CursorTransitionDisposition]
    CURSOR_CADENCE_SEMANTICS_MISMATCH: _ClassVar[CursorTransitionDisposition]
FIRE_DISPOSITION_UNSPECIFIED: FireDisposition
FIRE_ACCEPTED: FireDisposition
FIRE_RETRYABLE_OR_AMBIGUOUS: FireDisposition
FIRE_TERMINAL_QUARANTINED: FireDisposition
FIRE_SLOT_RESOLVED_REFRESH: FireDisposition
FIRE_STALE_CONTROL_REFRESH: FireDisposition
FIRE_LEGACY_UPGRADE_REQUIRED: FireDisposition
FIRE_CADENCE_SEMANTICS_MISMATCH: FireDisposition
QUARANTINE_OUTCOME_UNSPECIFIED: QuarantineOutcome
QUARANTINE_APPLIED: QuarantineOutcome
QUARANTINE_ALREADY_APPLIED: QuarantineOutcome
QUARANTINE_STALE_CONTROL: QuarantineOutcome
QUARANTINE_NOT_FOUND: QuarantineOutcome
CURSOR_DISPOSITION_UNSPECIFIED: CursorTransitionDisposition
CURSOR_APPLIED: CursorTransitionDisposition
CURSOR_IDEMPOTENT: CursorTransitionDisposition
CURSOR_SLOT_RESOLVED_REFRESH: CursorTransitionDisposition
CURSOR_STALE_CONTROL_REFRESH: CursorTransitionDisposition
CURSOR_CADENCE_SEMANTICS_MISMATCH: CursorTransitionDisposition

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
    __slots__ = ("id", "project_id", "engine", "name", "task_name", "kind", "expression", "timezone", "queue", "args_json", "kwargs_json", "is_enabled", "catch_up", "source", "last_run_at", "next_run_at", "total_runs", "source_hash", "control_token", "schedule_revision", "definition_digest", "cadence_semantics_version", "cadence_runtime_fingerprint")
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
    CONTROL_TOKEN_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_REVISION_FIELD_NUMBER: _ClassVar[int]
    DEFINITION_DIGEST_FIELD_NUMBER: _ClassVar[int]
    CADENCE_SEMANTICS_VERSION_FIELD_NUMBER: _ClassVar[int]
    CADENCE_RUNTIME_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
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
    control_token: str
    schedule_revision: int
    definition_digest: str
    cadence_semantics_version: int
    cadence_runtime_fingerprint: str
    def __init__(self, id: _Optional[str] = ..., project_id: _Optional[str] = ..., engine: _Optional[str] = ..., name: _Optional[str] = ..., task_name: _Optional[str] = ..., kind: _Optional[str] = ..., expression: _Optional[str] = ..., timezone: _Optional[str] = ..., queue: _Optional[str] = ..., args_json: _Optional[bytes] = ..., kwargs_json: _Optional[bytes] = ..., is_enabled: bool = ..., catch_up: _Optional[str] = ..., source: _Optional[str] = ..., last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., total_runs: _Optional[int] = ..., source_hash: _Optional[str] = ..., control_token: _Optional[str] = ..., schedule_revision: _Optional[int] = ..., definition_digest: _Optional[str] = ..., cadence_semantics_version: _Optional[int] = ..., cadence_runtime_fingerprint: _Optional[str] = ...) -> None: ...

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
    __slots__ = ("schedule_id", "fire_id", "scheduled_for", "fired_at", "triggered_by_user_id", "scheduler_protocol_epoch", "observed_control_token", "definition_digest", "expected_schedule_revision", "expected_last_run_at", "expected_next_run_at", "prepared_next_run_at", "cadence_semantics_version", "cadence_runtime_fingerprint")
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    FIRE_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULED_FOR_FIELD_NUMBER: _ClassVar[int]
    FIRED_AT_FIELD_NUMBER: _ClassVar[int]
    TRIGGERED_BY_USER_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULER_PROTOCOL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_CONTROL_TOKEN_FIELD_NUMBER: _ClassVar[int]
    DEFINITION_DIGEST_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SCHEDULE_REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    PREPARED_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    CADENCE_SEMANTICS_VERSION_FIELD_NUMBER: _ClassVar[int]
    CADENCE_RUNTIME_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    schedule_id: str
    fire_id: str
    scheduled_for: _timestamp_pb2.Timestamp
    fired_at: _timestamp_pb2.Timestamp
    triggered_by_user_id: str
    scheduler_protocol_epoch: int
    observed_control_token: str
    definition_digest: str
    expected_schedule_revision: int
    expected_last_run_at: _timestamp_pb2.Timestamp
    expected_next_run_at: _timestamp_pb2.Timestamp
    prepared_next_run_at: _timestamp_pb2.Timestamp
    cadence_semantics_version: int
    cadence_runtime_fingerprint: str
    def __init__(self, schedule_id: _Optional[str] = ..., fire_id: _Optional[str] = ..., scheduled_for: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., fired_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., triggered_by_user_id: _Optional[str] = ..., scheduler_protocol_epoch: _Optional[int] = ..., observed_control_token: _Optional[str] = ..., definition_digest: _Optional[str] = ..., expected_schedule_revision: _Optional[int] = ..., expected_last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expected_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., prepared_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., cadence_semantics_version: _Optional[int] = ..., cadence_runtime_fingerprint: _Optional[str] = ...) -> None: ...

class FireScheduleResponse(_message.Message):
    __slots__ = ("command_id", "error_code", "error_message", "buffered", "disposition", "acceptance_revision", "accepted_last_run_at", "accepted_next_run_at", "live_control_token", "live_revision", "live_last_run_at", "live_next_run_at")
    COMMAND_ID_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    BUFFERED_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    ACCEPTANCE_REVISION_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    LIVE_CONTROL_TOKEN_FIELD_NUMBER: _ClassVar[int]
    LIVE_REVISION_FIELD_NUMBER: _ClassVar[int]
    LIVE_LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    LIVE_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    command_id: str
    error_code: str
    error_message: str
    buffered: bool
    disposition: FireDisposition
    acceptance_revision: int
    accepted_last_run_at: _timestamp_pb2.Timestamp
    accepted_next_run_at: _timestamp_pb2.Timestamp
    live_control_token: str
    live_revision: int
    live_last_run_at: _timestamp_pb2.Timestamp
    live_next_run_at: _timestamp_pb2.Timestamp
    def __init__(self, command_id: _Optional[str] = ..., error_code: _Optional[str] = ..., error_message: _Optional[str] = ..., buffered: bool = ..., disposition: _Optional[_Union[FireDisposition, str]] = ..., acceptance_revision: _Optional[int] = ..., accepted_last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., accepted_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., live_control_token: _Optional[str] = ..., live_revision: _Optional[int] = ..., live_last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., live_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

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
    __slots__ = ("brain_version", "brain_time", "scheduler_protocol_epoch")
    BRAIN_VERSION_FIELD_NUMBER: _ClassVar[int]
    BRAIN_TIME_FIELD_NUMBER: _ClassVar[int]
    SCHEDULER_PROTOCOL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    brain_version: str
    brain_time: _timestamp_pb2.Timestamp
    scheduler_protocol_epoch: int
    def __init__(self, brain_version: _Optional[str] = ..., brain_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., scheduler_protocol_epoch: _Optional[int] = ...) -> None: ...

class SchedulerProtocolCapabilities(_message.Message):
    __slots__ = ("protocol_epoch", "fire_response_version", "cursor_transition_version", "stable_snapshot_version", "revision_watch_version", "per_id_state_version", "quarantine_version", "cadence_semantics_version", "cadence_runtime_fingerprint")
    PROTOCOL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    FIRE_RESPONSE_VERSION_FIELD_NUMBER: _ClassVar[int]
    CURSOR_TRANSITION_VERSION_FIELD_NUMBER: _ClassVar[int]
    STABLE_SNAPSHOT_VERSION_FIELD_NUMBER: _ClassVar[int]
    REVISION_WATCH_VERSION_FIELD_NUMBER: _ClassVar[int]
    PER_ID_STATE_VERSION_FIELD_NUMBER: _ClassVar[int]
    QUARANTINE_VERSION_FIELD_NUMBER: _ClassVar[int]
    CADENCE_SEMANTICS_VERSION_FIELD_NUMBER: _ClassVar[int]
    CADENCE_RUNTIME_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    protocol_epoch: int
    fire_response_version: int
    cursor_transition_version: int
    stable_snapshot_version: int
    revision_watch_version: int
    per_id_state_version: int
    quarantine_version: int
    cadence_semantics_version: int
    cadence_runtime_fingerprint: str
    def __init__(self, protocol_epoch: _Optional[int] = ..., fire_response_version: _Optional[int] = ..., cursor_transition_version: _Optional[int] = ..., stable_snapshot_version: _Optional[int] = ..., revision_watch_version: _Optional[int] = ..., per_id_state_version: _Optional[int] = ..., quarantine_version: _Optional[int] = ..., cadence_semantics_version: _Optional[int] = ..., cadence_runtime_fingerprint: _Optional[str] = ...) -> None: ...

class NegotiateSchedulerProtocolRequest(_message.Message):
    __slots__ = ("offered",)
    OFFERED_FIELD_NUMBER: _ClassVar[int]
    offered: SchedulerProtocolCapabilities
    def __init__(self, offered: _Optional[_Union[SchedulerProtocolCapabilities, _Mapping]] = ...) -> None: ...

class NegotiateSchedulerProtocolResponse(_message.Message):
    __slots__ = ("selected",)
    SELECTED_FIELD_NUMBER: _ClassVar[int]
    selected: SchedulerProtocolCapabilities
    def __init__(self, selected: _Optional[_Union[SchedulerProtocolCapabilities, _Mapping]] = ...) -> None: ...

class ListScheduleSnapshotRequest(_message.Message):
    __slots__ = ("project_id", "page_size", "snapshot_format_version")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FORMAT_VERSION_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    page_size: int
    snapshot_format_version: int
    def __init__(self, project_id: _Optional[str] = ..., page_size: _Optional[int] = ..., snapshot_format_version: _Optional[int] = ...) -> None: ...

class ScheduleSnapshotHeader(_message.Message):
    __slots__ = ("format_version", "snapshot_id", "project_id")
    FORMAT_VERSION_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    format_version: int
    snapshot_id: str
    project_id: str
    def __init__(self, format_version: _Optional[int] = ..., snapshot_id: _Optional[str] = ..., project_id: _Optional[str] = ...) -> None: ...

class ScheduleSnapshotRow(_message.Message):
    __slots__ = ("snapshot_id", "schedule")
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    snapshot_id: str
    schedule: Schedule
    def __init__(self, snapshot_id: _Optional[str] = ..., schedule: _Optional[_Union[Schedule, _Mapping]] = ...) -> None: ...

class ScheduleSnapshotComplete(_message.Message):
    __slots__ = ("format_version", "snapshot_id", "project_id", "watermark", "row_count", "digest")
    FORMAT_VERSION_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_ID_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    WATERMARK_FIELD_NUMBER: _ClassVar[int]
    ROW_COUNT_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    format_version: int
    snapshot_id: str
    project_id: str
    watermark: int
    row_count: int
    digest: str
    def __init__(self, format_version: _Optional[int] = ..., snapshot_id: _Optional[str] = ..., project_id: _Optional[str] = ..., watermark: _Optional[int] = ..., row_count: _Optional[int] = ..., digest: _Optional[str] = ...) -> None: ...

class ScheduleSnapshotFrame(_message.Message):
    __slots__ = ("header", "row", "complete")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    ROW_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    header: ScheduleSnapshotHeader
    row: ScheduleSnapshotRow
    complete: ScheduleSnapshotComplete
    def __init__(self, header: _Optional[_Union[ScheduleSnapshotHeader, _Mapping]] = ..., row: _Optional[_Union[ScheduleSnapshotRow, _Mapping]] = ..., complete: _Optional[_Union[ScheduleSnapshotComplete, _Mapping]] = ...) -> None: ...

class WatchSchedulesV2Request(_message.Message):
    __slots__ = ("project_id", "after_revision", "watch_format_version")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    AFTER_REVISION_FIELD_NUMBER: _ClassVar[int]
    WATCH_FORMAT_VERSION_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    after_revision: int
    watch_format_version: int
    def __init__(self, project_id: _Optional[str] = ..., after_revision: _Optional[int] = ..., watch_format_version: _Optional[int] = ...) -> None: ...

class ScheduleChange(_message.Message):
    __slots__ = ("kind", "revision", "project_id", "schedule", "deleted_id")
    class Kind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        CHANGE_UNSPECIFIED: _ClassVar[ScheduleChange.Kind]
        UPSERT: _ClassVar[ScheduleChange.Kind]
        TOMBSTONE: _ClassVar[ScheduleChange.Kind]
    CHANGE_UNSPECIFIED: ScheduleChange.Kind
    UPSERT: ScheduleChange.Kind
    TOMBSTONE: ScheduleChange.Kind
    KIND_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    DELETED_ID_FIELD_NUMBER: _ClassVar[int]
    kind: ScheduleChange.Kind
    revision: int
    project_id: str
    schedule: Schedule
    deleted_id: str
    def __init__(self, kind: _Optional[_Union[ScheduleChange.Kind, str]] = ..., revision: _Optional[int] = ..., project_id: _Optional[str] = ..., schedule: _Optional[_Union[Schedule, _Mapping]] = ..., deleted_id: _Optional[str] = ...) -> None: ...

class ScannedThrough(_message.Message):
    __slots__ = ("scanned_through_revision", "server_revision")
    SCANNED_THROUGH_REVISION_FIELD_NUMBER: _ClassVar[int]
    SERVER_REVISION_FIELD_NUMBER: _ClassVar[int]
    scanned_through_revision: int
    server_revision: int
    def __init__(self, scanned_through_revision: _Optional[int] = ..., server_revision: _Optional[int] = ...) -> None: ...

class ScheduleWatchFrame(_message.Message):
    __slots__ = ("format_version", "change", "scanned_through")
    FORMAT_VERSION_FIELD_NUMBER: _ClassVar[int]
    CHANGE_FIELD_NUMBER: _ClassVar[int]
    SCANNED_THROUGH_FIELD_NUMBER: _ClassVar[int]
    format_version: int
    change: ScheduleChange
    scanned_through: ScannedThrough
    def __init__(self, format_version: _Optional[int] = ..., change: _Optional[_Union[ScheduleChange, _Mapping]] = ..., scanned_through: _Optional[_Union[ScannedThrough, _Mapping]] = ...) -> None: ...

class GetScheduleStateRequest(_message.Message):
    __slots__ = ("project_id", "schedule_id", "minimum_observed_revision")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_OBSERVED_REVISION_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    schedule_id: str
    minimum_observed_revision: int
    def __init__(self, project_id: _Optional[str] = ..., schedule_id: _Optional[str] = ..., minimum_observed_revision: _Optional[int] = ...) -> None: ...

class ScheduleAbsence(_message.Message):
    __slots__ = ("project_id", "schedule_id")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    schedule_id: str
    def __init__(self, project_id: _Optional[str] = ..., schedule_id: _Optional[str] = ...) -> None: ...

class GetScheduleStateResponse(_message.Message):
    __slots__ = ("observed_revision", "schedule", "absence")
    OBSERVED_REVISION_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    ABSENCE_FIELD_NUMBER: _ClassVar[int]
    observed_revision: int
    schedule: Schedule
    absence: ScheduleAbsence
    def __init__(self, observed_revision: _Optional[int] = ..., schedule: _Optional[_Union[Schedule, _Mapping]] = ..., absence: _Optional[_Union[ScheduleAbsence, _Mapping]] = ...) -> None: ...

class QuarantineScheduleRequest(_message.Message):
    __slots__ = ("project_id", "schedule_id", "observed_control_token", "reason_code", "detail", "scheduler_protocol_epoch")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_CONTROL_TOKEN_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    SCHEDULER_PROTOCOL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    schedule_id: str
    observed_control_token: str
    reason_code: str
    detail: str
    scheduler_protocol_epoch: int
    def __init__(self, project_id: _Optional[str] = ..., schedule_id: _Optional[str] = ..., observed_control_token: _Optional[str] = ..., reason_code: _Optional[str] = ..., detail: _Optional[str] = ..., scheduler_protocol_epoch: _Optional[int] = ...) -> None: ...

class QuarantineScheduleResponse(_message.Message):
    __slots__ = ("outcome", "observed_revision")
    OUTCOME_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_REVISION_FIELD_NUMBER: _ClassVar[int]
    outcome: QuarantineOutcome
    observed_revision: int
    def __init__(self, outcome: _Optional[_Union[QuarantineOutcome, str]] = ..., observed_revision: _Optional[int] = ...) -> None: ...

class AdvanceScheduleCursorRequest(_message.Message):
    __slots__ = ("project_id", "schedule_id", "observed_control_token", "definition_digest", "expected_schedule_revision", "expected_last_run_at", "expected_next_run_at", "skipped_through", "prepared_next_run_at", "scheduler_protocol_epoch", "cadence_semantics_version", "cadence_runtime_fingerprint")
    PROJECT_ID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_ID_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_CONTROL_TOKEN_FIELD_NUMBER: _ClassVar[int]
    DEFINITION_DIGEST_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SCHEDULE_REVISION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    SKIPPED_THROUGH_FIELD_NUMBER: _ClassVar[int]
    PREPARED_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    SCHEDULER_PROTOCOL_EPOCH_FIELD_NUMBER: _ClassVar[int]
    CADENCE_SEMANTICS_VERSION_FIELD_NUMBER: _ClassVar[int]
    CADENCE_RUNTIME_FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    project_id: str
    schedule_id: str
    observed_control_token: str
    definition_digest: str
    expected_schedule_revision: int
    expected_last_run_at: _timestamp_pb2.Timestamp
    expected_next_run_at: _timestamp_pb2.Timestamp
    skipped_through: _timestamp_pb2.Timestamp
    prepared_next_run_at: _timestamp_pb2.Timestamp
    scheduler_protocol_epoch: int
    cadence_semantics_version: int
    cadence_runtime_fingerprint: str
    def __init__(self, project_id: _Optional[str] = ..., schedule_id: _Optional[str] = ..., observed_control_token: _Optional[str] = ..., definition_digest: _Optional[str] = ..., expected_schedule_revision: _Optional[int] = ..., expected_last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expected_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., skipped_through: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., prepared_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., scheduler_protocol_epoch: _Optional[int] = ..., cadence_semantics_version: _Optional[int] = ..., cadence_runtime_fingerprint: _Optional[str] = ...) -> None: ...

class AdvanceScheduleCursorResponse(_message.Message):
    __slots__ = ("disposition", "committed_revision", "committed_last_run_at", "committed_next_run_at", "live_control_token", "live_revision", "live_last_run_at", "live_next_run_at", "error_code", "error_message")
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    LIVE_CONTROL_TOKEN_FIELD_NUMBER: _ClassVar[int]
    LIVE_REVISION_FIELD_NUMBER: _ClassVar[int]
    LIVE_LAST_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    LIVE_NEXT_RUN_AT_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    ERROR_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    disposition: CursorTransitionDisposition
    committed_revision: int
    committed_last_run_at: _timestamp_pb2.Timestamp
    committed_next_run_at: _timestamp_pb2.Timestamp
    live_control_token: str
    live_revision: int
    live_last_run_at: _timestamp_pb2.Timestamp
    live_next_run_at: _timestamp_pb2.Timestamp
    error_code: str
    error_message: str
    def __init__(self, disposition: _Optional[_Union[CursorTransitionDisposition, str]] = ..., committed_revision: _Optional[int] = ..., committed_last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., committed_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., live_control_token: _Optional[str] = ..., live_revision: _Optional[int] = ..., live_last_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., live_next_run_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., error_code: _Optional[str] = ..., error_message: _Optional[str] = ...) -> None: ...
