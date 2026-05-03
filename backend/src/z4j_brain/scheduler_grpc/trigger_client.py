"""Brain-side gRPC client for the scheduler's TriggerSchedule RPC.

Sits opposite :class:`z4j_scheduler.trigger_grpc.server.TriggerGrpcServer`
- the dashboard's "fire now" button on a z4j-scheduler-managed
schedule routes through this client so the scheduler's local cache
gets the update (preventing the next tick from double-firing).

Connection model
----------------

One persistent ``grpc.aio.Channel`` per brain process. Construction
is cheap; :meth:`connect` opens the channel; :meth:`close` is
idempotent. Concurrent requests share the channel.

v1.1.0 reconnect semantics
--------------------------

The cached channel is reused across all trigger requests in the
process. If the scheduler restarts (rolling deploy, OOM-kill, sidecar
respawn) the cached channel goes stale: gRPC's HTTP/2 connection is
broken, the next call returns :data:`grpc.StatusCode.UNAVAILABLE`
(or ``DEADLINE_EXCEEDED`` if the call times out before the
connection error surfaces). :meth:`trigger` catches those two codes,
closes the dead channel, opens a fresh one, and retries the call
exactly once. Any other status code is re-raised, they're either
the scheduler's structured rejection (in which case the caller
already inspects ``response.error_code``) or a hard gRPC failure
that retry won't fix.

Operator deployment
-------------------

Brain needs three new env vars when ``Z4J_SCHEDULER_TRIGGER_URL``
is set:

- ``Z4J_SCHEDULER_TRIGGER_URL`` - host:port of the scheduler's
  trigger server, typically ``scheduler:7802``
- ``Z4J_SCHEDULER_TRIGGER_TLS_CERT`` - brain's client cert
- ``Z4J_SCHEDULER_TRIGGER_TLS_KEY`` - brain's client key
- ``Z4J_SCHEDULER_TRIGGER_TLS_CA`` - CA bundle for the scheduler's
  server cert

Without ``Z4J_SCHEDULER_TRIGGER_URL`` the brain falls back to its
existing direct-dispatch path on trigger-now (see ``api/schedules.py``).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

import grpc

from z4j_brain.scheduler_grpc.proto import scheduler_pb2 as pb
from z4j_brain.scheduler_grpc.proto import scheduler_pb2_grpc as pb_grpc

if TYPE_CHECKING:  # pragma: no cover
    from z4j_brain.settings import Settings

logger = logging.getLogger("z4j.brain.scheduler_grpc.trigger_client")

#: Per-call deadline for the unary TriggerSchedule RPC. Operators
#: clicking the dashboard expect feedback in seconds; we don't want
#: a hung scheduler to leave the request thread stuck for minutes.
_TRIGGER_TIMEOUT_SECONDS = 10.0

#: gRPC status codes that indicate the cached channel is stale and
#: a fresh connection might succeed. Any other code is either
#: structurally meaningful (NOT_FOUND, PERMISSION_DENIED) or a hard
#: failure (UNIMPLEMENTED, INTERNAL) and won't recover via retry.
_RECONNECT_STATUS_CODES = frozenset({
    grpc.StatusCode.UNAVAILABLE,
    grpc.StatusCode.DEADLINE_EXCEEDED,
})


class TriggerScheduleClient:
    """Async gRPC client for the scheduler's TriggerSchedule RPC.

    Constructed lazily by the FastAPI dependency the trigger route
    uses; one instance per brain process.
    """

    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings
        self._channel: grpc.aio.Channel | None = None
        self._stub: pb_grpc.SchedulerServiceStub | None = None
        # Round-7 audit fix R7-MED (race) (Apr 2026): serialise
        # connect/close. Without this, two concurrent ``trigger()``
        # callers could both see ``self._channel is None``, both
        # build a ``secure_channel``, both assign, the loser's
        # channel leaks (no ``close()``, no GC because of grpc-aio
        # internal refs).
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        """Open the channel + construct the stub. Idempotent."""
        if self._channel is not None:
            return
        if not self._settings.scheduler_trigger_url:
            raise RuntimeError(
                "TriggerScheduleClient.connect requires "
                "Z4J_SCHEDULER_TRIGGER_URL to be set",
            )
        async with self._lock:
            # Re-check inside the lock: another coroutine may have
            # connected while we were waiting.
            if self._channel is not None:
                return
            creds = _build_client_credentials(self._settings)
            channel = grpc.aio.secure_channel(
                self._settings.scheduler_trigger_url,
                creds,
            )
            self._channel = channel
            self._stub = pb_grpc.SchedulerServiceStub(channel)
            logger.info(
                "z4j.brain.scheduler_grpc.trigger_client: connected to %s",
                self._settings.scheduler_trigger_url,
            )

    async def close(self) -> None:
        """Close the channel cleanly. Idempotent."""
        async with self._lock:
            if self._channel is None:
                return
            channel = self._channel
            self._channel = None
            self._stub = None
        try:
            await channel.close(grace=2.0)
        except Exception:  # noqa: BLE001
            logger.debug(
                "z4j.brain.scheduler_grpc.trigger_client: close failed",
                exc_info=True,
            )

    async def trigger(
        self,
        *,
        schedule_id: UUID,
        user_id: UUID | None,
        idempotency_key: str | None = None,
    ) -> pb.TriggerScheduleResponse:
        """Issue a TriggerSchedule call. Caller handles error_code.

        v1.1.0: on UNAVAILABLE / DEADLINE_EXCEEDED (which typically
        means the scheduler restarted and the cached channel is
        stale), close the dead channel, open a fresh one, and retry
        exactly once. Other status codes propagate to the caller -
        the scheduler's own structured rejection (``response.error_code``)
        rides on a SUCCESS gRPC status by design.
        """
        if self._stub is None:
            await self.connect()
        assert self._stub is not None
        request = pb.TriggerScheduleRequest(
            schedule_id=str(schedule_id),
            user_id=str(user_id) if user_id is not None else "",
            idempotency_key=idempotency_key or "",
        )
        try:
            return await self._stub.TriggerSchedule(
                request, timeout=_TRIGGER_TIMEOUT_SECONDS,
            )
        except grpc.aio.AioRpcError as exc:
            if exc.code() not in _RECONNECT_STATUS_CODES:
                raise
            logger.warning(
                "z4j.brain.scheduler_grpc.trigger_client: stale channel "
                "(%s); reconnecting and retrying once",
                exc.code().name,
            )
            await self._reconnect()
            assert self._stub is not None
            return await self._stub.TriggerSchedule(
                request, timeout=_TRIGGER_TIMEOUT_SECONDS,
            )

    async def _reconnect(self) -> None:
        """Close + re-open the channel. Used by :meth:`trigger` to
        recover from a scheduler restart that orphaned the cached
        connection. Failures during close are swallowed (the channel
        is going away anyway); the connect phase raises if the
        scheduler is still unreachable so the caller sees a clean
        UNAVAILABLE on the second attempt.
        """
        try:
            await self.close()
        except Exception:  # noqa: BLE001
            logger.debug(
                "z4j.brain.scheduler_grpc.trigger_client: "
                "close during reconnect raised; ignoring",
                exc_info=True,
            )
        await self.connect()


def _build_client_credentials(settings: Settings) -> grpc.ChannelCredentials:
    """Read TLS material from settings into ChannelCredentials."""
    cert = _read_required_pem(
        settings.scheduler_trigger_tls_cert,
        "Z4J_SCHEDULER_TRIGGER_TLS_CERT",
    )
    key = _read_required_pem(
        settings.scheduler_trigger_tls_key,
        "Z4J_SCHEDULER_TRIGGER_TLS_KEY",
    )
    ca = _read_required_pem(
        settings.scheduler_trigger_tls_ca,
        "Z4J_SCHEDULER_TRIGGER_TLS_CA",
    )
    return grpc.ssl_channel_credentials(
        root_certificates=ca,
        private_key=key,
        certificate_chain=cert,
    )


def _read_required_pem(path_str: str | None, env_var: str) -> bytes:
    if not path_str:
        raise RuntimeError(
            f"TriggerScheduleClient requires {env_var} to be set",
        )
    path = Path(path_str)
    if not path.is_file():
        raise RuntimeError(
            f"{env_var} points at {path_str!r} which does not exist",
        )
    data = path.read_bytes()
    if not data.strip():
        raise RuntimeError(f"{env_var} file at {path_str!r} is empty")
    return data


__all__ = ["TriggerScheduleClient"]
