"""Generated gRPC stubs from ``packages/z4j-scheduler/proto/scheduler.proto``.

Stubs are committed (not generated at install time) so the
``grpcio-tools`` toolchain is build-only. Both brain and scheduler
ship copies of these stubs generated from the same source .proto.

Regenerate via:

    cd packages/z4j-scheduler
    python -m grpc_tools.protoc \\
      -I proto \\
      --python_out=../z4j-brain/backend/src/z4j_brain/scheduler_grpc/proto \\
      --grpc_python_out=../z4j-brain/backend/src/z4j_brain/scheduler_grpc/proto \\
      proto/scheduler.proto

Both copies must be regenerated together when the proto changes.

The Phase 0 commit ships an empty package; the actual stubs land
in Phase 1 alongside the gRPC server implementation.
"""
