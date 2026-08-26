# syntax=docker.io/docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

# The outer system_authority.py build-platform command supplies only values
# validated from the canonical policy.  This Dockerfile contains the complete
# network split: acquisition may fetch authenticated Debian snapshot/Trivy
# bytes but never executes package maintainer scripts; qualification and
# scanner execution have no network at all.
ARG RESOLVER_IMAGE
FROM ${RESOLVER_IMAGE} AS authority-source
WORKDIR /authority
COPY docker/production/system-authority-policy.json ./system-authority-policy.json
COPY docker/production/system_authority.py ./system_authority.py
COPY docker/production/production_authority_common.py ./production_authority_common.py
COPY docker/production/production_material_build.py ./production_material_build.py

FROM authority-source AS acquire
ARG Z4J_PLATFORM
ARG Z4J_BUILD_ID
ARG Z4J_POLICY_SHA256
ENV Z4J_PLATFORM=${Z4J_PLATFORM} \
    Z4J_BUILD_ID=${Z4J_BUILD_ID} \
    Z4J_POLICY_SHA256=${Z4J_POLICY_SHA256}
RUN --network=default ["python3", "-P", "/authority/system_authority.py", "internal-acquire"]

# Every authenticated locked deb is installed with exact local-only argv in a
# disposable real-base stage.  Maintainer scripts can mutate only this stage;
# the later payload/scanner stage receives its closed receipt, never its rootfs.
FROM authority-source AS installability
ARG Z4J_PLATFORM
ARG Z4J_BUILD_ID
ARG Z4J_POLICY_SHA256
COPY --from=acquire /acquired /acquired
ENV Z4J_PLATFORM=${Z4J_PLATFORM} \
    Z4J_BUILD_ID=${Z4J_BUILD_ID} \
    Z4J_POLICY_SHA256=${Z4J_POLICY_SHA256}
RUN --network=none ["python3", "-P", "/authority/system_authority.py", "internal-installability"]

FROM authority-source AS qualify
ARG Z4J_PLATFORM
ARG Z4J_BUILD_ID
ARG Z4J_POLICY_SHA256
COPY --from=acquire /acquired /acquired
COPY --from=installability /installability /installability
ENV Z4J_PLATFORM=${Z4J_PLATFORM} \
    Z4J_BUILD_ID=${Z4J_BUILD_ID} \
    Z4J_POLICY_SHA256=${Z4J_POLICY_SHA256}
# The exact Trivy metadata scan and payload construction are below this
# explicit network-none boundary and execute no maintainer scripts.
RUN --network=none ["python3", "-P", "/authority/system_authority.py", "internal-build"]

FROM scratch AS export
COPY --from=qualify /out/ /
