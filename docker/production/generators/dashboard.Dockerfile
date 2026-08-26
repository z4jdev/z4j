# syntax=docker.io/docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d

# Dashboard acquisition may fetch the exact pnpm/store/Trivy authorities.
# Install, Vite build, offline replay, scan, and payload construction execute
# only under the explicit network-none boundary.
ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS authority-source
WORKDIR /authority
COPY docker/production/dashboard-authority-policy.json ./dashboard-authority-policy.json
COPY docker/production/dashboard_authority.py ./dashboard_authority.py
COPY docker/production/production_authority_common.py ./production_authority_common.py
COPY docker/production/production_material_build.py ./production_material_build.py
COPY docker/production/generators/dashboard.mjs ./dashboard.mjs
COPY dashboard/.npmrc /source/dashboard/.npmrc
COPY dashboard/components.json /source/dashboard/components.json
COPY dashboard/index.html /source/dashboard/index.html
COPY dashboard/package.json /source/dashboard/package.json
COPY dashboard/pnpm-lock.yaml /source/dashboard/pnpm-lock.yaml
COPY dashboard/pnpm-workspace.yaml /source/dashboard/pnpm-workspace.yaml
COPY dashboard/public /source/dashboard/public
COPY dashboard/scripts /source/dashboard/scripts
COPY dashboard/src /source/dashboard/src
COPY dashboard/tsconfig.json /source/dashboard/tsconfig.json
COPY dashboard/vite.config.ts /source/dashboard/vite.config.ts

FROM authority-source AS acquire
ARG Z4J_PLATFORM
ARG Z4J_BUILD_ID
ARG Z4J_POLICY_SHA256
ENV Z4J_PLATFORM=${Z4J_PLATFORM} \
    Z4J_BUILD_ID=${Z4J_BUILD_ID} \
    Z4J_POLICY_SHA256=${Z4J_POLICY_SHA256}
RUN --network=default ["node", "/authority/dashboard.mjs", "internal-acquire"]

FROM authority-source AS qualify
ARG Z4J_PLATFORM
ARG Z4J_BUILD_ID
ARG Z4J_POLICY_SHA256
COPY --from=acquire /acquired /acquired
ENV Z4J_PLATFORM=${Z4J_PLATFORM} \
    Z4J_BUILD_ID=${Z4J_BUILD_ID} \
    Z4J_POLICY_SHA256=${Z4J_POLICY_SHA256}
RUN --network=none ["node", "/authority/dashboard.mjs", "internal-build"]

FROM scratch AS export
COPY --from=qualify /out/ /
