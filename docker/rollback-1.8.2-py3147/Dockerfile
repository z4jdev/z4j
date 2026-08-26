# syntax=docker.io/docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d
#
# z4j 1.8.2 / CPython 3.14.7 rollback-compatibility image.
#
# This is a content-addressed OCI rebase, not a source build and not a package
# resolution. The released 1.8.2 site-packages tree is copied from the
# immutable public image while the interpreter and standard library remain
# those of the immutable CPython 3.14.7 carrier. There is deliberately no
# package-manager or network operation in this file.
#
# tzdata is the one distribution NOT taken from the released image, and the
# reason is the same one that makes this image exist at all. Unchanged 1.8
# code accepts exactly one local cadence fingerprint, so the rollback ceremony
# can only restamp cursors this carrier will agree with if the carrier's
# cadence closure equals the candidate's. That is already why the interpreter
# is 3.14.7 rather than the 3.14.6 the released image shipped. The candidate
# pins IANA 2026c, so this carrier carries the same bytes, supplied as a
# digest-pinned wheel in the build context. The application tree is untouched.
#
# Do not retag this image as 1.8.2, 1.8, or latest. Its only permitted public
# tag is locked in manifest.json and the release workflow; rollback runbooks
# must still consume the promoted image by digest.

ARG SOURCE_DATE_EPOCH=1787184000

FROM docker.io/z4jdev/z4j@sha256:ed2dac96f24b4ea42fcc89e76f459035365229d62f9d8efe916741cfd9373c03 AS released

FROM docker.io/library/python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="z4j" \
      org.opencontainers.image.description="z4j 1.8.2 rollback compatibility runtime for a 1.9.0 rollback" \
      org.opencontainers.image.version="1.8.2" \
      org.opencontainers.image.revision="891d66f77cd87b93311eaf2ed8189e1780430e2c" \
      org.opencontainers.image.source="https://github.com/z4jdev/z4j" \
      org.opencontainers.image.url="https://github.com/z4jdev/z4j/tree/v1.8.2" \
      org.opencontainers.image.documentation="https://z4j.dev" \
      org.opencontainers.image.vendor="z4j contributors" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.base.name="docker.io/library/python:3.14.7-slim-trixie" \
      org.opencontainers.image.base.digest="sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4" \
      io.z4j.rollback.target="1.9.0" \
      io.z4j.rollback.compatibility.python="3.14.7" \
      io.z4j.rollback.source.image="docker.io/z4jdev/z4j@sha256:ed2dac96f24b4ea42fcc89e76f459035365229d62f9d8efe916741cfd9373c03" \
      io.z4j.rollback.source.tag-object="ca60bf9013ec923b64e13123c19b2bb55c798550" \
      io.z4j.rollback.source.commit="891d66f77cd87b93311eaf2ed8189e1780430e2c" \
      io.z4j.rollback.source.tree="0913546d59a4661ca2f2e17512ec2acfc46305ea"

ENV Z4J_RESOLVED_VERSION=1.8.2 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    Z4J_LOG_JSON=true \
    Z4J_BIND_HOST=0.0.0.0 \
    Z4J_BIND_PORT=7700 \
    Z4J_ENVIRONMENT=production \
    Z4J_PUBLIC_URL=http://localhost:7700 \
    Z4J_ALLOWED_HOSTS='["localhost","127.0.0.1"]' \
    Z4J_ALLOW_HTTP_PUBLIC_URL=true \
    Z4J_HOME=/data

# Delete the carrier's package payload as a unit. Copying into an existing
# directory would permit a carrier-only distribution to survive the rebase.
RUN rm -rf /usr/local/lib/python3.14/site-packages \
    && mkdir -p /usr/local/lib/python3.14/site-packages

# This is the only old-image Python tree admitted into the runtime. In
# particular, no old /usr/local/bin/python*, stdlib, shared library, or include
# tree is copied.
COPY --from=released /usr/local/lib/python3.14/site-packages/ /usr/local/lib/python3.14/site-packages/

# The single deliberate deviation from the released image's site-packages.
# The wheel is content-addressed: the build refuses if its bytes are not the
# exact reviewed artifact, so this cannot silently become a different tzdb.
COPY tzdata-2026.3-py2.py3-none-any.whl /tmp/tzdata.whl
RUN set -eu \
    && echo "dc096730c87af6cab1b171c9d532be840741ff5d459015e7f6947bd7d7e54931  /tmp/tzdata.whl" | sha256sum -c - \
    && rm -rf /usr/local/lib/python3.14/site-packages/tzdata \
              /usr/local/lib/python3.14/site-packages/tzdata-2026.1.dist-info \
    && python -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" \
              /tmp/tzdata.whl /usr/local/lib/python3.14/site-packages \
    && rm -f /tmp/tzdata.whl \
    && find /usr/local/lib/python3.14/site-packages/tzdata \
            /usr/local/lib/python3.14/site-packages/tzdata-2026.3.dist-info \
            -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} + \
    && python -c "import importlib.metadata as m; assert m.version('tzdata') == '2026.3', m.version('tzdata')"

# RECORD-owned entry points are copied explicitly. The generated bin
# __pycache__/vba_extract.cpython-314.pyc is not authority and is not copied.
COPY --from=released /usr/local/bin/alembic /usr/local/bin/alembic
COPY --from=released /usr/local/bin/cffi-gen-src /usr/local/bin/cffi-gen-src
COPY --from=released /usr/local/bin/dotenv /usr/local/bin/dotenv
COPY --from=released /usr/local/bin/email_validator /usr/local/bin/email_validator
COPY --from=released /usr/local/bin/fastapi /usr/local/bin/fastapi
COPY --from=released /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=released /usr/local/bin/idna /usr/local/bin/idna
COPY --from=released /usr/local/bin/mako-render /usr/local/bin/mako-render
COPY --from=released /usr/local/bin/markdown-it /usr/local/bin/markdown-it
COPY --from=released /usr/local/bin/pip3 /usr/local/bin/pip3
COPY --from=released /usr/local/bin/pip3.14 /usr/local/bin/pip3.14
COPY --from=released /usr/local/bin/pygmentize /usr/local/bin/pygmentize
COPY --from=released /usr/local/bin/python-grpc-tools-protoc /usr/local/bin/python-grpc-tools-protoc
COPY --from=released /usr/local/bin/typer /usr/local/bin/typer
COPY --from=released /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=released /usr/local/bin/vba_extract.py /usr/local/bin/vba_extract.py
COPY --from=released /usr/local/bin/watchfiles /usr/local/bin/watchfiles
COPY --from=released /usr/local/bin/websockets /usr/local/bin/websockets
COPY --from=released /usr/local/bin/z4j /usr/local/bin/z4j
COPY --from=released /usr/local/bin/z4j-scheduler /usr/local/bin/z4j-scheduler

# greenlet owns this public CPython-3.14 header. Tini is copied as the
# architecture-native static binary because the carrier has no apt packages.
COPY --from=released /usr/local/include/python3.14/greenlet/greenlet.h /usr/local/include/python3.14/greenlet/greenlet.h
COPY --from=released /usr/bin/tini-static /usr/bin/tini-static

# The verifier is image content. The manifest is deliberately external because
# its finalized candidate digest cannot be embedded in the image it identifies.
COPY --chmod=0555 verify.py /usr/local/share/z4j-rollback-compat/verify.py

RUN groupadd --system --gid 10001 z4j \
    && useradd --system --uid 10001 --gid z4j --home-dir /app --shell /usr/sbin/nologin z4j \
    && mkdir -p /app /data \
    && chmod 0700 /data \
    && chown -R z4j:z4j /app /data

VOLUME /data
WORKDIR /data
USER z4j
EXPOSE 7700

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7700/api/v1/health',timeout=3).status==200 else 1)"

ENTRYPOINT ["/usr/bin/tini-static", "--", "z4j"]
CMD ["serve"]
