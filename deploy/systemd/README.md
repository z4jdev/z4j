# z4j systemd units

Two hardened units for a pip-installed z4j on one Linux host: the brain
and, optionally, the standalone scheduler. They ship in the `z4j` sdist
under `deploy/systemd/` and in the source repository.

## Install

```sh
# 1. A system user and a virtualenv the units expect.
sudo useradd --system --home-dir /var/lib/z4j --shell /usr/sbin/nologin z4j
sudo python3 -m venv /opt/z4j/venv
sudo /opt/z4j/venv/bin/pip install z4j            # brain
sudo /opt/z4j/venv/bin/pip install z4j-scheduler  # only for the standalone scheduler

# 2. Configuration, readable by root only (systemd passes it to the process).
sudo install -d -m 0750 -o root -g z4j /etc/z4j
sudo install -m 0600 brain.env.example /etc/z4j/brain.env
sudo editor /etc/z4j/brain.env                    # public URL, allowed hosts, secrets, database

# 3. The unit.
sudo install -m 0644 z4j-brain.service /etc/systemd/system/z4j-brain.service
sudo systemctl daemon-reload
sudo systemctl enable --now z4j-brain

# 4. First boot prints a one-time setup URL in the journal.
sudo journalctl -u z4j-brain -f
curl http://127.0.0.1:7700/api/v1/health/ready
```

The brain listens on loopback and expects a reverse proxy (Caddy, nginx,
Traefik) to terminate TLS and forward `X-Forwarded-For`; `Z4J_PUBLIC_URL`
is the https origin and `Z4J_TRUSTED_PROXIES` names the proxy.

`StateDirectory=z4j` makes systemd create `/var/lib/z4j` as `Z4J_HOME`,
owned by the service user. The SQLite database, generated secrets and
recovery manifests live there; back it up with the database.

## Standalone scheduler

Enable the brain's gRPC listener in `/etc/z4j/brain.env` (the commented
`Z4J_SCHEDULER_GRPC_*` block), mint the certificates against a CA you
control, and install the second unit:

```sh
sudo install -d -m 0750 -o root -g z4j /etc/z4j/tls
# brain.crt / brain.key: server leaf for the listener's host name or IP
# scheduler-1.crt / scheduler-1.key: from `z4j mint-scheduler-cert --name scheduler-1 --ca-cert ca.crt --ca-key ca.key --out-dir .`
sudo install -m 0640 -o root -g z4j ca.crt brain.crt brain.key scheduler-1.crt scheduler-1.key /etc/z4j/tls/
sudo install -m 0600 scheduler.env.example /etc/z4j/scheduler.env
sudo install -m 0644 z4j-scheduler.service /etc/systemd/system/z4j-scheduler.service
sudo systemctl daemon-reload
sudo systemctl restart z4j-brain
sudo systemctl enable --now z4j-scheduler
curl http://127.0.0.1:7800/ready
```

Alternatively set `Z4J_EMBEDDED_SCHEDULER=true` in `brain.env` and skip
the second unit: the brain supervises the scheduler as a subprocess with
auto-minted loopback PKI.

## Rotation and upgrades

Both processes read their environment and certificate files once at
start. After editing an env file or replacing certificates, restart the
unit: `sudo systemctl restart z4j-brain` (or `z4j-scheduler`). Upgrade
with `pip install --upgrade z4j` in the venv, then restart; the brain runs
its database migrations on boot. Stop the scheduler before upgrading the
brain and start it again afterwards, so no fire lands in a mixed-version
window.

## Hardening

Each unit applies the systemd sandbox (`ProtectSystem=strict`,
`NoNewPrivileges`, an empty capability set, `@system-service` syscall
filter, read-only `/etc`, private `/tmp` and devices). Inspect it with
`systemd-analyze security z4j-brain`. If the journal shows the process
being refused something it needs, relax that one directive with
`systemctl edit z4j-brain` rather than removing the block.
