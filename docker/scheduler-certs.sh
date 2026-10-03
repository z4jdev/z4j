#!/bin/sh
# scheduler-certs.sh - mint the mTLS material for the z4j scheduler channel.
#
# The brain serves its scheduler gRPC service over mutual TLS, and the
# scheduler presents a client certificate whose CN the brain allow-lists.
# This script creates everything that handshake needs in one directory:
#
#   ca.crt  ca.key                  private CA; the key stays root-only
#   brain.crt  brain.key            server certificate presented by the brain
#   scheduler.crt  scheduler.key    client certificate presented by the scheduler
#
# It is the entrypoint of the ``scheduler-certs`` one-shot service in the
# shipped Compose stacks, where it runs as root, writes into the
# ``z4j_scheduler_pki`` named volume and hands the files to the uid the
# brain and the scheduler run as. It also runs on any host that has a
# POSIX sh and openssl; nothing else is required.
#
# Idempotent. An existing valid bundle is left alone. A certificate is
# minted again only when it is missing, does not chain to the current CA,
# does not match its key, expires within Z4J_PKI_RENEW_DAYS, or was minted
# for different names. Restart the brain and the scheduler after a renewal;
# both read their files at startup.
#
# Settings, all optional, all from the environment:
#
#   Z4J_PKI_DIR            output directory                        /pki
#   Z4J_PKI_BRAIN_SANS     comma-separated DNS names the brain is   z4j,brain,localhost
#                          dialed by (127.0.0.1 and ::1 are added)
#   Z4J_PKI_SCHEDULER_CN   CN and DNS SAN of the client cert; put   z4j-scheduler
#                          it in Z4J_SCHEDULER_GRPC_ALLOWED_CNS
#   Z4J_PKI_CA_DAYS        CA validity, days                        3650
#   Z4J_PKI_LEAF_DAYS      brain and scheduler validity, days       825
#   Z4J_PKI_RENEW_DAYS     mint again this close to expiry, days    30
#   Z4J_PKI_OWNER          uid:gid given the brain and scheduler    10001:10001
#                          files when running as root
#   Z4J_PKI_FORCE          1 discards the bundle and mints it again 0
#
# Prints file names, subjects, names and expiry dates. Never prints key
# material. Exits non-zero on any failure, so a Compose ``depends_on`` with
# ``condition: service_completed_successfully`` holds the brain and the
# scheduler back until the bundle exists.

set -euf
umask 077

PKI_DIR=${Z4J_PKI_DIR:-/pki}
BRAIN_SANS=${Z4J_PKI_BRAIN_SANS:-z4j,brain,localhost}
SCHEDULER_CN=${Z4J_PKI_SCHEDULER_CN:-z4j-scheduler}
CA_DAYS=${Z4J_PKI_CA_DAYS:-3650}
LEAF_DAYS=${Z4J_PKI_LEAF_DAYS:-825}
RENEW_DAYS=${Z4J_PKI_RENEW_DAYS:-30}
OWNER=${Z4J_PKI_OWNER:-10001:10001}
FORCE=${Z4J_PKI_FORCE:-0}

CA_SUBJECT="/CN=z4j scheduler channel CA"

log() { printf 'scheduler-certs: %s\n' "$*"; }
die() { printf 'scheduler-certs: error: %s\n' "$*" >&2; exit 1; }

require_dns_label() { # $1 setting, $2 value
  case $2 in
    "" | *[!A-Za-z0-9._-]* | -* | .*)
      die "$1 must be a DNS-style name (letters, digits, '.', '_', '-'); got '$2'" ;;
  esac
}

require_days() { # $1 setting, $2 value, $3 minimum
  case $2 in
    "" | *[!0-9]*) die "$1 must be a whole number of days; got '$2'" ;;
  esac
  [ "$2" -ge "$3" ] || die "$1 must be at least $3; got '$2'"
}

command -v openssl >/dev/null 2>&1 || die "openssl is not installed"
require_dns_label Z4J_PKI_SCHEDULER_CN "$SCHEDULER_CN"
require_days Z4J_PKI_CA_DAYS "$CA_DAYS" 1
require_days Z4J_PKI_LEAF_DAYS "$LEAF_DAYS" 1
require_days Z4J_PKI_RENEW_DAYS "$RENEW_DAYS" 0
case $OWNER in
  "" | *[!0-9:]* | *:*:*) die "Z4J_PKI_OWNER must be a numeric uid:gid; got '$OWNER'" ;;
esac

# Split the server names on commas; the first one becomes the subject CN.
old_ifs=$IFS
IFS=,
set -- $BRAIN_SANS
IFS=$old_ifs
SERVER_SANS=
SERVER_CN=
for name in "$@"; do
  name=$(printf '%s' "$name" | tr -d '[:space:]')
  [ -n "$name" ] || continue
  require_dns_label Z4J_PKI_BRAIN_SANS "$name"
  SERVER_SANS="${SERVER_SANS:+$SERVER_SANS,}DNS:$name"
  [ -n "$SERVER_CN" ] || SERVER_CN=$name
done
[ -n "$SERVER_SANS" ] || die "Z4J_PKI_BRAIN_SANS names no host"
SERVER_SANS="$SERVER_SANS,IP:127.0.0.1,IP:::1"
CLIENT_SANS="DNS:$SCHEDULER_CN"
PARAMS="sans=$SERVER_SANS cn=$SCHEDULER_CN"
RENEW_SECONDS=$((RENEW_DAYS * 86400))

# ``openssl req`` insists on a configuration file even when every field
# comes from the command line, and not every openssl build ships one.
# Carry a minimal one so the script does not depend on the host's.
REQ_CONF="$PKI_DIR/.openssl.cnf"
scratch_files="$REQ_CONF $PKI_DIR/.brain.csr $PKI_DIR/.brain.ext \
$PKI_DIR/.scheduler.csr $PKI_DIR/.scheduler.ext $PKI_DIR/.params.tmp"
cleanup() {
  for f in $scratch_files; do
    rm -f "$f"
  done
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Checks on the existing bundle
# ---------------------------------------------------------------------------
outlives_renew_window() { # $1 cert
  openssl x509 -in "$1" -noout -checkend "$RENEW_SECONDS" >/dev/null 2>&1
}

chains_to_ca() { # $1 cert
  openssl verify -CAfile "$PKI_DIR/ca.crt" "$1" >/dev/null 2>&1
}

key_matches() { # $1 cert, $2 key
  cert_pub=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null) || return 1
  key_pub=$(openssl pkey -in "$2" -pubout 2>/dev/null) || return 1
  [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ]
}

# ---------------------------------------------------------------------------
# Minting
# ---------------------------------------------------------------------------
mint_key() { # $1 path
  rm -f "$1"
  openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve \
    -out "$1"
}

write_req_conf() {
  printf '[req]\ndistinguished_name = req_dn\n[req_dn]\n' >"$REQ_CONF"
}

mint_ca() {
  log "minting the CA ($CA_DAYS days)"
  write_req_conf
  mint_key "$PKI_DIR/ca.key"
  openssl req -x509 -new -config "$REQ_CONF" -key "$PKI_DIR/ca.key" \
    -sha256 -days "$CA_DAYS" \
    -subj "$CA_SUBJECT" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$PKI_DIR/ca.crt"
}

mint_leaf() { # $1 file stem, $2 CN, $3 subjectAltName, $4 extendedKeyUsage
  log "minting the $1 certificate (CN=$2; $3; $LEAF_DAYS days)"
  csr="$PKI_DIR/.$1.csr"
  ext="$PKI_DIR/.$1.ext"
  write_req_conf
  mint_key "$PKI_DIR/$1.key"
  openssl req -new -config "$REQ_CONF" -key "$PKI_DIR/$1.key" -sha256 \
    -subj "/CN=$2" -out "$csr"
  {
    printf 'basicConstraints=critical,CA:FALSE\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'extendedKeyUsage=%s\n' "$4"
    printf 'subjectAltName=%s\n' "$3"
  } >"$ext"
  openssl x509 -req -in "$csr" -CA "$PKI_DIR/ca.crt" -CAkey "$PKI_DIR/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -sha256 -days "$LEAF_DAYS" \
    -extfile "$ext" -out "$PKI_DIR/$1.crt"
  rm -f "$csr" "$ext"
}

# ---------------------------------------------------------------------------
# Decide what to mint
# ---------------------------------------------------------------------------
mkdir -p "$PKI_DIR"

why=
need_ca=0
if [ "$FORCE" = 1 ]; then
  need_ca=1
  why="Z4J_PKI_FORCE=1"
elif [ ! -s "$PKI_DIR/ca.crt" ] || [ ! -s "$PKI_DIR/ca.key" ]; then
  need_ca=1
  why="no CA in $PKI_DIR yet"
elif ! key_matches "$PKI_DIR/ca.crt" "$PKI_DIR/ca.key"; then
  need_ca=1
  why="the CA certificate and key do not match"
elif ! outlives_renew_window "$PKI_DIR/ca.crt"; then
  need_ca=1
  why="the CA expires within $RENEW_DAYS days"
fi

need_leaves=$need_ca
if [ "$need_leaves" = 0 ]; then
  if [ ! -s "$PKI_DIR/.params" ] || [ "$(cat "$PKI_DIR/.params")" != "$PARAMS" ]; then
    need_leaves=1
    why="the requested names differ from the minted ones"
  else
    for stem in brain scheduler; do
      crt="$PKI_DIR/$stem.crt"
      key="$PKI_DIR/$stem.key"
      if [ ! -s "$crt" ] || [ ! -s "$key" ]; then
        need_leaves=1
        why="the $stem certificate or key is missing"
      elif ! key_matches "$crt" "$key"; then
        need_leaves=1
        why="the $stem certificate and key do not match"
      elif ! chains_to_ca "$crt"; then
        need_leaves=1
        why="the $stem certificate does not chain to the CA"
      elif ! outlives_renew_window "$crt"; then
        need_leaves=1
        why="the $stem certificate expires within $RENEW_DAYS days"
      fi
    done
  fi
fi

if [ "$need_ca" = 1 ]; then
  log "$why"
  mint_ca
fi
if [ "$need_leaves" = 1 ]; then
  [ "$need_ca" = 1 ] || log "$why"
  mint_leaf brain "$SERVER_CN" "$SERVER_SANS" serverAuth
  mint_leaf scheduler "$SCHEDULER_CN" "$CLIENT_SANS" clientAuth
  printf '%s' "$PARAMS" >"$PKI_DIR/.params.tmp"
  mv "$PKI_DIR/.params.tmp" "$PKI_DIR/.params"
else
  log "the bundle in $PKI_DIR is valid; nothing to mint"
fi

# ---------------------------------------------------------------------------
# Permissions: certificates world-readable, keys owner-only, the CA key and
# the directory root-owned when we are root, everything else handed to the
# uid the brain and the scheduler run as.
# ---------------------------------------------------------------------------
chmod 755 "$PKI_DIR"
chmod 644 "$PKI_DIR/ca.crt" "$PKI_DIR/brain.crt" "$PKI_DIR/scheduler.crt"
chmod 600 "$PKI_DIR/ca.key" "$PKI_DIR/brain.key" "$PKI_DIR/scheduler.key" "$PKI_DIR/.params"
if [ "$(id -u)" = 0 ]; then
  chown 0:0 "$PKI_DIR" "$PKI_DIR/ca.key" "$PKI_DIR/.params"
  chown "$OWNER" "$PKI_DIR/ca.crt" \
    "$PKI_DIR/brain.crt" "$PKI_DIR/brain.key" \
    "$PKI_DIR/scheduler.crt" "$PKI_DIR/scheduler.key"
fi

# ---------------------------------------------------------------------------
# Report (nothing secret)
# ---------------------------------------------------------------------------
describe() { # $1 label, $2 cert
  log "$1: $(openssl x509 -in "$2" -noout -subject -enddate | tr '\n' ' ')"
  names=$(openssl x509 -in "$2" -noout -ext subjectAltName 2>/dev/null | sed -n '2s/^ *//p') || names=
  [ -z "$names" ] || log "$1 names: $names"
}
describe "CA" "$PKI_DIR/ca.crt"
describe "brain" "$PKI_DIR/brain.crt"
describe "scheduler" "$PKI_DIR/scheduler.crt"
log "brain allow-list entry for Z4J_SCHEDULER_GRPC_ALLOWED_CNS: $SCHEDULER_CN"
