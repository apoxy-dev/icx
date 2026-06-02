# InterCloud eXpress (ICX) - CLI

ICX encrypts tunnel traffic with AES-128-GCM. Keys can be established two ways:

- **Control plane (recommended):** a QUIC/mTLS channel negotiates fresh,
  forward-secret, per-session keys and rotates them automatically. This is the only
  mode that is safe across restarts.
- **Static keys (legacy):** a pair of pre-shared keys loaded from an INI file and
  rotated by hand via `SIGHUP`. Retained for compatibility; see the caveats below.

The two modes are mutually exclusive and fail closed: configure exactly one. ICX never
silently falls back from the control plane to static keys.

## Control plane (recommended)

Each node has a long-term **identity key** (ECDSA P-256). Peers authenticate each other
WireGuard-style by pinning the expected public key — there is no CA. The control channel
runs on its own UDP port (`--control-port`, default `6082`), separate from the Geneve
data port (`--port`, default `6081`); the XDP filter only redirects the data port to
AF_XDP, so the control port rides the normal kernel stack.

### 1) Generate an identity on each host

```bash
# Host A
icx genkey --identity-key /etc/icx/identity.pem
# prints Host A's public key (base64) to stderr

# Host B
icx genkey --identity-key /etc/icx/identity.pem
```

`genkey` refuses to overwrite an existing key file (pass `--force` to override). Recover
a public key at any time:

```bash
icx pubkey --identity-key /etc/icx/identity.pem
```

### 2) Exchange public keys

Distribute each host's public key to the other out of band. The value is what you pass
as the peer's `--peer-key` (it accepts the base64 string directly or a path to a file
containing it).

### 3) Start ICX on both hosts

Both hosts run the same command shape; the dialer/listener roles are elected
deterministically from the two public keys, so no extra configuration is needed. Use the
**same `--control-port`** on both ends.

```bash
# Host A  (peer is B's data address)
icx -i eth0 \
  --identity-key /etc/icx/identity.pem \
  --peer-key '<B public key>' \
  198.51.100.7:6081

# Host B  (peer is A's data address)
icx -i eth0 \
  --identity-key /etc/icx/identity.pem \
  --peer-key '<A public key>' \
  203.0.113.2:6081
```

ICX establishes the control plane (fail-closed: if the handshake or first negotiation
fails, the tunnel does not come up), installs the negotiated keys, and renegotiates a
fresh security association every `--rekey-interval` (default `2m`). Rotation is
make-before-break: the previous receive key is honored for a 30s grace period.

Relevant flags:

- `--identity-key PATH` — this node's identity private key.
- `--peer-key STR|PATH` — the peer's pinned public key.
- `--control-port PORT` — control-plane UDP port (default `6082`; must match on both ends).
- `--peer-control-port PORT` — peer's control port if it differs (defaults to `--control-port`).
- `--rekey-interval DUR` — SA rotation period (default `2m`).
- `--require-fips` — refuse to start unless the Go FIPS 140-3 module is active
  (build/run with `GODEBUG=fips140=on`).
- `--state-file PATH` — persist the epoch high-water so a one-sided restart recovers
  seamlessly (see "Restart / reconnect"). Set it on **both** peers. Without it, a
  one-sided *initiator* restart recovers only after both peers cycle.
- `--require-state` — fail closed if the state file is corrupt/unreadable or becomes
  persistently un-writable, instead of degrading to a fresh start. Requires
  `--state-file`. It is an integrity tripwire against accidental corruption, not a
  defense against an attacker who can rewrite or delete the file.

### Operational notes

**Startup ordering.** The peers elect dialer/listener roles from their keys; the dialer
retries the QUIC handshake only for the handshake window (~10s). If the listener is not up
within that window the dialer's process exits (fail-closed — no tunnel comes up). Start both
ends close together, and run under a supervisor (systemd `Restart=always`, a container
restart policy) so a larger startup skew self-heals on restart. Once established, the control
plane reconnects on its own indefinitely.

**Restart / reconnect.** Control-plane keys are ephemeral, so a *clean* restart is always
crypto-safe: a new session derives fresh keys, and a reset transmit counter cannot reuse a
nonce under a fresh key. The remaining question is *availability* after a restart, which the
control plane handles in two layers:

- **Always on (no flag):** the data-plane epoch counter resets to 1 on every (re)connect, but
  the surviving peer's monotonicity guard only accepts a strictly increasing epoch. ICX
  carries the epoch high-water forward in memory and seeds each new session above it, so a
  **transient reconnect** (a network blip) and a **responder restart** recover immediately —
  the surviving *initiator* keeps the high-water and the restarted responder comes up fresh.

- **With `--state-file` (recommended):** the high-water is also persisted durably (fsync +
  atomic rename, integrity-protected by a MAC keyed from the identity), so an **initiator
  restart** recovers too — the restarted initiator reloads the high-water and resumes above
  the survivor's retained epoch. The dialer/listener role is auto-elected from the keys, so
  set `--state-file` on **both** peers; only the elected initiator's file is load-bearing, and
  the start-up log shows whether durable state is active for this node's role.

Without `--state-file`, a one-sided *initiator* restart still has the old caveat: the survivor
forwards on its existing keys until they expire and only re-keys once the new counter climbs
past the retained high-water — **cycle both peers** to recover immediately.

`--require-state` makes a corrupt/unreadable state file (or persistently failing writes) fail
closed instead of silently starting fresh. It is an integrity tripwire against accidental
corruption only: because keys are per-session ephemeral, even a rolled-back or deleted
high-water cannot cause nonce reuse — only a transient outage — so rollback and deletion
resistance (which would need a hardware monotonic counter) are out of scope. Use one state
file per tunnel; do not share it between processes.

## Static keys (legacy)

> Prefer the control plane. Static keys provide **no forward secrecy** and are **not safe
> across restarts**: a restart re-reads the INI starting again at epoch 1 with the TX
> counter reset to 0, so **do not restart against an unchanged key file** — rotate to
> fresh keys (below), otherwise the AES-GCM nonce sequence is reused under the same key.

ICX enforces two invariants when keys are installed and refuses the key otherwise: `rx`
and `tx` **must differ** (each direction needs its own key), and the key epoch must
**strictly increase** within a running process.

### 1) Generate two one-time keys

```bash
# Key used for A → B traffic
K_AB=$(openssl rand -hex 16)
# Key used for B → A traffic
K_BA=$(openssl rand -hex 16)
```

### 2) Create an INI file on each host

Each host reads keys from an INI file at `--key-file`. The required format is:

```ini
[keys]
rx=<32 hex chars>   # the key this host expects to RECEIVE with
tx=<32 hex chars>   # the key this host will TRANSMIT with
# Optional expiry (defaults to 24h if omitted):
# - as a Go duration (e.g. 24h, 90m)
# - or an RFC3339 timestamp (e.g. 2025-10-16T12:34:56Z)
expires=24h
```

For Host A `rx=${K_BA}`, `tx=${K_AB}`; for Host B `rx=${K_AB}`, `tx=${K_BA}`.

### 3) Start ICX on both hosts

```bash
icx -i <iface> --key-file=/path/to/icx.ini <peer_ip>:<port>
```

### 4) Key rotation (SIGHUP)

Update the same INI file with new rx/tx values, then send `SIGHUP`:

```bash
pkill -HUP icx
```

ICX reloads the INI, bumps the epoch, and applies the new keys. If the reloaded keys are
identical to the current ones, the reload is refused (epoch unchanged). `SIGHUP` reload is
only active in static mode.
