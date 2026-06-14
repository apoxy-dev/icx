# InterCloud eXpress (ICX) - CLI

ICX encrypts tunnel traffic with AES-128-GCM. Keys are established by a **QUIC/mTLS
control plane**: a channel that authenticates the peers, negotiates fresh,
forward-secret, per-session keys, and rotates them automatically — so the tunnel is safe
across restarts with no persisted key state.

## Control plane

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

### Operational notes

**Startup ordering.** The peers elect dialer/listener roles from their keys; the dialer
retries the QUIC handshake only for the handshake window (~10s). If the listener is not up
within that window the dialer's process exits (fail-closed — no tunnel comes up). Start both
ends close together, and run under a supervisor (systemd `Restart=always`, a container
restart policy) so a larger startup skew self-heals on restart. Once established, the control
plane reconnects on its own indefinitely.

**Restart / reconnect.** Control-plane keys are ephemeral, so any restart or reconnect is
both crypto-safe and seamless, with **no persisted state to manage**.

Each direction is a simplex SA with its own SPI: the receiver allocates it, the sender
encrypts to it (`nonce = SPI‖counter`). The receive-SPI allocator resets to 1 on every
(re)connect, but because each session is a fresh ECDHE handshake (no 0-RTT, no session
resumption — both are disabled and asserted fail-closed), every generation also derives a
**fresh master key**. A reset or regressed SPI is therefore always paired with a key that has
never been used, so its from-zero counter is a fresh nonce space and no AES-GCM nonce can
repeat. The data-plane install seam accepts the reset SPI for exactly this reason; the only
thing it refuses is re-installing the *currently-live* transmit SPI (which would reset a live
counter under an unchanged key).

This makes every recovery path seamless and symmetric:

- **Transient reconnect** (a network blip, both processes survive) — the next session derives
  fresh keys and both directions resume immediately.
- **One-sided restart** (either peer) — the restarted peer comes back with a fresh allocator
  and a fresh handshake; the survivor accepts the reset SPI under its fresh key and traffic
  resumes immediately. There is no high-water to carry forward and no peer to cycle.

