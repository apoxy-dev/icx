# InterCloud eXpress (ICX) - CLI

## Usage

ICX uses a pair of **ephemeral, per-session** symmetric keys for encrypting traffic.
**Do not reuse keys** across sessions (to avoid nonce reuse risks).

In production, use a secure key exchange mechanism (e.g., IKEv2) to
generate and distribute keys.

### 1) Generate two one-time keys

```bash
# Key used for A → B traffic
K_AB=$(openssl rand -hex 16)
# Key used for B → A traffic
K_BA=$(openssl rand -hex 16)
```

### 2) Create an INI file on each host

Each host reads keys from an INI file at --key-file. The required format is:

```ini
[keys]
rx=<32 hex chars>   # the key this host expects to RECEIVE with
tx=<32 hex chars>   # the key this host will TRANSMIT with
# Optional expiry (defaults to 24h if omitted):
# - as a Go duration (e.g. 24h, 90m)
# - or an RFC3339 timestamp (e.g. 2025-10-16T12:34:56Z)
expires=24h
```

For Host A:

```ini
[keys]
rx=${K_BA}
tx=${K_AB}
expires=24h
```

For Host B:

```ini
[keys]
rx=${K_AB}
tx=${K_BA}
expires=24h
```

### 3) Start ICX on both hosts

```bash
icx -i <iface> --key-file=/path/to/icx.ini <peer_ip>:<port>
```

#### Examples:

```bash
# Host A
icx -i eth0 --key-file=/etc/icx/keys.ini 203.0.113.2:6081

# Host B
icx -i eth0 --key-file=/etc/icx/keys.ini 198.51.100.7:6081
```

This creates an icx0 interface on both hosts, which you can use to securely
send and receive traffic over the ICX tunnel.

### 4) Key rotation (SIGHUP)

To rotate keys, update the same INI file with new rx/tx values, then send
SIGHUP to the running process:

```bash
pkill -HUP icx
# or: kill -HUP <pid>
```

ICX will reload the INI, bump the epoch, and apply the new keys. If the
reloaded keys are identical to the current ones, the reload is refused (epoch unchanged).