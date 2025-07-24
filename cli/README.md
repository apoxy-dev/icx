# InterCloud eXpress (ICX) - CLI

## Usage

You will need to generate a pair of ephemeral keys for encrypting traffic. 
**These keys MUST not be reused** (due to the risk of nonce reuse) and should 
be generated for each session.

To generate a key pair, you can use the following command:

```bash
openssl rand -hex 16
```

On the first host, run the following command to create a new ICX session:

```bash
icx -i <iface> --rx-key=<rx_key> --tx-key=<tx_key> <peer_address>:<port>
```

On the second host, run the same command but with the keys swapped:

```bash
icx -i <iface> --rx-key=<tx_key> --tx-key=<rx_key> <peer_address>:<port>
```

This will create a `icx0` interface on both hosts, which can be used to securely 
send and receive traffic over the ICX tunnel.

In a production environment, you would use a secure mechanism such as IKEv2 to
generate and exchange keys.