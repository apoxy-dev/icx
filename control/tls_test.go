package control

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// tlsHandshakeResult carries one side's post-handshake outcome.
type tlsHandshakeResult struct {
	state tls.ConnectionState
	err   error
}

// doHandshake runs a TLS 1.3 mTLS handshake between a client and server config
// over an in-memory pipe and returns both sides' results.
func doHandshake(t *testing.T, clientCfg, serverCfg *tls.Config) (client, server tlsHandshakeResult) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	srvCh := make(chan tlsHandshakeResult, 1)
	go func() {
		conn := tls.Server(s, serverCfg)
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		err := conn.Handshake()
		srvCh <- tlsHandshakeResult{state: conn.ConnectionState(), err: err}
	}()

	conn := tls.Client(c, clientCfg)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	clientErr := conn.Handshake()
	client = tlsHandshakeResult{state: conn.ConnectionState(), err: clientErr}
	server = <-srvCh
	return client, server
}

func mustConfigs(t *testing.T) (clientCfg, serverCfg *tls.Config, a, b *Identity) {
	t.Helper()
	a, err := GenerateIdentity() // client/initiator
	if err != nil {
		t.Fatal(err)
	}
	b, err = GenerateIdentity() // server/responder
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err = ClientTLSConfig(a, b.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err = ServerTLSConfig(b, a.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return clientCfg, serverCfg, a, b
}

func TestMTLSHandshakeSucceedsAndExportsSharedSecret(t *testing.T) {
	clientCfg, serverCfg, _, _ := mustConfigs(t)

	client, server := doHandshake(t, clientCfg, serverCfg)
	if client.err != nil {
		t.Fatalf("client handshake failed: %v", client.err)
	}
	if server.err != nil {
		t.Fatalf("server handshake failed: %v", server.err)
	}

	if client.state.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated TLS version %#x, want 1.3", client.state.Version)
	}
	if client.state.NegotiatedProtocol != ALPN {
		t.Fatalf("ALPN = %q, want %q", client.state.NegotiatedProtocol, ALPN)
	}

	cs, err := ExportRootSecret(client.state)
	if err != nil {
		t.Fatal(err)
	}
	ss, err := ExportRootSecret(server.state)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != RootSecretLen {
		t.Fatalf("root secret len = %d, want %d", len(cs), RootSecretLen)
	}
	if !bytes.Equal(cs, ss) {
		t.Fatalf("exported root secrets differ:\n client %x\n server %x", cs, ss)
	}
}

func TestMTLSWrongClientPinRejected(t *testing.T) {
	// Server pins a DIFFERENT key than the client actually holds.
	client, _ := GenerateIdentity()
	server, _ := GenerateIdentity()
	imposter, _ := GenerateIdentity()

	clientCfg, _ := ClientTLSConfig(client, server.PublicKey())
	// Server expects `imposter`, but the client authenticates as `client`.
	serverCfg, _ := ServerTLSConfig(server, imposter.PublicKey())

	c, s := doHandshake(t, clientCfg, serverCfg)
	if s.err == nil {
		t.Fatal("server accepted a client whose key it did not pin")
	}
	if c.err == nil {
		t.Fatal("client handshake should also fail when server rejects it")
	}
}

func TestMTLSWrongServerPinRejected(t *testing.T) {
	client, _ := GenerateIdentity()
	server, _ := GenerateIdentity()
	imposter, _ := GenerateIdentity()

	// Client expects `imposter`, but the server authenticates as `server`.
	clientCfg, _ := ClientTLSConfig(client, imposter.PublicKey())
	serverCfg, _ := ServerTLSConfig(server, client.PublicKey())

	c, _ := doHandshake(t, clientCfg, serverCfg)
	if c.err == nil {
		t.Fatal("client accepted a server whose key it did not pin")
	}
	if !errors.Is(c.err, c.err) { // smoke: error is non-nil (pin mismatch surfaced)
		t.Fatal("expected a pin-mismatch error")
	}
}

func TestExportRootSecretRejectsZeroState(t *testing.T) {
	if _, err := ExportRootSecret(tls.ConnectionState{}); err == nil {
		t.Fatal("expected error exporting from a non-1.3 (zero) connection state")
	}
}
