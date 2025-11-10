//go:build linux

package forwarder_test

import (
	"bytes"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/proxyarp"
	"github.com/apoxy-dev/icx/veth"
)

const nsName = "icx-test-ns"

func TestForwarder(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Create the phy interface.
	phyDev, err := veth.Create("icx-phy", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, phyDev.Close())
	})

	// Create the virt interface.
	virtDev, err := veth.Create("icx-virt", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, virtDev.Close())
	})

	// Forwrd all traffic from phy to virt (we need to include ARPs etc).
	phyFilter, err := filter.All()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, phyFilter.Close())
	})

	pcapFile, err := os.Create("forwarder_test.pcap")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, pcapFile.Close())
	})

	pcapWriter := pcapgo.NewWriter(pcapFile)
	require.NoError(t, pcapWriter.WriteFileHeader(uint32(math.MaxUint16), layers.LinkTypeEthernet))

	phyMAC, err := tcpip.ParseMACAddress(phyDev.Link.Attrs().HardwareAddr.String())
	require.NoError(t, err)

	h := &pipe{
		proxyARP: proxyarp.NewProxyARP(phyMAC),
	}

	// Create the forwarder.
	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(phyDev.Peer.Attrs().Name),
		forwarder.WithPhyFilter(phyFilter),
		forwarder.WithVirtName(virtDev.Peer.Attrs().Name),
		forwarder.WithPcapWriter(pcapWriter),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, fwd.Close())
	})

	// Start the forwarder.
	go func() {
		require.NoError(t, fwd.Start(t.Context()))
	}()

	// Create a network namespace.
	execIP(t, "netns", "add", nsName)
	t.Cleanup(func() {
		execIP(t, "netns", "del", nsName)
		execIP(t, "link", "del", phyDev.Peer.Attrs().Name)
	})

	// Move the phy interface into the namespace and configure it there.
	phyDevName := phyDev.Link.Attrs().Name
	execIP(t, "link", "set", "dev", phyDevName, "netns", nsName)
	execIP(t, "-n", nsName, "addr", "add", "10.200.0.1/24", "dev", phyDevName)
	execIP(t, "-n", nsName, "link", "set", "dev", phyDevName, "up")
	execIP(t, "-n", nsName, "route", "add", "default", "dev", phyDevName)

	// Get the path to the current executable.
	binPath, err := os.Executable()
	require.NoError(t, err)

	// Start the HTTP server as its own process *inside* the netns.
	srvCmd := exec.Command("ip", "netns", "exec", nsName,
		binPath, "-test.run", "^TestHTTPServerHelper$", "-test.v",
	)
	// Tell the helper to actually run.
	srvCmd.Env = append(os.Environ(), "HTTP_HELPER=1")
	// Separate process group for reliable teardown.
	srvCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	srvCmd.Stdout, srvCmd.Stderr = os.Stdout, os.Stderr

	require.NoError(t, srvCmd.Start())
	t.Cleanup(func() {
		// Kill the entire process group.
		_ = syscall.Kill(-srvCmd.Process.Pid, syscall.SIGKILL)
		_, _ = srvCmd.Process.Wait()
	})

	// Add an address to the virt interface.
	nlAddr, err := netlink.ParseAddr("10.200.0.2/24")
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(virtDev.Link, nlAddr))

	time.Sleep(1 * time.Second) // wait a bit for everything to settle

	httpClient := &http.Client{
		Timeout: 20 * time.Second,
	}

	// Make an HTTP request to the server via the forwarder.
	resp, err := httpClient.Get("http://10.200.0.1:8080/")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// Helper to run `ip` commands.
func execIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("ip %v failed: %v\n%s", args, err, buf.String())
	}
}

// Helper process that runs an HTTP server inside a network namespace.
func TestHTTPServerHelper(t *testing.T) {
	if os.Getenv("HTTP_HELPER") != "1" {
		t.Skip("helper process")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	})

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	slog.Debug("Starting HTTP server", slog.String("addr", srv.Addr))

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		t.Fatalf("server error: %v", err)
	}
}

// Simple handler implementation that just copies data between phy and virt.
type pipe struct {
	proxyARP *proxyarp.ProxyARP
}

func (h *pipe) PhyToVirt(phyFrame, virtFrame []byte) int {
	return copy(virtFrame, phyFrame)
}

func (h *pipe) VirtToPhy(virtFrame, phyFrame []byte) (int, bool) {
	return copy(phyFrame, virtFrame), false
}

func (h *pipe) ToPhy(phyFrame []byte) int {
	return 0
}
