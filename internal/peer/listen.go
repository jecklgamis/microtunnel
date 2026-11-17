package peer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketBufferSize is the requested kernel send/receive buffer (the kernel may
// clamp it to net.core.{r,w}mem_max).
const socketBufferSize = 4 * 1024 * 1024

// Listen binds the tunnel's UDP socket on address:port (an empty address means
// all IPv4 interfaces) with SO_REUSEADDR and enlarged socket buffers.
func Listen(address string, port int) (*net.UDPConn, error) {
	if address == "" {
		address = "0.0.0.0"
	}
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	conn := pc.(*net.UDPConn)
	_ = conn.SetReadBuffer(socketBufferSize)
	_ = conn.SetWriteBuffer(socketBufferSize)
	return conn, nil
}
