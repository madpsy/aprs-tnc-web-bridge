// proxyapp.go
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tarm/serial"
	"github.com/zishang520/engine.io/v2/types"
	"github.com/zishang520/socket.io/v2/socket"
)

// Constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// extractKISSFrames searches the provided data for complete frames.
// It returns a slice of complete frames (each beginning and ending with KISS_FLAG)
// and any leftover bytes.
func extractKISSFrames(data []byte) ([][]byte, []byte) {
	var frames [][]byte
	for {
		start := bytes.IndexByte(data, KISS_FLAG)
		if start == -1 {
			break
		}
		end := bytes.IndexByte(data[start+1:], KISS_FLAG)
		if end == -1 {
			break
		}
		end = start + 1 + end
		frame := data[start : end+1]
		frames = append(frames, frame)
		data = data[end+1:]
	}
	return frames, data
}

// unescapeData reverses the KISS escaping.
// (Not used below since we want to pass the raw frame, including escapes.)
func unescapeData(data []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(data); {
		b := data[i]
		if b == 0xDB && i+1 < len(data) {
			nxt := data[i+1]
			if nxt == 0xDC {
				out.WriteByte(KISS_FLAG)
				i += 2
				continue
			} else if nxt == 0xDD {
				out.WriteByte(0xDB)
				i += 2
				continue
			}
		}
		out.WriteByte(b)
		i++
	}
	return out.Bytes()
}

// Global variable for the underlying device connection.
var deviceConn io.ReadWriteCloser

// Socket.IO clients.
var (
	clients      []*socket.Socket
	clientsMutex sync.Mutex
)

// activeSocket is the most recently connected client.
// Only its events are forwarded to the device.
var (
	activeSocket      *socket.Socket
	activeSocketMutex sync.Mutex
)

// Raw TCP clients.
var (
	tcpClients      []net.Conn
	tcpClientsMutex sync.Mutex
)

// frameChan is a buffered channel used to decouple device reading from broadcasting.
var frameChan = make(chan []byte, 100)

func main() {
	// Command-line flags.
	connectionType := flag.String("connection", "", "Connection type: serial or tcp")
	serialPort := flag.String("serial-port", "", "Serial port device (required for serial connection)")
	baudRate := flag.Int("baud", 115200, "Baud rate (serial connection only, default 115200)")
	tcpHost := flag.String("host", "", "TCP host or IP (required for tcp connection)")
	tcpPort := flag.Int("port", 0, "TCP port (required for tcp connection)")
	listenIP := flag.String("listen-ip", "0.0.0.0", "IP address to bind the HTTP server (default 0.0.0.0)")
	listenPort := flag.Int("listen-port", 5000, "Port to bind the HTTP server (default 5000)")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	flag.Parse()

	debugMode := *debug

	// Open the underlying connection.
	switch *connectionType {
	case "serial":
		if *serialPort == "" {
			fmt.Fprintln(os.Stderr, "Error: -serial-port is required when connection type is serial")
			os.Exit(1)
		}
		config := &serial.Config{
			Name:        *serialPort,
			Baud:        *baudRate,
			ReadTimeout: time.Millisecond * 100,
		}
		s, err := serial.OpenPort(config)
		if err != nil {
			log.Fatalf("Failed to open serial port %s: %v", *serialPort, err)
		}
		deviceConn = s
		log.Printf("Opened serial connection on %s at %d baud", *serialPort, *baudRate)
	case "tcp":
		if *tcpHost == "" || *tcpPort == 0 {
			fmt.Fprintln(os.Stderr, "Error: -host and -port are required when connection type is tcp")
			os.Exit(1)
		}
		addr := fmt.Sprintf("%s:%d", *tcpHost, *tcpPort)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to connect to TCP %s: %v", addr, err)
		}
		deviceConn = conn
		log.Printf("Opened TCP connection to %s", addr)
	default:
		fmt.Fprintln(os.Stderr, "Error: -connection must be either serial or tcp")
		os.Exit(1)
	}

	// Create an Engine.IO server and a Socket.IO server on top of it.
	engineServer := types.CreateServer(nil)
	ioServer := socket.NewServer(engineServer, nil)

	// Handle Socket.IO client connections.
	ioServer.On("connection", func(args ...any) {
		client := args[0].(*socket.Socket)
		log.Printf("New Socket.IO client connected: %s", client.Id())

		// Set this client as the active client.
		activeSocketMutex.Lock()
		activeSocket = client
		activeSocketMutex.Unlock()

		// Add to the list of connected clients.
		clientsMutex.Lock()
		clients = append(clients, client)
		log.Printf("Now %d Socket.IO client(s) connected", len(clients))
		clientsMutex.Unlock()

		// Only forward events from the active client.
		client.On("raw_kiss_frame", func(datas ...any) {
			// Check if this client is the active one.
			activeSocketMutex.Lock()
			if activeSocket != client {
				activeSocketMutex.Unlock()
				return
			}
			activeSocketMutex.Unlock()

			if len(datas) == 0 {
				return
			}
			var msg []byte
			switch v := datas[0].(type) {
			case []byte:
				msg = v
			case string:
				msg = []byte(v)
			case interface{ Bytes() []byte }:
				msg = v.Bytes()
			default:
				log.Printf("Unexpected type for raw_kiss_frame: %T", v)
				return
			}
			if deviceConn != nil {
				_, err := deviceConn.Write(msg)
				if err != nil {
					log.Printf("Error writing to device: %v", err)
				} else if debugMode {
					log.Printf("DEBUG: Forwarded %d bytes from Socket.IO client to device", len(msg))
				}
			}
		})

		client.On("disconnect", func(datas ...any) {
			log.Printf("Socket.IO client disconnected: %s", client.Id())
			clientsMutex.Lock()
			for i, c := range clients {
				if c == client {
					clients = append(clients[:i], clients[i+1:]...)
					break
				}
			}
			clientsMutex.Unlock()
			// If the disconnecting client is the active one, reset activeSocket.
			activeSocketMutex.Lock()
			if activeSocket == client {
				activeSocket = nil
			}
			activeSocketMutex.Unlock()
		})
	})

	// Accept raw TCP connections on listenPort+1.
	rawTCPPort := *listenPort + 1
	tcpListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *listenIP, rawTCPPort))
	if err != nil {
		log.Fatalf("Failed to listen on raw TCP port %d: %v", rawTCPPort, err)
	}
	log.Printf("Listening for raw TCP connections on %s:%d", *listenIP, rawTCPPort)
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				log.Printf("Error accepting raw TCP connection: %v", err)
				continue
			}
			log.Printf("New raw TCP connection from %s", conn.RemoteAddr().String())
			tcpClientsMutex.Lock()
			tcpClients = append(tcpClients, conn)
			tcpClientsMutex.Unlock()
			go handleRawTCPClient(conn, debugMode)
		}
	}()

	// Continuously read from the device.
	go func() {
		buf := make([]byte, 1024)
		var readBuffer []byte
		for {
			n, err := deviceConn.Read(buf)
			if err != nil {
				if err == io.EOF {
					continue
				}
				log.Printf("Error reading from device: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if n == 0 {
				if debugMode {
					log.Println("DEBUG: Read timeout, no data")
				}
				continue
			}
			if debugMode {
				log.Printf("DEBUG: Read %d bytes from device: % X", n, buf[:n])
			}
			readBuffer = append(readBuffer, buf[:n]...)
			frames, remaining := extractKISSFrames(readBuffer)
			readBuffer = remaining
			for _, frame := range frames {
				if debugMode {
					log.Printf("Complete frame received: % X", frame)
				}
				// Push the complete frame into the channel.
				frameChan <- frame
			}
		}
	}()

	// Broadcast frames to Socket.IO and raw TCP clients.
	go func() {
		for frame := range frameChan {
			// Broadcast to Socket.IO clients.
			clientsMutex.Lock()
			numClients := len(clients)
			log.Printf("Broadcasting frame to %d Socket.IO client(s)", numClients)
			for _, c := range clients {
				go func(client *socket.Socket, frame []byte) {
					done := make(chan error, 1)
					go func() {
						done <- client.Emit("raw_kiss_frame", frame)
					}()
					select {
					case err := <-done:
						if err != nil {
							log.Printf("Error broadcasting to client %s: %v", client.Id(), err)
						} else if debugMode {
							log.Printf("DEBUG: Sent frame to Socket.IO client %s", client.Id())
						}
					case <-time.After(2 * time.Second):
						log.Printf("Timeout sending frame to client %s", client.Id())
					}
				}(c, frame)
			}
			clientsMutex.Unlock()

			// Broadcast to raw TCP clients.
			tcpClientsMutex.Lock()
			for _, tcpConn := range tcpClients {
				go func(conn net.Conn, frame []byte) {
					conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
					if _, err := conn.Write(frame); err != nil {
						log.Printf("Error writing to raw TCP client %s: %v", conn.RemoteAddr().String(), err)
						conn.Close()
					} else if debugMode {
						log.Printf("DEBUG: Sent frame to raw TCP client %s", conn.RemoteAddr().String())
					}
				}(tcpConn, frame)
			}
			tcpClientsMutex.Unlock()
		}
	}()

	// Set up HTTP server for Socket.IO and static files.
	mux := http.NewServeMux()
	mux.Handle("/socket.io/", engineServer)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "index.html")
			return
		}
		http.FileServer(http.Dir(".")).ServeHTTP(w, r)
	})

	bindAddr := fmt.Sprintf("%s:%d", *listenIP, *listenPort)
	httpServer := &http.Server{
		Addr:    bindAddr,
		Handler: mux,
	}
	go func() {
		log.Printf("Serving static files and Socket.IO on http://%s", bindAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe error: %v", err)
		}
	}()

	// Wait for termination signal.
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	<-exit
	log.Println("Shutting down server...")
	httpServer.Close()
	os.Exit(0)
}

// handleRawTCPClient manages a single raw TCP client's connection.
func handleRawTCPClient(conn net.Conn, debugMode bool) {
	defer func() {
		conn.Close()
		tcpClientsMutex.Lock()
		for i, c := range tcpClients {
			if c == conn {
				tcpClients = append(tcpClients[:i], tcpClients[i+1:]...)
				break
			}
		}
		tcpClientsMutex.Unlock()
		log.Printf("Raw TCP connection from %s closed", conn.RemoteAddr().String())
	}()

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from raw TCP client %s: %v", conn.RemoteAddr().String(), err)
			}
			break
		}
		if n > 0 {
			data := buf[:n]
			if debugMode {
				log.Printf("DEBUG: Received %d bytes from raw TCP client %s: % X", n, conn.RemoteAddr().String(), data)
			}
			log.Printf("Received %d bytes from raw TCP client %s; forwarding to device", n, conn.RemoteAddr().String())
			if deviceConn != nil {
				_, err := deviceConn.Write(data)
				if err != nil {
					log.Printf("Error writing to device from raw TCP client %s: %v", conn.RemoteAddr().String(), err)
				}
			}
		}
	}
}
