package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tarm/serial"
)

// -----------------------------------------------------------------------------
// KISS / AX.25 Constants and Helper Functions
// -----------------------------------------------------------------------------

const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// escapeData escapes any KISS special bytes so that framing is preserved.
func escapeData(data []byte) []byte {
	var out bytes.Buffer
	for _, b := range data {
		if b == KISS_FLAG {
			out.Write([]byte{0xDB, 0xDC})
		} else if b == 0xDB {
			out.Write([]byte{0xDB, 0xDD})
		} else {
			out.WriteByte(b)
		}
	}
	return out.Bytes()
}

// unescapeData reverses KISS escaping.
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

// buildKISSFrame wraps raw packet bytes in a KISS frame.
func buildKISSFrame(packet []byte) []byte {
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	return frame
}

// extractKISSFrames extracts complete KISS frames from data.
// Returns a slice of complete frames and any remaining bytes.
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

// decodeAX25Address converts a 7‑byte AX.25 address field to a callsign.
func decodeAX25Address(addr []byte) string {
	if len(addr) < 7 {
		return ""
	}
	cs := make([]byte, 6)
	for i := 0; i < 6; i++ {
		cs[i] = addr[i] >> 1
	}
	return strings.TrimSpace(string(cs))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// canonicalKey returns a key that is independent of the packet direction by
// alphabetically ordering the two callsigns and appending the fileID.
func canonicalKey(sender, receiver, fileID string) string {
	s := strings.ToUpper(strings.TrimSpace(sender))
	r := strings.ToUpper(strings.TrimSpace(receiver))
	fid := strings.TrimSpace(fileID)
	if s < r {
		return fmt.Sprintf("%s|%s|%s", s, r, fid)
	}
	return fmt.Sprintf("%s|%s|%s", r, s, fid)
}

// -----------------------------------------------------------------------------
// Packet Parsing: Structures and Functions
// -----------------------------------------------------------------------------

// Packet represents a parsed packet (data or ACK).
type Packet struct {
	Type     string // "data" or "ack"
	Sender   string
	Receiver string
	FileID   string
	Seq      int
	BurstTo  int
	Total    int    // For header packets (seq==1), total number of packets.
	Payload  []byte // The inner payload.
	RawInfo  string // The decoded info field.
	Ack      string // For ACK packets.
}

// parsePacket attempts to parse a packet from raw unescaped bytes.
// It returns nil if the packet is too short or malformed.
func parsePacket(packet []byte) *Packet {
	// Expect at least 16 bytes for the AX.25 header.
	if len(packet) < 16 {
		return nil
	}
	infoAndPayload := packet[16:]
	if len(infoAndPayload) == 0 {
		return nil
	}
	prefix := string(infoAndPayload[:min(50, len(infoAndPayload))])
	// If the info field contains "ACK:" then parse as an ACK packet.
	if strings.Contains(prefix, "ACK:") {
		fields := strings.Split(string(infoAndPayload), ":")
		if len(fields) >= 4 {
			srParts := strings.Split(fields[0], ">")
			if len(srParts) != 2 {
				return &Packet{
					Type:    "ack",
					Ack:     strings.TrimSpace(fields[len(fields)-1]),
					RawInfo: string(infoAndPayload),
				}
			}
			sender := strings.TrimSpace(srParts[0])
			receiver := strings.TrimSpace(srParts[1])
			fileID := strings.TrimSpace(fields[1])
			ackVal := strings.TrimSpace(fields[3])
			return &Packet{
				Type:     "ack",
				Sender:   sender,
				Receiver: receiver,
				FileID:   fileID,
				Ack:      ackVal,
				RawInfo:  string(infoAndPayload),
			}
		}
		// Fallback if structure is not as expected.
		ackVal := ""
		parts := strings.Split(string(infoAndPayload), "ACK:")
		if len(parts) >= 2 {
			ackVal = strings.Trim(strings.Trim(parts[1], ":"), " ")
		}
		return &Packet{
			Type:    "ack",
			Ack:     ackVal,
			RawInfo: string(infoAndPayload),
		}
	}

	// Process as a data packet.
	var infoField, payload []byte
	// For a header packet, the info field ends after "0001" plus a colon.
	if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
		idx := bytes.IndexByte(infoAndPayload[27:], ':')
		if idx == -1 {
			return nil
		}
		endIdx := 27 + idx + 1
		if len(infoAndPayload) < endIdx {
			return nil
		}
		infoField = infoAndPayload[:endIdx]
		payload = infoAndPayload[endIdx:]
	} else {
		// For data packets we expect at least 32 bytes for the info field.
		if len(infoAndPayload) < 32 {
			return nil
		}
		infoField = infoAndPayload[:32]
		payload = infoAndPayload[32:]
	}
	infoStr := string(infoField)
	parts := strings.Split(infoStr, ":")
	if len(parts) < 4 {
		return nil
	}
	srParts := strings.Split(parts[0], ">")
	if len(srParts) != 2 {
		return nil
	}
	sender := strings.TrimSpace(srParts[0])
	receiver := strings.TrimSpace(srParts[1])
	fileID := strings.TrimSpace(parts[1])
	seqBurst := strings.TrimSpace(parts[2])
	var seq int
	var burstTo int
	total := 0
	if strings.Contains(seqBurst, "/") {
		// Header packet.
		seq = 1
		if len(seqBurst) < 8 {
			return nil
		}
		burstPart := seqBurst[4:8]
		b, err := strconv.ParseInt(burstPart, 16, 32)
		if err != nil {
			return nil
		}
		burstTo = int(b)
		spl := strings.Split(seqBurst, "/")
		if len(spl) < 2 {
			return nil
		}
		t, err := strconv.ParseInt(spl[1], 16, 32)
		if err != nil {
			return nil
		}
		total = int(t)
	} else {
		if len(seqBurst) != 8 {
			return nil
		}
		seqInt, err1 := strconv.ParseInt(seqBurst[:4], 16, 32)
		burstInt, err2 := strconv.ParseInt(seqBurst[4:], 16, 32)
		if err1 != nil || err2 != nil {
			return nil
		}
		seq = int(seqInt)
		burstTo = int(burstInt)
	}
	return &Packet{
		Type:     "data",
		Sender:   sender,
		Receiver: receiver,
		FileID:   fileID,
		Seq:      seq,
		BurstTo:  burstTo,
		Total:    total,
		Payload:  payload,
		RawInfo:  infoStr,
	}
}

// -----------------------------------------------------------------------------
// KISSConnection Interface and Implementations (TCP and Serial)
// -----------------------------------------------------------------------------

// KISSConnection defines methods for sending and receiving KISS frames.
type KISSConnection interface {
	SendFrame(frame []byte) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn     net.Conn
	listener net.Listener // for server mode
	isServer bool
	lock     sync.Mutex
}

func newTCPKISSConnection(host string, port int, isServer bool) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	tnc := &TCPKISSConnection{isServer: isServer}
	if isServer {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		tnc.listener = ln
		log.Printf("[TCP Server] Listening on %s", addr)
		conn, err := ln.Accept()
		if err != nil {
			return nil, err
		}
		tnc.conn = conn
		log.Printf("[TCP Server] Accepted connection from %s", conn.RemoteAddr().String())
	} else {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tnc.conn = conn
		log.Printf("[TCP Client] Connected to %s", addr)
	}
	return tnc, nil
}

func (t *TCPKISSConnection) SendFrame(frame []byte) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	_, err := t.conn.Write(frame)
	return err
}

func (t *TCPKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := t.conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			return []byte{}, nil
		}
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			return []byte{}, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (t *TCPKISSConnection) Close() error {
	if t.conn != nil {
		t.conn.Close()
	}
	if t.isServer && t.listener != nil {
		t.listener.Close()
	}
	return nil
}

// SerialKISSConnection implements KISSConnection over a serial port.
type SerialKISSConnection struct {
	ser  *serial.Port
	lock sync.Mutex
}

func newSerialKISSConnection(portName string, baud int) (*SerialKISSConnection, error) {
	c := &serial.Config{Name: portName, Baud: baud, ReadTimeout: time.Millisecond * 100}
	ser, err := serial.OpenPort(c)
	if err != nil {
		return nil, err
	}
	log.Printf("[Serial] Opened serial port %s at %d baud", portName, baud)
	return &SerialKISSConnection{ser: ser}, nil
}

func (s *SerialKISSConnection) SendFrame(frame []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, err := s.ser.Write(frame)
	return err
}

func (s *SerialKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := s.ser.Read(buf)
	if err != nil {
		if err == io.EOF {
			return []byte{}, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// -----------------------------------------------------------------------------
// FrameReader: Reads raw data and extracts KISS frames
// -----------------------------------------------------------------------------

type FrameReader struct {
	conn    KISSConnection
	outChan chan []byte
	running bool
	buffer  []byte
}

func NewFrameReader(conn KISSConnection, outChan chan []byte) *FrameReader {
	return &FrameReader{
		conn:    conn,
		outChan: outChan,
		running: true,
		buffer:  []byte{},
	}
}

func (fr *FrameReader) Run() {
	for fr.running {
		data, err := fr.conn.RecvData(100 * time.Millisecond)
		if err != nil {
			log.Printf("Receive error: %v", err)
			continue
		}
		if len(data) > 0 {
			fr.buffer = append(fr.buffer, data...)
			frames, remaining := extractKISSFrames(fr.buffer)
			fr.buffer = remaining
			for _, f := range frames {
				if len(f) >= 2 && f[0] == KISS_FLAG && f[len(f)-1] == KISS_FLAG {
					if len(f) < 4 {
						continue
					}
					inner := f[2 : len(f)-1]
					unesc := unescapeData(inner)
					fr.outChan <- unesc
				}
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (fr *FrameReader) Stop() {
	fr.running = false
}

// -----------------------------------------------------------------------------
// Transfer Tracking Structures
// -----------------------------------------------------------------------------

// Transfer holds header information and progress for a file transfer.
type Transfer struct {
	Sender         string
	Receiver       string
	FileID         string
	Filename       string
	TotalPackets   int       // Total packets (including header)
	LastSeq        int       // Highest sequence number seen
	StartTime      time.Time
	TimeoutSeconds float64   // Timeout value (from header)
	FinAckTime     time.Time // Time at which FIN-ACK was received; zero if not received
}

var (
	// transfers maps a canonical key to its Transfer record.
	transfers     = make(map[string]*Transfer)
	transfersLock sync.Mutex

	// allowedCalls holds the allowed callsigns (uppercase).
	allowedCalls = make(map[string]bool)
)

// -----------------------------------------------------------------------------
// Global Command‑Line Options
// -----------------------------------------------------------------------------

// TNC1 options
var (
	tnc1ConnType   = flag.String("tnc1-connection-type", "tcp", "Connection type for TNC1: tcp or serial")
	tnc1Host       = flag.String("tnc1-host", "127.0.0.1", "TCP host for TNC1")
	tnc1Port       = flag.Int("tnc1-port", 9001, "TCP port for TNC1")
	tnc1SerialPort = flag.String("tnc1-serial-port", "", "Serial port for TNC1 (e.g., COM3 or /dev/ttyUSB0)")
	tnc1Baud       = flag.Int("tnc1-baud", 115200, "Baud rate for TNC1 serial connection")
)

// TNC2 options
var (
	tnc2ConnType   = flag.String("tnc2-connection-type", "tcp", "Connection type for TNC2: tcp or serial")
	tnc2Host       = flag.String("tnc2-host", "127.0.0.1", "TCP host for TNC2")
	tnc2Port       = flag.Int("tnc2-port", 9002, "TCP port for TNC2")
	tnc2SerialPort = flag.String("tnc2-serial-port", "", "Serial port for TNC2")
	tnc2Baud       = flag.Int("tnc2-baud", 115200, "Baud rate for TNC2 serial connection")
)

// Allowed callsigns option (comma‑delimited).
var callsigns = flag.String("callsigns", "", "Comma delimited list of valid sender/receiver callsigns")
var debug = flag.Bool("debug", false, "Enable debug logging")

// -----------------------------------------------------------------------------
// Packet Processing and Forwarding Logic
// -----------------------------------------------------------------------------

// processAndForwardPacket examines a raw packet (already unescaped) from one TNC,
// validates header packets, tracks transfer progress, and forwards the packet
// to the destination connection if allowed. The "direction" string (e.g., "TNC1->TNC2")
// is used for logging. Every log message includes the fileID and sender/receiver.
func processAndForwardPacket(pkt []byte, dstConn KISSConnection, direction string) {
	packet := parsePacket(pkt)
	if packet == nil {
           if *debug {
		log.Printf("[%s] [FileID: <unknown>] [From: <unknown> To: <unknown>] Could not parse packet.", direction)
            }
		return
	}

	// Use canonical key to be independent of direction.
	key := canonicalKey(packet.Sender, packet.Receiver, packet.FileID)

	// Before processing, check if a transfer exists and if a FIN-ACK was received.
	transfersLock.Lock()
	transfer, exists := transfers[key]
	if exists && !transfer.FinAckTime.IsZero() {
		// If the FIN-ACK was received, forward packets until timeout expires.
		if time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds*float64(time.Second)) {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping packet.", direction, packet.FileID, packet.Sender, packet.Receiver)
			delete(transfers, key)
			transfersLock.Unlock()
			return
		}
	}
	transfersLock.Unlock()

	// For non-ACK packets, ensure both sender and receiver are allowed.
	if packet.Type != "ack" {
		srcAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Sender))]
		dstAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Receiver))]
		if !srcAllowed || !dstAllowed {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping packet: callsign not allowed", direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
	}

	// Process ACK packets.
	if packet.Type == "ack" {
		transfersLock.Lock()
		transfer, exists := transfers[key]
		if exists {
			// If this ACK contains FIN-ACK, mark the transfer with the current time
			// (if not already set) but do not remove it immediately.
			if strings.Contains(packet.Ack, "FIN-ACK") {
				if transfer.FinAckTime.IsZero() {
					transfer.FinAckTime = time.Now()
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Received FIN-ACK for file %s. Transfer complete. Continuing for timeout period (%.2f sec).", direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename, transfer.TimeoutSeconds)
				} else {
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Re-received FIN-ACK for file %s.", direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename)
				}
			} else {
				// For normal ACK packets, if the transfer is in FIN-ACK state, check timeout.
				if !transfer.FinAckTime.IsZero() && time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds*float64(time.Second)) {
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping ACK packet.", direction, packet.FileID, packet.Sender, packet.Receiver)
					delete(transfers, key)
					transfersLock.Unlock()
					return
				}
			}
			transfersLock.Unlock()
		} else {
			transfersLock.Unlock()
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping ACK packet: header not seen yet", direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding ACK packet: %s", direction, packet.FileID, packet.Sender, packet.Receiver, packet.Ack)
		frame := buildKISSFrame(pkt)
		if err := dstConn.SendFrame(frame); err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding ACK packet: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
		}
		return
	}

	// Process header packets (seq==1).
	if packet.Seq == 1 {
		headerStr := string(packet.Payload)
		fields := strings.Split(headerStr, "|")
		if len(fields) < 9 {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping header packet: invalid header (not enough fields)", direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
		timeoutSec, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid timeout seconds in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		timeoutRetries, err := strconv.Atoi(fields[1])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid timeout retries in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		filename := fields[2]
		origSize, err := strconv.Atoi(fields[3])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid original size in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compSize, err := strconv.Atoi(fields[4])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid compressed size in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		md5Hash := fields[5]
		compressFlag := fields[7]
		totalPackets, err := strconv.Atoi(fields[8])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid total packets in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compress := compressFlag == "1"

		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Received HEADER packet:", direction, packet.FileID, packet.Sender, packet.Receiver)
		log.Printf("           Filename       : %s", filename)
		log.Printf("           Timeout Secs   : %f", timeoutSec)
		log.Printf("           Timeout Retries: %d", timeoutRetries)
		log.Printf("           Orig Size      : %d", origSize)
		log.Printf("           Comp Size      : %d", compSize)
		log.Printf("           MD5            : %s", md5Hash)
		log.Printf("           Compression    : %v", compress)
		log.Printf("           Total Packets  : %d", totalPackets)

		transfersLock.Lock()
		transfers[key] = &Transfer{
			Sender:         packet.Sender,
			Receiver:       packet.Receiver,
			FileID:         packet.FileID,
			Filename:       filename,
			TotalPackets:   totalPackets,
			LastSeq:        1,
			StartTime:      time.Now(),
			TimeoutSeconds: timeoutSec,
			FinAckTime:     time.Time{}, // zero value
		}
		transfersLock.Unlock()

		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding HEADER packet for file %s", direction, packet.FileID, packet.Sender, packet.Receiver, filename)
		frame := buildKISSFrame(pkt)
		if err := dstConn.SendFrame(frame); err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding HEADER packet: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
		}
		return
	}

	// Process data packets (seq > 1).
	transfersLock.Lock()
	transfer, exists = transfers[key]
	transfersLock.Unlock()
	if !exists {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping data packet seq %d: header not seen", direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
		return
	}

	// If FIN-ACK was already received, ensure we are still within the timeout period.
	if !transfer.FinAckTime.IsZero() {
		if time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds*float64(time.Second)) {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping data packet seq %d.", direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
			transfersLock.Lock()
			delete(transfers, key)
			transfersLock.Unlock()
			return
		}
	}

	if packet.Seq > transfer.LastSeq {
		transfer.LastSeq = packet.Seq
		progress := float64(packet.Seq-1) / float64(transfer.TotalPackets-1) * 100.0
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer progress for file %s: packet %d of %d (%.1f%%)", direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename, packet.Seq, transfer.TotalPackets, progress)
		if packet.Seq == transfer.TotalPackets {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] All data packets received for file %s; waiting for FIN-ACK.", direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename)
		}
	}

	log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding data packet seq %d", direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
	frame := buildKISSFrame(pkt)
	if err := dstConn.SendFrame(frame); err != nil {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding data packet: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
	}
}

// -----------------------------------------------------------------------------
// Main: Connection Setup and Forwarding Loop
// -----------------------------------------------------------------------------

func main() {
	flag.Parse()

	if *callsigns == "" {
		log.Fatalf("The -callsigns option is required.")
	}

	// Build allowed callsigns set (uppercase).
	for _, s := range strings.Split(*callsigns, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" {
			allowedCalls[s] = true
		}
	}
	log.Printf("Allowed callsigns: %v", allowedCalls)

	// Create TNC1 connection.
	var tnc1Conn KISSConnection
	var err error
	switch strings.ToLower(*tnc1ConnType) {
	case "tcp":
		tnc1Conn, err = newTCPKISSConnection(*tnc1Host, *tnc1Port, false)
		if err != nil {
			log.Fatalf("Error creating TNC1 TCP connection: %v", err)
		}
	case "serial":
		if *tnc1SerialPort == "" {
			log.Fatalf("TNC1 serial port must be specified for serial connection.")
		}
		tnc1Conn, err = newSerialKISSConnection(*tnc1SerialPort, *tnc1Baud)
		if err != nil {
			log.Fatalf("Error creating TNC1 serial connection: %v", err)
		}
	default:
		log.Fatalf("Invalid TNC1 connection type: %s", *tnc1ConnType)
	}

	// Create TNC2 connection.
	var tnc2Conn KISSConnection
	switch strings.ToLower(*tnc2ConnType) {
	case "tcp":
		tnc2Conn, err = newTCPKISSConnection(*tnc2Host, *tnc2Port, false)
		if err != nil {
			log.Fatalf("Error creating TNC2 TCP connection: %v", err)
		}
	case "serial":
		if *tnc2SerialPort == "" {
			log.Fatalf("TNC2 serial port must be specified for serial connection.")
		}
		tnc2Conn, err = newSerialKISSConnection(*tnc2SerialPort, *tnc2Baud)
		if err != nil {
			log.Fatalf("Error creating TNC2 serial connection: %v", err)
		}
	default:
		log.Fatalf("Invalid TNC2 connection type: %s", *tnc2ConnType)
	}

	// Create channels to receive unescaped packets from each TNC.
	tnc1Chan := make(chan []byte, 100)
	tnc2Chan := make(chan []byte, 100)

	// Start FrameReaders on both connections.
	fr1 := NewFrameReader(tnc1Conn, tnc1Chan)
	fr2 := NewFrameReader(tnc2Conn, tnc2Chan)
	go fr1.Run()
	go fr2.Run()

	// Forward packets from TNC1 to TNC2.
	go func() {
		for pkt := range tnc1Chan {
			processAndForwardPacket(pkt, tnc2Conn, "TNC1->TNC2")
		}
	}()

	// Forward packets from TNC2 to TNC1.
	go func() {
		for pkt := range tnc2Chan {
			processAndForwardPacket(pkt, tnc1Conn, "TNC2->TNC1")
		}
	}()

	// Block forever.
	select {}
}
