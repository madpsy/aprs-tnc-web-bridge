// proxy.go
package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
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

// padCallsign pads and uppercases a callsign to 9 characters.
func padCallsign(cs string) string {
	return fmt.Sprintf("%-9s", strings.ToUpper(cs))
}

// generateFileID returns a two‑character random file ID.
func generateFileID() string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return string([]byte{chars[rand.Intn(len(chars))], chars[rand.Intn(len(chars))]})
}

// encodeAX25Address encodes an AX.25 address field for the given callsign.
func encodeAX25Address(callsign string, isLast bool) []byte {
	parts := strings.Split(strings.ToUpper(callsign), "-")
	call := parts[0]
	if len(call) < 6 {
		call = call + strings.Repeat(" ", 6-len(call))
	} else if len(call) > 6 {
		call = call[:6]
	}
	addr := make([]byte, 7)
	for i := 0; i < 6; i++ {
		addr[i] = call[i] << 1
	}
	addr[6] = 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// buildAX25Header builds an AX.25 header using the sender and receiver callsigns.
func buildAX25Header(sender, receiver string) []byte {
	dest := encodeAX25Address(receiver, false)
	src := encodeAX25Address(sender, true)
	header := append(dest, src...)
	header = append(header, 0x03, 0xF0)
	return header
}

// canonicalKey returns a key independent of direction by alphabetically ordering the callsigns and appending the fileID.
func canonicalKey(sender, receiver, fileID string) string {
	s := strings.ToUpper(strings.TrimSpace(sender))
	r := strings.ToUpper(strings.TrimSpace(receiver))
	fid := strings.TrimSpace(fileID)
	if s < r {
		return fmt.Sprintf("%s|%s|%s", s, r, fid)
	}
	return fmt.Sprintf("%s|%s|%s", r, s, fid)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// -----------------------------------------------------------------------------
// Packet Parsing: Structures and Functions
// -----------------------------------------------------------------------------

// Packet represents a parsed packet (data or ACK).
// The EncodingMethod field holds the extra one-byte value (0=binary, 1=base64).
type Packet struct {
	Type           string // "data" or "ack"
	Sender         string
	Receiver       string
	FileID         string
	Seq            int
	BurstTo        int
	Total          int    // For header packets (seq==1), total number of packets.
	Payload        []byte // The inner payload.
	RawInfo        string // The decoded info field.
	Ack            string // For ACK packets.
	EncodingMethod byte   // new: 0=binary, 1=base64
}

// parsePacket attempts to parse a packet from raw unescaped bytes.
func parsePacket(packet []byte) *Packet {
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

	// ----- Header Packet Detection -----
	var infoField, payload []byte
	// Check if this is a header packet by verifying that bytes 23-27 equal "0001"
	if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
		idx := bytes.IndexByte(infoAndPayload[27:], ':')
		if idx == -1 {
			return nil
		}
		endIdx := 27 + idx + 1
		infoField = infoAndPayload[:endIdx]
		payload = infoAndPayload[endIdx:]
	} else {
		// Otherwise assume fixed-length splitting.
		if len(infoAndPayload) < 32 {
			return nil
		}
		infoField = infoAndPayload[:32]
		payload = infoAndPayload[32:]
	}
	// -----------------------------------------

	// For non-header packets, do NOT remove an extra byte.
	var encodingMethod byte = 0

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
		// Header packet: sequence is always 1.
		seq = 1
		if len(seqBurst) >= 8 {
			burstPart := seqBurst[4:8]
			b, err := strconv.ParseInt(burstPart, 16, 32)
			if err != nil {
				return nil
			}
			burstTo = int(b)
		}
		// total remains 0 and will be set from the header payload
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
	// For header packets (seq==1), parse the header payload to extract the encoding method.
	if seq == 1 {
		headerFields := strings.Split(string(payload), "|")
		if len(headerFields) >= 10 {
			if val, err := strconv.Atoi(headerFields[7]); err == nil {
				encodingMethod = byte(val)
			}
			if tot, err := strconv.Atoi(headerFields[9]); err == nil {
				total = tot
			}
		}
	}
	return &Packet{
		Type:           "data",
		Sender:         sender,
		Receiver:       receiver,
		FileID:         fileID,
		Seq:            seq,
		BurstTo:        burstTo,
		Total:          total,
		Payload:        payload,
		RawInfo:        infoStr,
		EncodingMethod: encodingMethod,
	}
}

// -----------------------------------------------------------------------------
// KISSConnection Interface and Implementations (TCP and Serial)
// -----------------------------------------------------------------------------

type KISSConnection interface {
	SendFrame(frame []byte) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

type TCPKISSConnection struct {
	conn     net.Conn
	listener net.Listener // used in server mode
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
// TimeoutSeconds is now an int and EncodingMethod is new.
type Transfer struct {
	Sender         string
	Receiver       string
	FileID         string
	Filename       string
	TotalPackets   int             // Total packets (including header)
	LastSeq        int             // Highest sequence number seen
	StartTime      time.Time
	TimeoutSeconds int             // Timeout value (from header, now an integer)
	FinAckTime     time.Time       // Time at which FIN-ACK was received; zero if not received
	PacketData     map[int][]byte  // Map of sequence number to payload (data packets only)
	EncodingMethod byte            // new: 0 = binary, 1 = base64
	Compress       bool            // Whether file was compressed
	FileSaved      bool            // File saved flag
}

var (
	transfers     = make(map[string]*Transfer)
	transfersLock sync.Mutex
	allowedCalls  = make(map[string]bool)
)

// -----------------------------------------------------------------------------
// Global Command-Line Options
// -----------------------------------------------------------------------------

var (
	tnc1ConnType   = flag.String("tnc1-connection-type", "tcp", "Connection type for TNC1: tcp or serial")
	tnc1Host       = flag.String("tnc1-host", "127.0.0.1", "TCP host for TNC1")
	tnc1Port       = flag.Int("tnc1-port", 9001, "TCP port for TNC1")
	tnc1SerialPort = flag.String("tnc1-serial-port", "", "Serial port for TNC1 (e.g., COM3 or /dev/ttyUSB0)")
	tnc1Baud       = flag.Int("tnc1-baud", 115200, "Baud rate for TNC1 serial connection")
	tnc2ConnType   = flag.String("tnc2-connection-type", "tcp", "Connection type for TNC2: tcp or serial")
	tnc2Host       = flag.String("tnc2-host", "127.0.0.1", "TCP host for TNC2")
	tnc2Port       = flag.Int("tnc2-port", 9002, "TCP port for TNC2")
	tnc2SerialPort = flag.String("tnc2-serial-port", "", "Serial port for TNC2")
	tnc2Baud       = flag.Int("tnc2-baud", 115200, "Baud rate for TNC2 serial connection")
)

var callsigns = flag.String("callsigns", "", "Comma delimited list of valid sender/receiver callsigns")
var debug = flag.Bool("debug", false, "Enable debug logging")
var saveFiles = flag.Bool("save-files", false, "Save all files seen by the proxy (prepending <SENDER>_<RECEIVER>_ to filename)")

// -----------------------------------------------------------------------------
// Packet Processing and Forwarding Logic
// -----------------------------------------------------------------------------

func processAndForwardPacket(pkt []byte, dstConn KISSConnection, direction string) {
	packet := parsePacket(pkt)
	if packet == nil {
		if *debug {
			log.Printf("[%s] [FileID: <unknown>] [From: <unknown> To: <unknown>] Could not parse packet.", direction)
		}
		return
	}

	key := canonicalKey(packet.Sender, packet.Receiver, packet.FileID)

	transfersLock.Lock()
	transfer, exists := transfers[key]
	if exists && !transfer.FinAckTime.IsZero() {
		if time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds)*time.Second {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping packet.", direction, packet.FileID, packet.Sender, packet.Receiver)
			delete(transfers, key)
			transfersLock.Unlock()
			return
		}
	}
	transfersLock.Unlock()

	if packet.Type != "ack" {
		srcAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Sender))]
		dstAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Receiver))]
		if !srcAllowed || !dstAllowed {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping packet: callsign not allowed", direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
	}

	if packet.Type == "ack" {
		transfersLock.Lock()
		transfer, exists := transfers[key]
		if exists {
			if strings.Contains(packet.Ack, "FIN-ACK") {
				if transfer.FinAckTime.IsZero() {
					transfer.FinAckTime = time.Now()
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Received FIN-ACK for file %s. Transfer complete. Continuing for timeout period (%d sec).", direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename, transfer.TimeoutSeconds)
				} else {
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Re-received FIN-ACK for file %s.", direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename)
				}
			} else {
				if !transfer.FinAckTime.IsZero() && time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds)*time.Second {
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
		// Use the header payload as sent by the sender.
		headerStr := string(packet.Payload)
		fields := strings.Split(headerStr, "|")
		if len(fields) < 10 {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping header packet: invalid header (not enough fields)", direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
		// Parse header fields.
		timeoutSec, err := strconv.Atoi(fields[0])
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
		encodingMethodVal, err := strconv.Atoi(fields[7])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid encoding method in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compFlag := fields[8]
		totalPackets, err := strconv.Atoi(fields[9])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid total packets in header: %v", direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compress := compFlag == "1"

		var encStr string = "binary"
		if encodingMethodVal == 1 {
			encStr = "base64"
		}

		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Received HEADER packet:",
			direction, packet.FileID, packet.Sender, packet.Receiver)
		log.Printf("           Filename       : %s", filename)
		log.Printf("           Timeout Secs   : %d", timeoutSec)
		log.Printf("           Timeout Retries: %d", timeoutRetries)
		log.Printf("           Orig Size      : %d", origSize)
		log.Printf("           Comp Size      : %d", compSize)
		log.Printf("           MD5            : %s", md5Hash)
		log.Printf("           Compression    : %v", compress)
		log.Printf("           Total Packets  : %d", totalPackets)
		log.Printf("           Encoding Method: %s", encStr)

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
			FinAckTime:     time.Time{},
			PacketData:     make(map[int][]byte),
			EncodingMethod: byte(encodingMethodVal),
			Compress:       compress,
			FileSaved:      false,
		}
		transfersLock.Unlock()

		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding HEADER packet for file %s",
			direction, packet.FileID, packet.Sender, packet.Receiver, filename)
		frame := buildKISSFrame(pkt)
		if err := dstConn.SendFrame(frame); err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding HEADER packet: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
		}
		return
	}

	// Process data packets (seq > 1).
	transfersLock.Lock()
	transfer, exists = transfers[key]
	transfersLock.Unlock()
	if !exists {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping data packet seq %d: header not seen",
			direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
		return
	}

	if !transfer.FinAckTime.IsZero() {
		if time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds)*time.Second {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping data packet seq %d.",
				direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
			transfersLock.Lock()
			delete(transfers, key)
			transfersLock.Unlock()
			return
		}
	}

	if packet.Seq > transfer.LastSeq {
		transfer.LastSeq = packet.Seq
		progress := float64(packet.Seq-1) / float64(transfer.TotalPackets-1) * 100.0
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer progress for file %s: packet %d of %d (%.1f%%)",
			direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename, packet.Seq, transfer.TotalPackets, progress)
		if packet.Seq == transfer.TotalPackets {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] All data packets received for file %s; waiting for FIN-ACK.",
				direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename)
		}
	}

	if *saveFiles {
		transfersLock.Lock()
		if transfer.PacketData == nil {
			transfer.PacketData = make(map[int][]byte)
		}
		if _, exists := transfer.PacketData[packet.Seq]; !exists {
			transfer.PacketData[packet.Seq] = append([]byte(nil), packet.Payload...)
		}
		complete := (len(transfer.PacketData) == (transfer.TotalPackets - 1))
		alreadySaved := transfer.FileSaved
		transfersLock.Unlock()

		if complete && !alreadySaved {
			var buf bytes.Buffer
			for i := 2; i <= transfer.TotalPackets; i++ {
				data, ok := transfer.PacketData[i]
				if !ok {
					log.Printf("[%s] [FileID: %s] Missing packet seq %d; cannot reassemble file.",
						direction, packet.FileID, i)
					return
				}
				if transfer.EncodingMethod == 1 {
					decoded, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
					if err != nil {
						log.Printf("[%s] [FileID: %s] Error decoding base64 on packet seq %d: %v",
							direction, packet.FileID, i, err)
						return
					}
					buf.Write(decoded)
				} else {
					buf.Write(data)
				}
			}
			fileData := buf.Bytes()
			if transfer.Compress {
				b := bytes.NewReader(fileData)
				zr, err := zlib.NewReader(b)
				if err != nil {
					log.Printf("[%s] [FileID: %s] Error decompressing file: %v", direction, packet.FileID, err)
					return
				}
				decompressed, err := ioutil.ReadAll(zr)
				zr.Close()
				if err != nil {
					log.Printf("[%s] [FileID: %s] Error reading decompressed data: %v", direction, packet.FileID, err)
					return
				}
				fileData = decompressed
			}
			newFilename := fmt.Sprintf("%s_%s_%s", strings.ToUpper(transfer.Sender), strings.ToUpper(transfer.Receiver), transfer.Filename)
			finalFilename := newFilename
			if _, err := os.Stat(finalFilename); err == nil {
				extIndex := strings.LastIndex(newFilename, ".")
				var base, ext string
				if extIndex != -1 {
					base = newFilename[:extIndex]
					ext = newFilename[extIndex:]
				} else {
					base = newFilename
					ext = ""
				}
				for i := 1; ; i++ {
					candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
					if _, err := os.Stat(candidate); os.IsNotExist(err) {
						finalFilename = candidate
						break
					}
				}
			}
			err := ioutil.WriteFile(finalFilename, fileData, 0644)
			if err != nil {
				log.Printf("[%s] [FileID: %s] Error saving file %s: %v", direction, packet.FileID, finalFilename, err)
			} else {
				log.Printf("[%s] [FileID: %s] Saved file as %s", direction, packet.FileID, finalFilename)
			}
			transfersLock.Lock()
			transfer.FileSaved = true
			transfersLock.Unlock()
		}
	}

	log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding data packet seq %d",
		direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
	frame := buildKISSFrame(pkt)
	if err := dstConn.SendFrame(frame); err != nil {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding data packet: %v",
			direction, packet.FileID, packet.Sender, packet.Receiver, err)
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

	for _, s := range strings.Split(*callsigns, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s != "" {
			allowedCalls[s] = true
		}
	}
	log.Printf("Allowed callsigns: %v", allowedCalls)

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

	tnc1Chan := make(chan []byte, 100)
	tnc2Chan := make(chan []byte, 100)

	fr1 := NewFrameReader(tnc1Conn, tnc1Chan)
	fr2 := NewFrameReader(tnc2Conn, tnc2Chan)
	go fr1.Run()
	go fr2.Run()

	go func() {
		for pkt := range tnc1Chan {
			processAndForwardPacket(pkt, tnc2Conn, "TNC1->TNC2")
		}
	}()

	go func() {
		for pkt := range tnc2Chan {
			processAndForwardPacket(pkt, tnc1Conn, "TNC2->TNC1")
		}
	}()

	select {}
}
