// sender.go
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/base64" // <<-- new import (already present)
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/fsnotify/fsnotify" // go get github.com/fsnotify/fsnotify
	"github.com/tarm/serial"        // run: go get github.com/tarm/serial
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------
// Global Constants
// ---------------------

const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
	CHUNK_SIZE    = 205
)

// ---------------------
// KISS / AX.25 Utility Functions
// ---------------------

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

// unescapeData reverses the KISS escaping.
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

// buildKISSFrame builds a KISS frame from raw packet bytes.
func buildKISSFrame(packet []byte) []byte {
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	return frame
}

// extractKISSFrames extracts complete KISS frames from the given buffer.
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

// buildAX25Header builds an AX.25 header using the source and destination callsigns.
func buildAX25Header(source, destination string) []byte {
	dest := encodeAX25Address(destination, false)
	src := encodeAX25Address(source, true)
	header := append(dest, src...)
	header = append(header, 0x03, 0xF0)
	return header
}

// buildPacket builds a packet for sending.
// For the header packet (seq==1), the info field contains total packet count etc.
// For data packets (seq>=2), a different info field format is used.
// <<-- Minimal change: the extra encodingMethod field is now not appended separately.
func buildPacket(sender, receiver string, seq, totalDataPackets int, payload []byte, fileID string, burstTo int, encodingMethod byte) []byte {
	sStr := padCallsign(sender)
	rStr := padCallsign(receiver)
	var info string
	if seq == 1 {
		totalHex := fmt.Sprintf("%04X", totalDataPackets)
		// The header info field does NOT append an extra byte; the encoding method is included in the header string.
		info = fmt.Sprintf("%s>%s:%s:0001%s/%s:", sStr, rStr, fileID, fmt.Sprintf("%04X", burstTo), totalHex)
	} else {
		info = fmt.Sprintf("%s>%s:%s:%s%s:", sStr, rStr, fileID, fmt.Sprintf("%04X", seq), fmt.Sprintf("%04X", burstTo))
	}
	infoBytes := []byte(info)
	ax25 := buildAX25Header(sender, receiver)
	packet := append(ax25, infoBytes...)
	// Do not append the encodingMethod separately.
	packet = append(packet, payload...)
	return packet
}

// generateFileID returns a two‑character random file ID.
func generateFileID() string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return string([]byte{
		chars[rand.Intn(len(chars))],
		chars[rand.Intn(len(chars))],
	})
}

// ---------------------
// Packet Parsing
// ---------------------

// Packet represents a parsed data or ACK packet.
type Packet struct {
	Type           string // "data" or "ack"
	Sender         string
	Receiver       string
	FileID         string
	Seq            int
	BurstTo        int
	Total          int    // For header packets (seq==1), total number of data packets.
	Payload        []byte // Binary payload.
	RawInfo        string // The decoded info field.
	Ack            string // For ACK packets.
	EncodingMethod byte   // <<-- new field: 0=binary, 1=base64
}

// parsePacket parses an unescaped packet.
func parsePacket(packet []byte) *Packet {
	if len(packet) < 16 {
		return nil
	}
	infoAndPayload := packet[16:]
	// Look for ACK indication.
	prefix := string(infoAndPayload[:min(50, len(infoAndPayload))])
	if strings.Contains(prefix, "ACK:") {
		fullInfo := string(infoAndPayload)
		parts := strings.Split(fullInfo, "ACK:")
		if len(parts) >= 2 {
			ackVal := strings.Trim(strings.Trim(parts[1], ":"), " ")
			return &Packet{
				Type:    "ack",
				Ack:     ackVal,
				RawInfo: fullInfo,
			}
		}
	}
	// Otherwise assume data packet.
	if len(infoAndPayload) < 32 {
		return nil
	}
	var infoField, payload []byte
	if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
		idx := bytes.IndexByte(infoAndPayload[27:], ':')
		if idx == -1 {
			return nil
		}
		endIdx := 27 + idx + 1
		infoField = infoAndPayload[:endIdx]
		payload = infoAndPayload[endIdx:]
	} else {
		infoField = infoAndPayload[:32]
		payload = infoAndPayload[32:]
	}
	// <<-- New: For sender-only version the receiver doesn’t need to parse an extra encoding byte.
	// (It is now embedded in the header string for seq==1.)
	infoStr := string(infoField)
	parts := strings.Split(infoStr, ":")
	if len(parts) < 4 {
		return nil
	}
	splitSR := strings.Split(parts[0], ">")
	if len(splitSR) != 2 {
		return nil
	}
	sender := strings.TrimSpace(splitSR[0])
	receiver := strings.TrimSpace(splitSR[1])
	fileID := strings.TrimSpace(parts[1])
	seqBurst := strings.TrimSpace(parts[2])
	var seq int
	var burstTo int
	total := 0
	if strings.Contains(seqBurst, "/") {
		if len(seqBurst) < 8 {
			return nil
		}
		seq = 1
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
		Type:           "data",
		Sender:         sender,
		Receiver:       receiver,
		FileID:         fileID,
		Seq:            seq,
		BurstTo:        burstTo,
		Total:          total,
		Payload:        payload,
		RawInfo:        infoStr,
		EncodingMethod: 0, // Not used on sender side
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------
// Connection Interfaces and Implementations
// ---------------------

// KISSConnection defines methods for sending and receiving KISS frames.
type KISSConnection interface {
	SendFrame(frame []byte) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn     net.Conn
	listener net.Listener // used in server mode (if needed)
	isServer bool
	lock     sync.Mutex
}

func newTCPKISSConnection(host string, port int, isServer bool) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	tcpConn := &TCPKISSConnection{isServer: isServer}
	if isServer {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		tcpConn.listener = ln
		log.Printf("[TCP Server] Listening on %s …", addr)
		conn, err := ln.Accept()
		if err != nil {
			return nil, err
		}
		tcpConn.conn = conn
		log.Printf("[TCP Server] Connection from %s", conn.RemoteAddr().String())
	} else {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tcpConn.conn = conn
		log.Printf("[TCP Client] Connected to %s", addr)
	}
	return tcpConn, nil
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

// ---------------------
// Frame Reader
// ---------------------

// FrameReader continuously reads from a KISSConnection, extracts complete KISS frames,
// unescapes them, and sends the resulting packet bytes over a channel.
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
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") {
				continue
			}
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

// ---------------------
// Utility Functions
// ---------------------

func indexOf(slice []int, val int) int {
	for i, v := range slice {
		if v == val {
			return i
		}
	}
	return -1
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------
// Command‑Line Arguments (Sender‑Only)
// ---------------------

// Arguments holds the command‑line arguments for the sender.
type Arguments struct {
	MyCallsign            string  // Your callsign (required)
	ReceiverCallsign      string  // Receiver's callsign (required)
	WindowSize            string  // "auto" or an integer (allowed: 1,2,4,6,8,10)
	Connection            string  // "tcp" or "serial"
	Debug                 bool    // Enable debug output
	Host                  string  // TCP host
	Port                  int     // TCP port
	SerialPort            string  // Serial port (e.g. COM3 or /dev/ttyUSB0)
	Baud                  int     // Baud rate for serial
	File                  string  // File(s) to send (comma delimited)
	Compress              bool    // Enable compression (default true)
	TimeoutSeconds        int     // <<-- changed: Timeout in seconds now an integer (default 5)
	TimeoutRetries        int     // Number of timeout retries (default 5)
	FileDirectory         string  // Directory to monitor for files to send (mutually exclusive with -file)
	FileDirectoryRetries  int     // Number of retries for sending a file from the directory (default 0)
	FileDirectoryExisting bool    // When true, queue existing files in the directory (default false)
	Base64                bool    // <<-- new field: when true, encode payload as Base64 after compression
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.ReceiverCallsign, "receiver-callsign", "", "Receiver callsign (required)")
	flag.StringVar(&args.WindowSize, "window-size", "auto", "Window (burst) size as an integer, or 'auto'")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug output")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host")
	flag.IntVar(&args.Port, "port", 9001, "TCP port")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g. COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial")
	flag.StringVar(&args.File, "file", "", "File(s) to send (comma delimited)")
	flag.StringVar(&args.FileDirectory, "file-directory", "", "Directory to monitor for files to send (mutually exclusive with -file)")
	flag.IntVar(&args.FileDirectoryRetries, "file-directory-retries", 0, "Number of retries for sending a file from the directory (default 0)")
	flag.BoolVar(&args.FileDirectoryExisting, "file-directory-existing", false, "Queue existing files in the directory (default false)")
	noCompress := flag.Bool("no-compress", false, "Disable compression")
	// <<-- changed: use IntVar for timeout-seconds
	flag.IntVar(&args.TimeoutSeconds, "timeout-seconds", 5, "Timeout in seconds (default 5 seconds)")
	flag.IntVar(&args.TimeoutRetries, "timeout-retries", 5, "Number of timeout retries (default 5)")
	flag.BoolVar(&args.Base64, "base64", false, "Encode file payload in base64 after compression")
	flag.Parse()

	args.Compress = !(*noCompress)

	// Ensure mutually exclusive file vs file-directory
	if args.File != "" && args.FileDirectory != "" {
		log.Fatalf("Specify either -file or -file-directory, not both.")
	}
	if args.File == "" && args.FileDirectory == "" {
		log.Fatalf("Either -file or -file-directory must be specified.")
	}
	// In file-directory mode, we ignore the -file value.
	return args
}

// ---------------------
// Sender Function for a Single File
// ---------------------

// sendFile handles transferring one file using the existing protocol.
// Instead of calling log.Fatal, errors are returned.
func sendFile(args *Arguments) error {
	// Read the file.
	if _, err := os.Stat(args.File); os.IsNotExist(err) {
		return fmt.Errorf("File %s not found", args.File)
	}
	fileData, err := ioutil.ReadFile(args.File)
	if err != nil {
		return fmt.Errorf("Error reading file: %v", err)
	}
	originalSize := len(fileData)
	var finalData []byte
	if args.Compress {
		var buf bytes.Buffer
		zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
		if err != nil {
			return fmt.Errorf("Compression error: %v", err)
		}
		_, err = zw.Write(fileData)
		if err != nil {
			return fmt.Errorf("Compression error: %v", err)
		}
		zw.Close()
		finalData = buf.Bytes()
	} else {
		finalData = fileData
	}
	// <<-- new: if the base64 flag is set, encode the payload in base64.
	if args.Base64 {
		encoded := base64.StdEncoding.EncodeToString(finalData)
		finalData = []byte(encoded)
	}
	compressedSize := len(finalData)
	md5sum := md5.Sum(fileData)
	md5Hash := hex.EncodeToString(md5sum[:])
	fileID := generateFileID()
	dataPacketCount := int(math.Ceil(float64(len(finalData)) / float64(CHUNK_SIZE)))
	totalIncludingHeader := dataPacketCount + 1

	// Compute the encoding method value to be sent (0=binary, 1=base64)
	var encodingMethod byte = 0
	if args.Base64 {
		encodingMethod = 1
	}

	// Build header string.
	// Note: TimeoutSeconds is now an integer and the encodingMethod field is added as a distinct delimited field.
	headerStr := fmt.Sprintf("%d|%d|%s|%d|%d|%s|%s|%d|%d|%d",
		args.TimeoutSeconds, args.TimeoutRetries, filepath.Base(args.File),
		originalSize, compressedSize, md5Hash, fileID, encodingMethod, boolToInt(args.Compress), totalIncludingHeader)
	headerPayload := []byte(headerStr)
	log.Printf("File: %s (%d bytes)", args.File, originalSize)
	log.Printf("Compressed to %d bytes, split into %d data packets (total packets including header: %d)", compressedSize, dataPacketCount, totalIncludingHeader)
	log.Printf("MD5: %s  File ID: %s", md5Hash, fileID)

	totalBytesToSend := len(finalData)
	overallStart := time.Now()
	totalBytesSent := 0
	totalRetries := 0
	allowedWindows := []int{1, 2, 4, 6, 8, 10}
	var currentWindowIndex int
	staticWindow := (args.WindowSize != "auto")
	if staticWindow {
		winVal, err := strconv.Atoi(args.WindowSize)
		if err != nil {
			log.Printf("Invalid window size argument. Defaulting to 4.")
			currentWindowIndex = indexOf(allowedWindows, 4)
		} else if idx := indexOf(allowedWindows, winVal); idx != -1 {
			currentWindowIndex = idx
		} else {
			log.Printf("Provided window size %d is not allowed. Defaulting to 4.", winVal)
			currentWindowIndex = indexOf(allowedWindows, 4)
		}
	} else {
		currentWindowIndex = indexOf(allowedWindows, 4)
	}
	successfulBurstCount := 0
	perPacketTimeout := 1.5

	// Build chunks: header first, then file data chunks.
	chunks := make([][]byte, 0, totalIncludingHeader)
	chunks = append(chunks, headerPayload)
	for i := 0; i < len(finalData); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		if end > len(finalData) {
			end = len(finalData)
		}
		chunks = append(chunks, finalData[i:end])
	}

	// Open connection.
	var conn KISSConnection
	if args.Connection == "tcp" {
		c, err := newTCPKISSConnection(args.Host, args.Port, false)
		if err != nil {
			return fmt.Errorf("TCP connection error: %v", err)
		}
		conn = c
	} else {
		c, err := newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			return fmt.Errorf("Serial connection error: %v", err)
		}
		conn = c
	}

	// Set up frame reader to receive ACKs.
	frameChan := make(chan []byte, 100)
	reader := NewFrameReader(conn, frameChan)
	go reader.Run()
	currentPacket := 1

	flushQueue := func() {
		for {
			select {
			case <-frameChan:
			default:
				return
			}
		}
	}

	// sendPacket now passes the encodingMethod to buildPacket.
	sendPacket := func(seq int) int {
		var burstTo int
		if seq == 1 {
			burstTo = 1
			pkt := buildPacket(args.MyCallsign, args.ReceiverCallsign, seq, totalIncludingHeader-1, chunks[seq-1], fileID, burstTo, encodingMethod)
			frame := buildKISSFrame(pkt)
			conn.SendFrame(frame)
			log.Printf("Sent packet seq=%d, burst_to=%d.", seq, burstTo)
			return 0
		} else {
			windowSize := allowedWindows[currentWindowIndex]
			burstTo = currentPacket + windowSize - 1
			if burstTo > totalIncludingHeader {
				burstTo = totalIncludingHeader
			}
			pkt := buildPacket(args.MyCallsign, args.ReceiverCallsign, seq, totalIncludingHeader-1, chunks[seq-1], fileID, burstTo, encodingMethod)
			frame := buildKISSFrame(pkt)
			conn.SendFrame(frame)
			log.Printf("Sent packet seq=%d, burst_to=%d.", seq, burstTo)
			return len(chunks[seq-1])
		}
	}

	waitForAck := func(numPackets int, isHeader bool) string {
		retries := 0
		overallTimeout := time.Duration(numPackets)*time.Duration(perPacketTimeout*float64(time.Second)) + time.Duration(args.TimeoutSeconds)*time.Second
		for retries < args.TimeoutRetries {
			deadline := time.Now().Add(overallTimeout)
			for time.Now().Before(deadline) {
				select {
				case pktBytes := <-frameChan:
					parsed := parsePacket(pktBytes)
					if parsed == nil {
						continue
					}
					if parsed.Type == "ack" {
						return parsed.Ack
					}
				case <-time.After(100 * time.Millisecond):
				}
			}
			retries++
			totalRetries++
			log.Printf("Timeout waiting for ACK (retry %d/%d).", retries, args.TimeoutRetries)
			if isHeader {
				log.Printf("Resending header packet (retry %d/%d).", retries, args.TimeoutRetries)
				sendPacket(1)
			}
			overallTimeout = time.Duration(args.TimeoutSeconds*int(math.Pow(1.5, float64(retries)))) * time.Second
		}
		return ""
	}

	log.Printf("Sending header packet (seq=1) …")
	headerStart := time.Now()
	_ = sendPacket(1)
	totalBytesSent += 0 // header not counted
	ackVal := waitForAck(1, true)
	headerAckDuration := time.Since(headerStart).Seconds()
	if headerAckDuration > 0 {
		perPacketTimeout = headerAckDuration / 2
		log.Printf("Updated per-packet timeout to %.2f seconds based on header ACK timing.", perPacketTimeout)
	} else {
		perPacketTimeout = 1.5
	}
	log.Printf("Received ACK: %s", ackVal)
	ackInt, err := strconv.ParseInt(ackVal, 16, 32)
	if err != nil {
		ackInt = 0
	}
	for int(ackInt) != 1 {
		log.Printf("Unexpected header ACK %s; waiting for correct ACK …", ackVal)
		ackVal = waitForAck(1, true)
		if ackVal == "" {
			reader.Stop()
			conn.Close()
			return fmt.Errorf("No correct header ACK received after maximum retries. Giving up on transfer.")
		}
		ackInt, _ = strconv.ParseInt(ackVal, 16, 32)
	}
	currentPacket = int(ackInt) + 1
	log.Printf("Header ACK received (0001); proceeding with data packets …")
	for currentPacket <= totalIncludingHeader {
		flushQueue()
		startSeq := currentPacket
		windowSize := allowedWindows[currentWindowIndex]
		endSeq := startSeq + windowSize - 1
		if endSeq > totalIncludingHeader {
			endSeq = totalIncludingHeader
		}
		log.Printf("Sending burst: packets %d to %d (window size %d) …", startSeq, endSeq, windowSize)
		burstStart := time.Now()
		burstBytes := 0
		for seq := startSeq; seq <= endSeq; seq++ {
			n := sendPacket(seq)
			burstBytes += n
			totalBytesSent += n
			time.Sleep(5 * time.Millisecond)
		}
		burstCount := endSeq - startSeq + 1
		expectedAck := endSeq + 1
		ackVal = waitForAck(burstCount, false)
		burstDuration := time.Since(burstStart).Seconds()
		if burstCount > 0 {
			newTimeout := burstDuration / float64(burstCount+1)
			perPacketTimeout = newTimeout
			log.Printf("Updated per-packet timeout to %.2f seconds based on ACK.", perPacketTimeout)
		}
		if ackVal == "" {
			log.Printf("No ACK received after maximum retries. Giving up on transfer.")
			break
		}
		log.Printf("Received ACK: %s", ackVal)
		var ackNum int
		if strings.Contains(ackVal, "-") {
			parts := strings.Split(ackVal, "-")
			if len(parts) >= 2 {
				if num, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
					ackNum = int(num) + 1
				}
			}
		} else {
			if num, err := strconv.ParseInt(ackVal, 16, 32); err == nil {
				ackNum = int(num) + 1
			} else {
				ackNum = currentPacket + 1
			}
		}
		if ackNum == expectedAck {
			if !staticWindow {
				successfulBurstCount++
				log.Printf("All packets in burst acknowledged.")
				if successfulBurstCount >= 2 && currentWindowIndex < len(allowedWindows)-1 {
					currentWindowIndex++
					successfulBurstCount = 0
					log.Printf("Increasing window size to %d", allowedWindows[currentWindowIndex])
				} else {
					log.Printf("Window remains at %d", allowedWindows[currentWindowIndex])
				}
			} else {
				log.Printf("All packets in burst acknowledged. (Static window in use)")
			}
		} else {
			log.Printf("Not all packets acknowledged. Expected ACK: %d, received ACK: %d", expectedAck, ackNum)
			if !staticWindow {
				if currentWindowIndex > 0 {
					currentWindowIndex--
					successfulBurstCount = 0
					log.Printf("Reducing window size to %d", allowedWindows[currentWindowIndex])
				} else {
					log.Printf("Window size is at minimum (1).")
				}
			} else {
				log.Printf("Static window size in use; no adjustment made.")
			}
		}
		if ackNum <= currentPacket {
			log.Printf("Stale ACK received; waiting for next ACK …")
			continue
		}
		currentPacket = ackNum
		log.Printf("Updated current_packet to %d.", currentPacket)
		overallElapsed := time.Since(overallStart).Seconds()
		burstRate := float64(burstBytes) / burstDuration
		overallRate := float64(totalBytesSent) / overallElapsed
		progress := (float64(totalBytesSent) / float64(totalBytesToSend)) * 100
		var eta float64
		if overallRate > 0 {
			eta = float64(totalBytesToSend-totalBytesSent) / overallRate
		} else {
			eta = 0
		}
		log.Printf("--- Stats ---")
		log.Printf("Previous burst: %d bytes in %.2fs (%.2f bytes/s)", burstBytes, burstDuration, burstRate)
		log.Printf("Overall: %d/%d bytes (%.2f%%), elapsed: %.2fs, ETA: %.2fs", totalBytesSent, totalBytesToSend, progress, overallElapsed, eta)
		log.Printf("Overall bytes/sec: %.2f bytes/s", overallRate)
		log.Printf("--------------")
	}
	if currentPacket <= totalIncludingHeader {
		reader.Stop()
		conn.Close()
		return fmt.Errorf("File transfer incomplete; aborted before sending all packets.")
	}
	overallElapsed := time.Since(overallStart).Seconds()
	overallRate := float64(totalBytesSent) / overallElapsed
	log.Printf("File transfer complete.")
	log.Printf("=== Final Summary ===")
	log.Printf("Total bytes sent: %d bytes in %.2fs (%.2f bytes/s).", totalBytesSent, overallElapsed, overallRate)
	log.Printf("Total retries: %d.", totalRetries)
	log.Printf("=====================")
	finalConfirmationInfo := fmt.Sprintf("%s>%s:%s:ACK:FIN-ACK", padCallsign(args.MyCallsign), padCallsign(args.ReceiverCallsign), fileID)
	finalConfirmationPkt := append(buildAX25Header(args.MyCallsign, args.ReceiverCallsign), []byte(finalConfirmationInfo)...)
	finalFrame := buildKISSFrame(finalConfirmationPkt)
	conn.SendFrame(finalFrame)
	log.Printf("Sent FIN-ACK after final cumulative ACK. Transfer fully completed.")
	finalWaitPeriod := 1500*time.Millisecond + time.Duration(args.TimeoutSeconds)*time.Second
	log.Printf("Listening for re-transmitted ACK for %.2f seconds...", finalWaitPeriod.Seconds())
	endTime := time.Now().Add(finalWaitPeriod)
	for time.Now().Before(endTime) {
		select {
		case ackPkt := <-frameChan:
			parsedAck := parsePacket(ackPkt)
			if parsedAck != nil && parsedAck.Type == "ack" && strings.Contains(parsedAck.Ack, "-") {
				log.Printf("Re-received cumulative ACK from receiver, re-sending final confirmation FIN-ACK.")
				conn.SendFrame(finalFrame)
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	reader.Stop()
	conn.Close()
	return nil
}

// processFile wraps sendFile so that in directory‑mode a file is retried a specified
// number of times before giving up.
func processFile(file string, args *Arguments) {
	originalFileArg := args.File
	args.File = file
	var err error
	for attempt := 0; attempt <= args.FileDirectoryRetries; attempt++ {
		err = sendFile(args)
		if err == nil {
			log.Printf("Successfully sent file: %s", file)
			break
		}
		log.Printf("Error sending file %s: %v (attempt %d/%d)", file, err, attempt+1, args.FileDirectoryRetries+1)
		if attempt < args.FileDirectoryRetries {
			time.Sleep(2 * time.Second)
		}
	}
	if err != nil {
		log.Printf("Giving up on file: %s", file)
	}
	args.File = originalFileArg
}

// ---------------------
// Main
// ---------------------

func main() {
	rand.Seed(time.Now().UnixNano())
	log.SetFlags(log.LstdFlags)
	args := parseArguments()
	if args.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// If file-directory is specified, run in directory‑monitoring mode.
	if args.FileDirectory != "" {
		// Create a channel to queue files.
		fileQueue := make(chan string, 100)

		// Optionally, perform an initial scan of the directory if -file-directory-existing is true.
		if args.FileDirectoryExisting {
			files, err := ioutil.ReadDir(args.FileDirectory)
			if err != nil {
				log.Fatalf("Error reading directory %s: %v", args.FileDirectory, err)
			}
			for _, fi := range files {
				// Ignore files whose names start with a dot.
				if strings.HasPrefix(fi.Name(), ".") {
					continue
				}
				if fi.Mode().IsRegular() {
					fullPath := filepath.Join(args.FileDirectory, fi.Name())
					fileQueue <- fullPath
					log.Printf("Queued existing file: %s", fullPath)
				}
			}
		}

		// Set up a file system watcher.
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatalf("Error creating file watcher: %v", err)
		}
		defer watcher.Close()
		err = watcher.Add(args.FileDirectory)
		if err != nil {
			log.Fatalf("Error watching directory %s: %v", args.FileDirectory, err)
		}
		log.Printf("Monitoring directory: %s", args.FileDirectory)

		// Start a goroutine to enqueue newly created or modified files.
		go func() {
			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return
					}
					// We care about create and write events.
					if event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Write == fsnotify.Write {
						baseName := filepath.Base(event.Name)
						// Ignore files starting with a dot.
						if strings.HasPrefix(baseName, ".") {
							continue
						}
						// Make sure it's a regular file.
						info, err := os.Stat(event.Name)
						if err == nil && info.Mode().IsRegular() {
							fileQueue <- event.Name
							log.Printf("Enqueued file from event: %s", event.Name)
						}
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						return
					}
					log.Printf("Watcher error: %v", err)
				}
			}
		}()

		// Process files from the queue one at a time.
		for {
			select {
			case file := <-fileQueue:
				log.Printf("=== Starting transfer for file: %s ===", file)
				processFile(file, args)
				log.Printf("=== Completed transfer for file: %s ===", file)
			default:
				time.Sleep(500 * time.Millisecond)
			}
		}
	} else {
		// File mode: process comma-delimited file list.
		fileList := strings.Split(args.File, ",")
		if len(fileList) == 0 {
			log.Fatalf("No files specified.")
		}
		for i, file := range fileList {
			file = strings.TrimSpace(file)
			if file == "" {
				continue
			}
			args.File = file
			log.Printf("=== Starting transfer for file %d of %d: %s ===", i+1, len(fileList), file)
			if err := sendFile(args); err != nil {
				log.Fatalf("Error sending file %s: %v", file, err)
			}
			log.Printf("=== Completed transfer for file: %s ===", file)
		}
	}
}
