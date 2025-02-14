// files.go
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"go.bug.st/serial"
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

// buildAX25Header builds an AX.25 header using the source and destination callsigns.
func buildAX25Header(sender, receiver string) []byte {
	dest := encodeAX25Address(receiver, false)
	src := encodeAX25Address(sender, true)
	header := append(dest, src...)
	header = append(header, 0x03, 0xF0)
	return header
}

// buildPacket builds a packet with the appropriate info field.
// In our design, the header packet (seq==1) contains the header payload (which itself includes the encoding method)
// while all other packets use file data chunks.
func buildPacket(sender, receiver string, seq, totalDataPackets int, payload []byte, fileID string, burstTo int) []byte {
	sStr := padCallsign(sender)
	rStr := padCallsign(receiver)
	var info string
	if seq == 1 {
		totalHex := fmt.Sprintf("%04X", totalDataPackets)
		info = fmt.Sprintf("%s>%s:%s:0001%s/%s:", sStr, rStr, fileID, fmt.Sprintf("%04X", burstTo), totalHex)
	} else {
		info = fmt.Sprintf("%s>%s:%s:%s%s:", sStr, rStr, fileID, fmt.Sprintf("%04X", seq), fmt.Sprintf("%04X", burstTo))
	}
	infoBytes := []byte(info)
	ax25 := buildAX25Header(sender, receiver)
	return append(append(ax25, infoBytes...), payload...)
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
	EncodingMethod byte   // 0 = binary, 1 = base64 (only set in header packet)
}

// parsePacket parses an unescaped packet.
func parsePacket(packet []byte) *Packet {
    if len(packet) < 16 {
        return nil
    }
    // Skip the first 16 bytes (AX.25 header)
    infoAndPayload := packet[16:]
    
    // NEW: Check if this is an ACK packet.
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
    
    var infoField, payload []byte
    // For header packets: the info field ends with a colon after "0001".
    if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
        idx := bytes.IndexByte(infoAndPayload[27:], ':')
        if idx == -1 {
            return nil
        }
        endIdx := 27 + idx + 1
        infoField = infoAndPayload[:endIdx]
        payload = infoAndPayload[endIdx:]
    } else {
        // For data packets: fixed info field length.
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

    // For header packets (seq==1), parse the header payload to extract the encoding method.
    var encodingMethod byte = 0
    if seq == 1 {
        // The header payload follows the format:
        // timeout|timeoutRetries|filename|origSize|compSize|md5|fileID|encodingMethod|compress|totalPackets
        headerFields := strings.Split(string(payload), "|")
        if len(headerFields) >= 10 {
            if val, err := strconv.Atoi(headerFields[7]); err == nil {
                encodingMethod = byte(val)
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
	listener net.Listener // used in server mode
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
			// Treat EOF as no data.
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
	ser  serial.Port
	lock sync.Mutex
}

func newSerialKISSConnection(portName string, baud int) (*SerialKISSConnection, error) {
	mode := &serial.Mode{
		BaudRate: baud,
		Parity:   serial.NoParity,
		DataBits: 8,
		StopBits: serial.OneStopBit,
	}
	ser, err := serial.Open(portName, mode)
	if err != nil {
		return nil, err
	}
	// Optionally, set a read timeout if desired.
	if err := ser.SetReadTimeout(100 * time.Millisecond); err != nil {
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
			// Treat EOF as no data.
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
			// If EOF is returned, simply continue.
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
// Command‑Line Arguments
// ---------------------

// Arguments holds the command‑line arguments.
type Arguments struct {
	Role             string
	MyCallsign       string
	ReceiverCallsign string
	WindowSize       string
	Connection       string
	Debug            bool
	Host             string
	Port             int
	SerialPort       string
	Baud             int
	File             string
	Compress         bool
	TimeoutSeconds   int // now an integer
	TimeoutRetries   int
	OneFile          bool
	Base64           bool // Only valid when role == "sender"
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.Role, "role", "", "Role: sender or receiver (required)")
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.ReceiverCallsign, "receiver-callsign", "", "Receiver callsign (required if sender)")
	flag.StringVar(&args.WindowSize, "window-size", "auto", "Window (burst) size as an integer, or 'auto'")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug output")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host")
	flag.IntVar(&args.Port, "port", 9001, "TCP port")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g. COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial")
	flag.StringVar(&args.File, "file", "", "File to send (required if sender)")
	noCompress := flag.Bool("no-compress", false, "Disable compression")
	flag.IntVar(&args.TimeoutSeconds, "timeout-seconds", 10, "Timeout in seconds [Sender only]")
	flag.IntVar(&args.TimeoutRetries, "timeout-retries", 5, "Number of timeout retries [Sender only]")
	flag.BoolVar(&args.OneFile, "one-file", false, "Exit after successfully receiving one file (Receiver mode)")
	flag.BoolVar(&args.Base64, "base64", false, "Enable base64 encoding for file data payloads (sender mode only)")
	flag.Parse()

	args.Compress = !(*noCompress)

	if args.Role == "sender" {
		if args.ReceiverCallsign == "" {
			log.Fatalf("--receiver-callsign is required in sender mode.")
		}
		if args.File == "" {
			log.Fatalf("--file is required in sender mode.")
		}
	} else if args.Role != "receiver" {
		log.Fatalf("Role must be either sender or receiver.")
	}
	// In receiver mode, ignore any base64 flag.
	if args.Role == "receiver" && args.Base64 {
		log.Printf("Warning: -base64 flag is ignored in receiver mode.")
		args.Base64 = false
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	return args
}

// ---------------------
// Sender Main Function
// ---------------------

func senderMain(args *Arguments) {
	// Read the file.
	if _, err := os.Stat(args.File); os.IsNotExist(err) {
		log.Fatalf("File %s not found.", args.File)
	}
	fileData, err := ioutil.ReadFile(args.File)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	originalSize := len(fileData)
	var finalData []byte
	if args.Compress {
		var buf bytes.Buffer
		zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
		if err != nil {
			log.Fatalf("Compression error: %v", err)
		}
		_, err = zw.Write(fileData)
		if err != nil {
			log.Fatalf("Compression error: %v", err)
		}
		zw.Close()
		finalData = buf.Bytes()
	} else {
		finalData = fileData
	}
	compressedSize := len(finalData)
	md5sum := md5.Sum(fileData)
	md5Hash := hex.EncodeToString(md5sum[:])
	fileID := generateFileID()

	// Determine chunk size.
	dataChunkSize := CHUNK_SIZE
	if args.Base64 {
		dataChunkSize = (CHUNK_SIZE / 4) * 3
		log.Printf("Base64 mode enabled; splitting file data into chunks of up to %d raw bytes.", dataChunkSize)
	}
	dataPacketCount := int(math.Ceil(float64(len(finalData)) / float64(dataChunkSize)))
	totalIncludingHeader := dataPacketCount + 1

	// Build the header payload.
	// Header format: timeout|timeoutRetries|filename|origSize|compSize|md5|fileID|encodingMethod|compress|totalPackets
	encodingMethod := 0
	if args.Base64 {
		encodingMethod = 1
	}
	headerStr := fmt.Sprintf("%d|%d|%s|%d|%d|%s|%s|%d|%d|%d",
		args.TimeoutSeconds, args.TimeoutRetries, filepath.Base(args.File),
		originalSize, compressedSize, md5Hash, fileID, encodingMethod, boolToInt(args.Compress), totalIncludingHeader)
	headerPayload := []byte(headerStr)

	log.Printf("File: %s (%d bytes)", args.File, originalSize)
	log.Printf("Compressed to %d bytes, split into %d data packets (total packets including header: %d)", compressedSize, dataPacketCount, totalIncludingHeader)
	log.Printf("MD5: %s  File ID: %s", md5Hash, fileID)

	// Build the chunks array.
	// We follow the original design: chunk 0 is the header, then the file data chunks.
	chunks := make([][]byte, 0, totalIncludingHeader)
	chunks = append(chunks, headerPayload)
	for i := 0; i < len(finalData); i += dataChunkSize {
		end := i + dataChunkSize
		if end > len(finalData) {
			end = len(finalData)
		}
		chunkData := finalData[i:end]
		if args.Base64 {
			encoded := base64.StdEncoding.EncodeToString(chunkData)
			chunkData = []byte(encoded)
		}
		chunks = append(chunks, chunkData)
	}

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

	var conn KISSConnection
	if args.Connection == "tcp" {
		c, err := newTCPKISSConnection(args.Host, args.Port, false)
		if err != nil {
			log.Fatalf("TCP connection error: %v", err)
		}
		conn = c
	} else {
		c, err := newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("Serial connection error: %v", err)
		}
		conn = c
	}
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

	// sendPacket uses the prebuilt chunks.
	sendPacket := func(seq int) int {
		var burstTo int
		if seq == 1 {
			burstTo = 1
			pkt := buildPacket(args.MyCallsign, args.ReceiverCallsign, seq, totalIncludingHeader-1, chunks[0], fileID, burstTo)
			frame := buildKISSFrame(pkt)
			conn.SendFrame(frame)
			log.Printf("Sent header packet seq=%d, burst_to=%d.", seq, burstTo)
			return 0
		} else {
			windowSize := allowedWindows[currentWindowIndex]
			burstTo = currentPacket + windowSize - 1
			if burstTo > totalIncludingHeader {
				burstTo = totalIncludingHeader
			}
			pkt := buildPacket(args.MyCallsign, args.ReceiverCallsign, seq, totalIncludingHeader-1, chunks[seq-1], fileID, burstTo)
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
			overallTimeout = time.Duration(args.TimeoutSeconds)*time.Second * time.Duration(math.Pow(1.5, float64(retries)))
		}
		return ""
	}

	log.Printf("Sending header packet (seq=1) …")
	headerStart := time.Now()
	_ = sendPacket(1)
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
			log.Printf("No correct header ACK received after maximum retries. Giving up on transfer.")
			reader.Stop()
			conn.Close()
			os.Exit(1)
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
			if parsedAck != nil && parsedAck.Type == "ack" && strings.Contains(parsedAck.Ack, "FIN-ACK") {
				log.Printf("Re-received cumulative ACK from receiver, re-sending final confirmation FIN-ACK.")
				conn.SendFrame(finalFrame)
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	reader.Stop()
	conn.Close()
}

// ---------------------
// Receiver Data Structures and Functions
// ---------------------

// Transfer holds state for an incoming file transfer.
type Transfer struct {
	Sender           string
	Filename         string
	OrigSize         int
	CompSize         int
	MD5              string
	Compress         bool
	Packets          map[int][]byte
	BurstTo          int
	LastReceived     time.Time
	LastAckSent      time.Time
	RetryCount       int
	TimeoutSeconds   int
	TimeoutRetries   int
	RetryInterval    float64
	Total            int
	StartTime        time.Time
	BytesReceived    int
	DuplicateCount   int
	BurstBytes       int
	LastBurstAckTime time.Time
	EncodingMethod   byte // 0 = binary, 1 = base64 (set from header)
}

// computeCumulativeAck computes the highest contiguous sequence number received.
// If only the header is present, it returns "0001".
// Otherwise it returns "0001-XXXX" where XXXX is the highest contiguous packet.
func computeCumulativeAck(t *Transfer) string {
	var keys []int
	for k := range t.Packets {
		if k >= 2 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "0001"
	}
	maxSeq := 0
	for i := 2; ; i++ {
		if _, ok := t.Packets[i]; ok {
			maxSeq = i
		} else {
			break
		}
	}
	if maxSeq == 0 {
		return "0001"
	}
	return fmt.Sprintf("0001-%04X", maxSeq)
}

// sendAck builds and sends an ACK packet.
func sendAck(conn KISSConnection, myCallsign, remote, fileID, ackStr string) {
	info := fmt.Sprintf("%s>%s:%s:ACK:%s", padCallsign(myCallsign), padCallsign(remote), fileID, ackStr)
	ackPkt := append(buildAX25Header(myCallsign, remote), []byte(info)...)
	frame := buildKISSFrame(ackPkt)
	conn.SendFrame(frame)
	log.Printf("Sent ACK: %s for file %s", ackStr, fileID)
}

// ---------------------
// Receiver Main Function
// ---------------------

func receiverMain(args *Arguments) {
	var conn KISSConnection
	var err error
	if args.Connection == "tcp" {
		conn, err = newTCPKISSConnection(args.Host, args.Port, false)
		if err != nil {
			log.Fatalf("TCP connection error: %v", err)
		}
	} else {
		conn, err = newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("Serial connection error: %v", err)
		}
	}
	frameChan := make(chan []byte, 100)
	reader := NewFrameReader(conn, frameChan)
	go reader.Run()
	log.Printf("Receiver started. My callsign: %s", strings.ToUpper(args.MyCallsign))
	transfers := make(map[string]*Transfer)

	// Main receiver loop.
	for {
		select {
		case pktBytes := <-frameChan:
			parsed := parsePacket(pktBytes)
			if parsed == nil {
				log.Printf("Could not parse packet.")
				continue
			}
			if parsed.Type == "ack" {
				log.Printf("Received an ACK packet (ignored on receiver).")
				continue
			}
			seq := parsed.Seq
			fileID := parsed.FileID
			sender := parsed.Sender
			receiverStr := parsed.Receiver
			log.Printf("Received data packet: seq=%d, file_id=%s, burst_to=%d, sender=%s, receiver=%s", seq, fileID, parsed.BurstTo, sender, receiverStr)
			localCS := strings.ToUpper(strings.TrimSpace(args.MyCallsign))
			if strings.ToUpper(strings.TrimSpace(receiverStr)) != localCS {
				log.Printf("Packet intended for %s, not me (%s). Ignoring.", receiverStr, localCS)
				continue
			}
			if _, ok := transfers[fileID]; !ok {
				if seq != 1 {
					log.Printf("Received non-header packet (seq=%d) for unknown transfer %s. Ignoring.", seq, fileID)
					continue
				}
				headerPayload := parsed.Payload
				headerInfo := string(headerPayload)
				parts := strings.Split(headerInfo, "|")
				if len(parts) < 10 {
					log.Printf("Invalid header info – ignoring transfer.")
					continue
				}
				transferTimeoutSeconds, _ := strconv.Atoi(parts[0])
				transferTimeoutRetries, _ := strconv.Atoi(parts[1])
				filename := parts[2]
				origSize, _ := strconv.Atoi(parts[3])
				compSize, _ := strconv.Atoi(parts[4])
				md5Hash := parts[5]
				// parts[6] is fileID, parts[7] is encodingMethod, parts[8] is compress, parts[9] is total packets.
				encodingMethodVal, _ := strconv.Atoi(parts[7])
				compFlag := parts[8]
				totalPackets, _ := strconv.Atoi(parts[9])
				compress := (compFlag == "1")
				transfers[fileID] = &Transfer{
					Sender:           sender,
					Filename:         filename,
					OrigSize:         origSize,
					CompSize:         compSize,
					MD5:              md5Hash,
					Compress:         compress,
					Packets:          make(map[int][]byte),
					BurstTo:          parsed.BurstTo,
					LastReceived:     time.Now(),
					LastAckSent:      time.Now(),
					RetryCount:       0,
					TimeoutSeconds:   transferTimeoutSeconds,
					TimeoutRetries:   transferTimeoutRetries,
					RetryInterval:    float64(transferTimeoutSeconds) + 1.5,
					Total:            totalPackets,
					StartTime:        time.Now(),
					BytesReceived:    0,
					DuplicateCount:   0,
					BurstBytes:       0,
					LastBurstAckTime: time.Now(),
					EncodingMethod:   byte(encodingMethodVal),
				}
				log.Printf("Started transfer from %s (File: %s, ID: %s)", sender, filename, fileID)
				log.Printf("Total packets required (including header): %d", totalPackets)
				sendAck(conn, args.MyCallsign, sender, fileID, "0001")
				continue
			}
			transfer := transfers[fileID]
			transfer.LastReceived = time.Now()
			transfer.RetryInterval = float64(transfer.TimeoutSeconds)
			if parsed.BurstTo > transfer.BurstTo {
				transfer.BurstTo = parsed.BurstTo
			}
			if _, exists := transfer.Packets[seq]; exists {
				transfer.DuplicateCount++
				log.Printf("Duplicate packet seq %d received; duplicates so far: %d.", seq, transfer.DuplicateCount)
				continue
			}
			transfer.Packets[seq] = parsed.Payload
			transfer.BytesReceived += len(parsed.Payload)
			transfer.BurstBytes += len(parsed.Payload)
			if transfer.BurstTo != 0 && seq == transfer.BurstTo {
				now := time.Now()
				burstDuration := now.Sub(transfer.LastBurstAckTime).Seconds()
				burstRate := float64(transfer.BurstBytes) / burstDuration
				overallElapsed := now.Sub(transfer.StartTime).Seconds()
				overallRate := float64(transfer.BytesReceived) / overallElapsed
				progress := (float64(transfer.BytesReceived) / float64(transfer.CompSize)) * 100
				var eta float64
				if overallRate > 0 {
					eta = float64(transfer.CompSize-transfer.BytesReceived) / overallRate
				}
				log.Printf("--- Stats ---")
				log.Printf("Previous burst: %d bytes in %.2fs (%.2f bytes/s)", transfer.BurstBytes, burstDuration, burstRate)
				log.Printf("Overall: %d/%d bytes (%.2f%%), elapsed: %.2fs, ETA: %.2fs", transfer.BytesReceived, transfer.CompSize, progress, overallElapsed, eta)
				log.Printf("Overall bytes/sec: %.2f bytes/s", overallRate)
				log.Printf("--------------")
				ackRange := computeCumulativeAck(transfer)
				sendAck(conn, args.MyCallsign, sender, fileID, ackRange)
				transfer.LastAckSent = time.Now()
				transfer.BurstBytes = 0
				transfer.LastBurstAckTime = now
				transfer.RetryCount = 0
				transfer.RetryInterval = float64(transfer.TimeoutSeconds)
			}
			if transfer.Total > 0 && len(transfer.Packets) == transfer.Total-1 {
				overallElapsed := time.Since(transfer.StartTime).Seconds()
				overallRate := float64(transfer.BytesReceived) / overallElapsed
				log.Printf("=== Receiver Final Summary for file %s ===", fileID)
				log.Printf("Total bytes received: %d bytes in %.2fs (%.2f bytes/s), Duplicates: %d.",
					transfer.BytesReceived, overallElapsed, overallRate, transfer.DuplicateCount)
				log.Printf("===============================================")
				log.Printf("Transfer complete for file %s. Reassembling file …", fileID)
				var fileDataBuffer bytes.Buffer
				complete := true
				for i := 2; i <= transfer.Total; i++ {
					part, ok := transfer.Packets[i]
					if !ok {
						log.Printf("Missing packet %d – cannot reassemble.", i)
						complete = false
						break
					}
					// Use the encoding method from the header.
					if transfer.EncodingMethod == 1 {
						decoded, err := base64.StdEncoding.DecodeString(string(part))
						if err != nil {
							log.Printf("Error decoding base64 for packet %d: %v", i, err)
							complete = false
							break
						}
						fileDataBuffer.Write(decoded)
					} else {
						fileDataBuffer.Write(part)
					}
				}
				if !complete {
					continue
				}
				fullData := fileDataBuffer.Bytes()
				if transfer.Compress {
					b := bytes.NewReader(fullData)
					zr, err := zlib.NewReader(b)
					if err != nil {
						log.Printf("Decompression error: %v", err)
						continue
					}
					decompressed, err := ioutil.ReadAll(zr)
					zr.Close()
					if err != nil {
						log.Printf("Decompression error: %v", err)
						continue
					}
					fullData = decompressed
				}
				calculatedMD5 := md5.Sum(fullData)
				calculatedMD5Str := hex.EncodeToString(calculatedMD5[:])
				if calculatedMD5Str == transfer.MD5 {
					log.Printf("Checksum OK.")
				} else {
					log.Printf("Checksum mismatch! (Expected: %s, Got: %s)", transfer.MD5, calculatedMD5Str)
				}
				outname := transfer.Filename
				base := outname
				ext := ""
				if dot := strings.LastIndex(outname, "."); dot != -1 {
					base = outname[:dot]
					ext = outname[dot:]
				}
				cnt := 1
				for {
					if _, err := os.Stat(outname); os.IsNotExist(err) {
						break
					}
					outname = fmt.Sprintf("%s_%d%s", base, cnt, ext)
					cnt++
				}
				err = ioutil.WriteFile(outname, fullData, 0644)
				if err != nil {
					log.Printf("Error saving file: %v", err)
				} else {
					log.Printf("Saved received file as %s", outname)
				}
				log.Printf("Waiting for sender's final confirmation (FIN-ACK)...")
				var finalConfirmation string
				retries := 0
				for finalConfirmation == "" && retries < transfer.TimeoutRetries {
					select {
					case ackPkt := <-frameChan:
						parsedAck := parsePacket(ackPkt)
						if parsedAck != nil && parsedAck.Type == "ack" && strings.Contains(parsedAck.Ack, "FIN-ACK") {
							finalConfirmation = parsedAck.Ack
							log.Printf("Received sender's final confirmation FIN-ACK.")
						}
					case <-time.After(time.Duration(transfer.TimeoutSeconds) * time.Second):
						retries++
						log.Printf("Timeout waiting for final confirmation (FIN-ACK) (retry %d/%d). Resending cumulative ACK.", retries, transfer.TimeoutRetries)
						ackRange := computeCumulativeAck(transfer)
						sendAck(conn, args.MyCallsign, sender, fileID, ackRange)
					}
				}
				if finalConfirmation == "" {
					log.Printf("Final confirmation FIN-ACK not received after maximum retries.")
				} else {
					log.Printf("Final handshake completed successfully.")
				}
				delete(transfers, fileID)
				if args.OneFile {
					log.Printf("Received one file successfully. Exiting receiver mode as --one-file flag is set.")
					reader.Stop()
					conn.Close()
					return
				}
			}
		case <-time.After(500 * time.Millisecond):
			now := time.Now()
			for fid, transfer := range transfers {
				lastEvent := transfer.LastReceived
				if transfer.LastAckSent.After(lastEvent) {
					lastEvent = transfer.LastAckSent
				}
				if now.Sub(lastEvent).Seconds() >= transfer.RetryInterval {
					if transfer.RetryCount < transfer.TimeoutRetries {
						ackRange := computeCumulativeAck(transfer)
						sendAck(conn, args.MyCallsign, transfer.Sender, fid, ackRange)
						transfer.LastAckSent = now
						transfer.RetryCount++
						log.Printf("Resent ACK %s for file %s due to inactivity (retry %d/%d, interval %.2fs).",
							ackRange, fid, transfer.RetryCount, transfer.TimeoutRetries, transfer.RetryInterval)
						transfer.RetryInterval *= 1.5
					} else {
						log.Printf("Giving up on transfer %s after %d ACK retries due to inactivity.", fid, transfer.TimeoutRetries)
						delete(transfers, fid)
					}
				}
			}
		}
	}
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
// Main
// ---------------------

func main() {
	rand.Seed(time.Now().UnixNano())
	log.SetFlags(log.LstdFlags)
	args := parseArguments()
	if args.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	if args.Role == "sender" {
		senderMain(args)
	} else {
		receiverMain(args)
	}
}
