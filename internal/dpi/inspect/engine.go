package inspect

import (
	"bytes"
	"encoding/binary"
	"sort"
	"strings"

	"kaliwall/internal/dpi/types"
)

var suspiciousPayloadPatterns = [][]byte{
	[]byte("union select"),
	[]byte("<script>"),
	[]byte("cmd="),
}

// Engine performs application-layer extraction and threat signal detection.
type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Inspect(payload types.AppPayload) types.InspectResult {
	res := types.InspectResult{
		Timestamp: payload.Timestamp,
		Tuple:     payload.Tuple,
		Protocol:  payload.Tuple.Protocol,
		Payload:   append([]byte(nil), payload.Payload...),
	}

	if payload.DNSQuery != "" {
		res.DNSDomain = strings.TrimSuffix(strings.ToLower(payload.DNSQuery), ".")
	}

	if len(payload.Payload) == 0 {
		return res
	}

	lower := bytes.ToLower(payload.Payload)
	for _, pat := range suspiciousPayloadPatterns {
		if bytes.Contains(lower, pat) {
			res.Detections = append(res.Detections, "payload:"+string(pat))
		}
	}

	if method, host, url, headers, ok := parseHTTP(payload.Payload); ok {
		res.HTTPMethod = method
		res.HTTPHost = host
		res.HTTPURL = url
		res.HTTPHeaders = headers
		res.Protocol = "http"
	}

	if sni, ok := parseTLSSNI(payload.Payload); ok {
		res.TLSSNI = sni
		if res.Protocol == payload.Tuple.Protocol {
			res.Protocol = "tls"
		}
	}

	return res
}

func parseHTTP(buf []byte) (method, host, path string, headers map[string]string, ok bool) {
	lineEnd := bytes.Index(buf, []byte("\r\n"))
	if lineEnd <= 0 {
		return "", "", "", nil, false
	}
	line := string(buf[:lineEnd])
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return "", "", "", nil, false
	}
	m := parts[0]
	if !isHTTPMethod(m) {
		return "", "", "", nil, false
	}
	headers = extractHeaders(buf)
	host = headers["host"]
	return m, host, parts[1], headers, true
}

func isHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

func extractHeaders(buf []byte) map[string]string {
	headers := make(map[string]string)
	lines := bytes.Split(buf, []byte("\r\n"))
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if len(line) == 0 {
			break
		}
		parts := bytes.SplitN(line, []byte(":"), 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(string(parts[0])))
		v := strings.TrimSpace(string(parts[1]))
		if k != "" {
			headers[k] = v
		}
	}
	return headers
}

// HeaderSummary returns deterministic small header previews for logging/debug.
func HeaderSummary(headers map[string]string, max int) string {
	if len(headers) == 0 || max <= 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > max {
		keys = keys[:max]
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+headers[k])
	}
	return strings.Join(parts, ";")
}

// parseTLSSNI extracts server_name from a TLS ClientHello without decrypting traffic.
func parseTLSSNI(buf []byte) (string, bool) {
	if len(buf) < 5 {
		return "", false
	}
	if buf[0] != 0x16 {
		return "", false
	}
	recordLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if 5+recordLen > len(buf) {
		return "", false
	}
	hs := buf[5 : 5+recordLen]
	if len(hs) < 42 || hs[0] != 0x01 {
		return "", false
	}
	idx := 4 + 2 + 32
	if idx >= len(hs) {
		return "", false
	}
	sidLen := int(hs[idx])
	idx += 1 + sidLen
	if idx+2 > len(hs) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(hs[idx : idx+2]))
	idx += 2 + csLen
	if idx >= len(hs) {
		return "", false
	}
	compLen := int(hs[idx])
	idx += 1 + compLen
	if idx+2 > len(hs) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(hs[idx : idx+2]))
	idx += 2
	end := idx + extLen
	if end > len(hs) {
		return "", false
	}

	for idx+4 <= end {
		extType := binary.BigEndian.Uint16(hs[idx : idx+2])
		extSize := int(binary.BigEndian.Uint16(hs[idx+2 : idx+4]))
		idx += 4
		if idx+extSize > end {
			return "", false
		}
		if extType == 0x0000 {
			extData := hs[idx : idx+extSize]
			if len(extData) < 5 {
				return "", false
			}
			listLen := int(binary.BigEndian.Uint16(extData[0:2]))
			if listLen+2 > len(extData) {
				return "", false
			}
			p := 2
			for p+3 <= 2+listLen {
				nameType := extData[p]
				nameLen := int(binary.BigEndian.Uint16(extData[p+1 : p+3]))
				p += 3
				if p+nameLen > len(extData) {
					return "", false
				}
				if nameType == 0 {
					return strings.ToLower(string(extData[p : p+nameLen])), true
				}
				p += nameLen
			}
		}
		idx += extSize
	}
	return "", false
}
