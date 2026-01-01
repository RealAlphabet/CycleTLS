package cycletls

import (
	"bytes"
)

func writeStringWithLen(b *bytes.Buffer, s string) {
	l := len(s)
	b.WriteByte(byte(l >> 8))
	b.WriteByte(byte(l))
	b.WriteString(s)
}

func writeRequestAndMethod(b *bytes.Buffer, requestID, method string) {
	writeStringWithLen(b, requestID)
	writeStringWithLen(b, method)
}

func buildErrorFrame(requestID string, statusCode int, message string) []byte {
	var b bytes.Buffer
	writeRequestAndMethod(&b, requestID, "error")

	b.WriteByte(byte(statusCode >> 8))
	b.WriteByte(byte(statusCode))

	writeStringWithLen(&b, message)
	return b.Bytes()
}

func buildEndFrame(requestID string) []byte {
	var b bytes.Buffer
	writeRequestAndMethod(&b, requestID, "end")
	return b.Bytes()
}

func buildDataFrame(requestID string, body []byte) []byte {
	var b bytes.Buffer
	writeRequestAndMethod(&b, requestID, "data")

	length := len(body)
	b.WriteByte(byte(length >> 24))
	b.WriteByte(byte(length >> 16))
	b.WriteByte(byte(length >> 8))
	b.WriteByte(byte(length))
	b.Write(body)

	return b.Bytes()
}

func buildResponseFrame(requestID string, statusCode int, finalURL string, headers map[string][]string) []byte {
	var b bytes.Buffer
	writeRequestAndMethod(&b, requestID, "response")

	b.WriteByte(byte(statusCode >> 8))
	b.WriteByte(byte(statusCode))

	// final URL
	writeStringWithLen(&b, finalURL)

	// headers
	b.WriteByte(byte(len(headers) >> 8))
	b.WriteByte(byte(len(headers)))
	for name, values := range headers {
		writeStringWithLen(&b, name)
		b.WriteByte(byte(len(values) >> 8))
		b.WriteByte(byte(len(values)))
		for _, v := range values {
			writeStringWithLen(&b, v)
		}
	}

	return b.Bytes()
}
