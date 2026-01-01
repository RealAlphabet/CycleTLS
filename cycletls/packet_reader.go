package cycletls

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxStringLen définit la taille maximale autorisée pour une chaîne.
// Cela protège contre les paquets malformés ou malveillants.
const MaxStringLen = 4096

// ErrStringTooLarge est retournée lorsque la taille d'une chaîne dépasse MaxStringLen.
var ErrStringTooLarge = errors.New("packet: string length exceeds limit")
var ErrNegativeLength = errors.New("packet: negative length")

// Reader permet de lire séquentiellement des valeurs typées depuis un buffer binaire.
//
// IMPORTANT :
//   - Reader N'EST PAS thread-safe.
//   - Il doit être utilisé par UNE SEULE goroutine à la fois.
//   - Toute utilisation concurrente provoquera des data races.
//
// Reader ne modifie jamais le buffer sous-jacent, mais conserve un index interne mutable.
type Reader struct {
	data []byte
	pos  int
}

// NewReader crée un Reader positionné au début du buffer.
//
// Le buffer passé n'est PAS copié :
//   - il doit rester valide pendant toute la durée d'utilisation du Reader
//   - il ne doit pas être modifié pendant la lecture
func NewReader(data []byte) *Reader {
	return &Reader{data: data}
}

// Remaining retourne le nombre d'octets encore lisibles.
func (r *Reader) Remaining() int {
	return len(r.data) - r.pos
}

// ReadU16 lit un entier non signé 16 bits en big-endian.
func (r *Reader) ReadU16() (uint16, error) {
	const size = 2

	if (r.pos + size) > len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}

	v := binary.BigEndian.Uint16(r.data[r.pos : r.pos+size])
	r.pos += size
	return v, nil
}

// ReadU32 lit un entier non signé 32 bits en big-endian.
func (r *Reader) ReadU32() (uint32, error) {
	const size = 4

	if (r.pos + size) > len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}

	v := binary.BigEndian.Uint32(r.data[r.pos : r.pos+size])
	r.pos += size
	return v, nil
}

// ReadString lit une chaîne encodée sous la forme :
//
//	uint16 length (big-endian)
//	followed by <length> bytes
//
// La chaîne retournée est COPIÉE et ne référence pas le buffer interne.
//
// Erreurs possibles :
//   - io.ErrUnexpectedEOF
//   - ErrStringTooLarge
func (r *Reader) ReadString() (string, error) {
	length, err := r.ReadU16()
	if err != nil {
		return "", err
	}

	if length > MaxStringLen {
		return "", ErrStringTooLarge
	}

	n := int(length)

	if n == 0 {
		return "", nil
	}

	if (r.pos + n) > len(r.data) {
		return "", io.ErrUnexpectedEOF
	}

	s := string(r.data[r.pos : r.pos+n])
	r.pos += n
	return s, nil
}

// ReadBytes lit n octets et retourne une COPIE du buffer.
//
// Cette méthode permet d'éviter des conversions inutiles en string.
func (r *Reader) ReadBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeLength
	}

	if n == 0 {
		return []byte{}, nil
	}

	if (r.pos + n) > len(r.data) {
		return nil, io.ErrUnexpectedEOF
	}

	out := make([]byte, n)
	copy(out, r.data[r.pos:r.pos+n])
	r.pos += n
	return out, nil
}

// -----------------------------------------------------------------------------
// Message parsing
// -----------------------------------------------------------------------------

func parseInitMessage(data []byte) (cycleTLSRequest, uint32, error) {
	r := NewReader(data)

	requestID, err := r.ReadString()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	method, err := r.ReadString()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}
	if method != "init" {
		return cycleTLSRequest{}, 0, fmt.Errorf("unexpected method %q", method)
	}

	initialWindow, err := r.ReadU32()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	optionsJSON, err := r.ReadString()
	if err != nil {
		return cycleTLSRequest{}, 0, err
	}

	var opts Options
	if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
		return cycleTLSRequest{}, 0, err
	}

	return cycleTLSRequest{
		RequestID: requestID,
		Options:   opts,
	}, initialWindow, nil
}

func parseCreditMessage(data []byte) (string, uint32, error) {
	r := NewReader(data)

	requestID, err := r.ReadString()
	if err != nil {
		return "", 0, err
	}

	method, err := r.ReadString()
	if err != nil {
		return "", 0, err
	}
	if method != "credit" {
		return "", 0, fmt.Errorf("unexpected method %q", method)
	}

	credits, err := r.ReadU32()
	if err != nil {
		return "", 0, err
	}

	return requestID, credits, nil
}
