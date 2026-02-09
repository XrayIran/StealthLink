//go:build cgo && rustcrypto

package ffi

/*
#cgo linux LDFLAGS: -L${SRCDIR}/../../../rust/stealthlink-crypto/target/release -lstealthlink_crypto
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t* ptr;
    size_t len;
} Buffer;

extern Buffer sl_xchacha_encrypt(const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* aad, size_t aad_len,
    char** err_out);
extern Buffer sl_xchacha_decrypt(const uint8_t* key, size_t key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* aad, size_t aad_len,
    char** err_out);
extern Buffer sl_salamander_xor(const uint8_t* input, size_t input_len,
    const uint8_t* key, size_t key_len,
    uint64_t nonce, char** err_out);
extern Buffer sl_build_packet(uint8_t version, uint8_t flags, uint32_t flow_id, uint32_t seq,
    const uint8_t* payload, size_t payload_len, char** err_out);
extern int sl_parse_packet_header(const uint8_t* input, size_t input_len,
    uint8_t* version_out, uint8_t* flags_out, uint32_t* flow_id_out, uint32_t* seq_out,
    uint32_t* payload_offset_out, uint32_t* payload_len_out, char** err_out);
extern void sl_free_buffer(Buffer buf);
extern void sl_last_error_free(char* err);
*/
import "C"

import (
	"errors"
	"unsafe"
)

func Enabled() bool { return true }

func callErr(e *C.char) error {
	if e == nil {
		return nil
	}
	msg := C.GoString(e)
	C.sl_last_error_free(e)
	return errors.New(msg)
}

func takeBuf(buf C.Buffer) []byte {
	if buf.ptr == nil || buf.len == 0 {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(buf.ptr), C.int(buf.len))
	C.sl_free_buffer(buf)
	return out
}

func XChaChaEncrypt(key, nonce, plaintext, aad []byte) ([]byte, error) {
	var errPtr *C.char
	buf := C.sl_xchacha_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])), C.size_t(len(nonce)),
		(*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.size_t(len(plaintext)),
		ptrOrNil(aad), C.size_t(len(aad)),
		&errPtr,
	)
	if err := callErr(errPtr); err != nil {
		return nil, err
	}
	return takeBuf(buf), nil
}

func XChaChaDecrypt(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	var errPtr *C.char
	buf := C.sl_xchacha_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])), C.size_t(len(nonce)),
		(*C.uint8_t)(unsafe.Pointer(&ciphertext[0])), C.size_t(len(ciphertext)),
		ptrOrNil(aad), C.size_t(len(aad)),
		&errPtr,
	)
	if err := callErr(errPtr); err != nil {
		return nil, err
	}
	return takeBuf(buf), nil
}

func SalamanderXOR(input, key []byte, nonce uint64) ([]byte, error) {
	var errPtr *C.char
	buf := C.sl_salamander_xor(
		(*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		C.uint64_t(nonce), &errPtr,
	)
	if err := callErr(errPtr); err != nil {
		return nil, err
	}
	return takeBuf(buf), nil
}

func BuildPacket(version, flags uint8, flowID, seq uint32, payload []byte) ([]byte, error) {
	var errPtr *C.char
	buf := C.sl_build_packet(
		C.uint8_t(version), C.uint8_t(flags), C.uint32_t(flowID), C.uint32_t(seq),
		(*C.uint8_t)(unsafe.Pointer(&payload[0])), C.size_t(len(payload)), &errPtr,
	)
	if err := callErr(errPtr); err != nil {
		return nil, err
	}
	return takeBuf(buf), nil
}

func ParsePacketHeader(pkt []byte) (version, flags uint8, flowID, seq uint32, payloadOffset, payloadLen uint32, err error) {
	var errPtr *C.char
	var v C.uint8_t
	var f C.uint8_t
	var flow C.uint32_t
	var s C.uint32_t
	var off C.uint32_t
	var plen C.uint32_t

	rc := C.sl_parse_packet_header(
		(*C.uint8_t)(unsafe.Pointer(&pkt[0])), C.size_t(len(pkt)),
		&v, &f, &flow, &s, &off, &plen, &errPtr,
	)
	if rc != 0 {
		err = callErr(errPtr)
		return
	}
	version = uint8(v)
	flags = uint8(f)
	flowID = uint32(flow)
	seq = uint32(s)
	payloadOffset = uint32(off)
	payloadLen = uint32(plen)
	return
}

func ptrOrNil(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
