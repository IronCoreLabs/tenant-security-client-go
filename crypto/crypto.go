package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/IronCoreLabs/tenant-security-client-go/icl_proto"
	"google.golang.org/protobuf/proto"
)

const (
	DOCUMENT_HEADER_META_LENGTH int = 7
	/** Max IronCore header size. Equals 2^16 - 1 since we do a 2 byte size. */
	MAX_HEADER_SIZE int = 65535
	NONCE_LEN       int = 12
	TAG_LEN         int = 16
	KEY_LEN         int = 32
)

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	nonce := make([]byte, NONCE_LEN)
	// Fill the nonce using a cryptographically secure random number generator
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	return EncryptWithNonce(plaintext, key, nonce)
}

func EncryptWithNonce(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != KEY_LEN {
		return nil, fmt.Errorf("encryption key was %d bytes, expected %d", len(key), KEY_LEN)
	}
	if len(nonce) != NONCE_LEN {
		return nil, errors.New("the nonce passed was not the correct length")
	}
	// generate a new aes cipher using our 32 byte long key
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func EncryptDocument(document []byte, tenantId string, dek []byte) ([]byte, error) {
	header, err := GenerateHeader(dek, tenantId)
	if err != nil {
		return nil, err
	}
	encrypted, err := Encrypt(document, dek)
	if err != nil {
		return nil, err
	}
	return append(header, encrypted...), nil
}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != KEY_LEN {
		return nil, fmt.Errorf("encryption key was %d bytes, expected %d", len(key), KEY_LEN)
	}
	if len(ciphertext) <= NONCE_LEN+TAG_LEN {
		return nil, errors.New("the ciphertext was not well formed")
	}

	nonce := ciphertext[:NONCE_LEN]
	ciphertextAndTag := ciphertext[NONCE_LEN:]
	c, _ := aes.NewCipher(key) // Can't error as we already verified key length
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}
	return plaintext, nil
}

func DecryptDocument(document []byte, dek []byte) ([]byte, error) {
	documentParts, err := SplitDocument(document)
	if err != nil {
		return nil, err
	}
	headerBytes := documentParts.header
	documentHeader := icl_proto.V3DocumentHeader{}
	err = proto.Unmarshal(headerBytes, &documentHeader)
	if err != nil {
		return nil, err
	}
	ciphertext := documentParts.ciphertext
	if !VerifySignature(dek, &documentHeader) {
		return nil, errors.New("the signature computed did not match. The document key is likely incorrect")
	}
	return Decrypt(ciphertext, dek)
}

func GenerateSignature(dek []byte, nonce []byte, header *icl_proto.SaaSShieldHeader) (V3HeaderSignature, error) {
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return V3HeaderSignature{nil, nil}, err // TODO: what should left side be?
	}
	encryptedHeaderValue, err := EncryptWithNonce(headerBytes, dek, nonce)
	if err != nil {
		return V3HeaderSignature{nil, nil}, err // TODO: what should left side be?
	}
	encryptedHeaderLength := len(encryptedHeaderValue)
	tag := encryptedHeaderValue[encryptedHeaderLength-TAG_LEN:]
	return V3HeaderSignature{tag, nonce}, nil
}

func CreateHeaderProto(dek []byte, tenantId string, nonce []byte) (*icl_proto.V3DocumentHeader, error) {
	saasHeader := icl_proto.SaaSShieldHeader{}
	saasHeader.TenantId = tenantId
	signature, err := GenerateSignature(dek, nonce, &saasHeader)
	if err != nil {
		return &icl_proto.V3DocumentHeader{}, err // TODO: what should left side be?
	}
	v3Header := icl_proto.V3DocumentHeader{}
	v3Header.Sig = signature.GetBytes()
	v3Header.Header = &icl_proto.V3DocumentHeader_SaasShield{SaasShield: &saasHeader}
	return &v3Header, nil // TODO: mad about mutex if it's not a pointer. Is this wrong?
}

func GenerateHeader(dek []byte, tenantId string) ([]byte, error) {
	nonce := make([]byte, NONCE_LEN)
	// Fill the nonce using a cryptographically secure random number generator
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	headerProto, err := CreateHeaderProto(dek, tenantId, nonce)
	if err != nil {
		return nil, err
	}
	headerBytes, err := proto.Marshal(headerProto)
	if err != nil {
		return nil, err
	}
	headerLength := len(headerBytes)
	if headerLength > MAX_HEADER_SIZE {
		return nil, fmt.Errorf("the header is too large. It is %d bytes long", headerLength)
	}
	headerSize := make([]byte, 2)
	binary.BigEndian.PutUint16(headerSize, uint16(headerLength))
	documentVersion := getCurrentDocumentHeaderVersion()
	return append([]byte{documentVersion}, append(getDocumentMagic(), append(headerSize, headerBytes...)...)...), nil
}

func VerifySignature(dek []byte, header *icl_proto.V3DocumentHeader) bool {
	if header.GetSaasShield() == nil {
		return false
	}
	headerSig := header.Sig
	knownSig, err := NewV3HeaderSignature(headerSig)
	if err != nil {
		return false
	}
	candidateSig, err := GenerateSignature(dek, knownSig.nonce, header.GetSaasShield())
	if err != nil {
		return false
	}
	return bytes.Equal(candidateSig.tag, knownSig.tag)
}

func VerifyPreamble(preamble []byte) bool {
	return len(preamble) == DOCUMENT_HEADER_META_LENGTH &&
		preamble[0] == getCurrentDocumentHeaderVersion() &&
		containsIroncoreMagic(preamble) &&
		getHeaderSize(preamble) >= 0
}

func SplitDocument(document []byte) (DocumentParts, error) {
	fixedPreamble := document[0:DOCUMENT_HEADER_META_LENGTH]
	if !VerifyPreamble(fixedPreamble) {
		return DocumentParts{}, errors.New("provided bytes were not an IronCore encrypted document")
	}
	headerLength := getHeaderSize(fixedPreamble)
	headerEnd := DOCUMENT_HEADER_META_LENGTH + headerLength
	header := document[DOCUMENT_HEADER_META_LENGTH:headerEnd]
	ciphertext := document[headerEnd:]
	return DocumentParts{preamble: fixedPreamble, header: header, ciphertext: ciphertext}, nil

}

func getDocumentMagic() []byte {
	return []byte("IRON")
}

func containsIroncoreMagic(headerBytes []byte) bool {
	return bytes.Equal(headerBytes[1:5], getDocumentMagic())
}

func getHeaderSize(preamble []byte) int {
	headerSizeBytes := preamble[5:7]
	return int(binary.BigEndian.Uint16(headerSizeBytes))
}

func getCurrentDocumentHeaderVersion() byte {
	return byte(3)
}

type V3HeaderSignature struct {
	tag   []byte
	nonce []byte
}

func (s *V3HeaderSignature) GetBytes() []byte {
	return append(s.nonce, s.tag...)
}

func NewV3HeaderSignature(bytes []byte) (V3HeaderSignature, error) {
	if len(bytes) != NONCE_LEN+TAG_LEN {
		return V3HeaderSignature{nil, nil}, errors.New("bytes were not a V3HeaderSignature because they were not the correct length")
	}
	return V3HeaderSignature{nonce: bytes[0:NONCE_LEN], tag: bytes[NONCE_LEN : NONCE_LEN+TAG_LEN]}, nil
}

type DocumentParts struct {
	preamble   []byte
	header     []byte
	ciphertext []byte
}
