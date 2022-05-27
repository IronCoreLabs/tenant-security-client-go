package tsc

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
	documentHeaderMetaLength int = 7
	/** Max IronCore header size. Equals 2^16 - 1 since we do a 2 byte size. */
	maxHeaderSize = 65535
	nonceLen      = 12
	tagLen        = 16
	keyLen        = 32
	magicLen      = 4
)

func createGcm(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("encryption key was %d bytes, expected %d", len(key), keyLen)
	}
	c, _ := aes.NewCipher(key) // Can't error as we already verified key length
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	return gcm, nil
}

func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceLen)
	// Fill the nonce using a cryptographically secure random number generator
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return encryptWithNonce(plaintext, key, nonce)
}

func encryptWithNonce(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != nonceLen {
		return nil, errors.New("the nonce passed was not the correct length")
	}
	gcm, err := createGcm(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func encryptDocument(document []byte, tenantID string, dek []byte) ([]byte, error) {
	header, err := generateHeader(dek, tenantID)
	if err != nil {
		return nil, err
	}
	encrypted, err := encrypt(document, dek)
	if err != nil {
		return nil, err
	}
	return append(header, encrypted...), nil
}

func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) <= nonceLen+tagLen {
		return nil, errors.New("the ciphertext was not well formed")
	}
	gcm, err := createGcm(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:nonceLen]
	ciphertextAndTag := ciphertext[nonceLen:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, fmt.Errorf("AES decryption failed: %w", err)
	}
	return plaintext, nil
}

func decryptDocument(document []byte, dek []byte) ([]byte, error) {
	documentParts, err := splitDocument(document)
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
	if !verifySignature(dek, &documentHeader) {
		return nil, errors.New("the signature computed did not match. The document key is likely incorrect")
	}
	return decrypt(ciphertext, dek)
}

func generateSignature(dek []byte, nonce []byte, header *icl_proto.SaaSShieldHeader) (*v3HeaderSignature, error) {
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return nil, err
	}
	encryptedHeaderValue, err := encryptWithNonce(headerBytes, dek, nonce)
	if err != nil {
		return nil, err
	}
	encryptedHeaderLength := len(encryptedHeaderValue)
	tag := encryptedHeaderValue[encryptedHeaderLength-tagLen:]
	return &v3HeaderSignature{tag, nonce}, nil
}

func createHeaderProto(dek []byte, tenantID string, nonce []byte) (*icl_proto.V3DocumentHeader, error) {
	saasHeader := icl_proto.SaaSShieldHeader{}
	saasHeader.TenantId = tenantID
	signature, err := generateSignature(dek, nonce, &saasHeader)
	if err != nil {
		return nil, err
	}
	v3Header := icl_proto.V3DocumentHeader{}
	v3Header.Sig = signature.GetBytes()
	v3Header.Header = &icl_proto.V3DocumentHeader_SaasShield{SaasShield: &saasHeader}
	return &v3Header, nil
}

func generateHeader(dek []byte, tenantID string) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	headerProto, err := createHeaderProto(dek, tenantID, nonce)
	if err != nil {
		return nil, err
	}
	headerBytes, err := proto.Marshal(headerProto)
	if err != nil {
		return nil, err
	}
	headerLength := len(headerBytes)
	if headerLength > maxHeaderSize {
		return nil, fmt.Errorf("the header is too large. It is %d bytes long", headerLength)
	}
	headerSize := make([]byte, 2)
	binary.BigEndian.PutUint16(headerSize, uint16(headerLength))
	documentVersion := getCurrentDocumentHeaderVersion()

	header := make([]byte, 0, 1+magicLen+len(headerSize)+headerLength)
	header = append(header, documentVersion)
	header = append(header, getDocumentMagic()...)
	header = append(header, headerSize...)
	header = append(header, headerBytes...)

	return header, nil
}

func verifySignature(dek []byte, header *icl_proto.V3DocumentHeader) bool {
	if header.GetSaasShield() == nil {
		return false
	}
	headerSig := header.Sig
	candidateSig, err := newV3HeaderSignature(headerSig)
	if err != nil {
		return false
	}
	generatedSign, err := generateSignature(dek, candidateSig.nonce, header.GetSaasShield())
	if err != nil {
		return false
	}
	return bytes.Equal(generatedSign.tag, candidateSig.tag)
}

func verifyPreamble(preamble []byte) bool {
	return len(preamble) == documentHeaderMetaLength &&
		preamble[0] == getCurrentDocumentHeaderVersion() &&
		containsIroncoreMagic(preamble) &&
		getHeaderSize(preamble) >= 0
}

func splitDocument(document []byte) (*documentParts, error) {
	fixedPreamble := document[0:documentHeaderMetaLength]
	if !verifyPreamble(fixedPreamble) {
		return nil, errors.New("provided bytes were not an IronCore encrypted document")
	}
	headerLength := getHeaderSize(fixedPreamble)
	headerEnd := documentHeaderMetaLength + headerLength
	header := document[documentHeaderMetaLength:headerEnd]
	ciphertext := document[headerEnd:]
	return &documentParts{preamble: fixedPreamble, header: header, ciphertext: ciphertext}, nil

}

func getDocumentMagic() []byte {
	// magicLen must match the length of this.
	return []byte("IRON")
}

func containsIroncoreMagic(headerBytes []byte) bool {
	// Length should be verified by the first check in `VerifyPreamble`
	return bytes.Equal(headerBytes[1:5], getDocumentMagic())
}

func getHeaderSize(preamble []byte) int {
	headerSizeBytes := preamble[5:7]
	return int(binary.BigEndian.Uint16(headerSizeBytes))
}

func getCurrentDocumentHeaderVersion() byte {
	return byte(3)
}

type v3HeaderSignature struct {
	tag   []byte
	nonce []byte
}

func (s *v3HeaderSignature) GetBytes() []byte {
	return append(s.nonce, s.tag...)
}

func newV3HeaderSignature(bytes []byte) (*v3HeaderSignature, error) {
	if len(bytes) != nonceLen+tagLen {
		return nil, fmt.Errorf("bytes were not a V3HeaderSignature because their length was %d, not %d", len(bytes), nonceLen+tagLen)
	}
	return &v3HeaderSignature{nonce: bytes[0:nonceLen], tag: bytes[nonceLen : nonceLen+tagLen]}, nil
}

type documentParts struct {
	preamble   []byte
	header     []byte
	ciphertext []byte
}
