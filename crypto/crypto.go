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

func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return EncryptWithNonce(plaintext, key, nonce)
}

func EncryptWithNonce(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != nonceLen {
		return nil, errors.New("the nonce passed was not the correct length")
	}
	gcm, err := createGcm(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func EncryptDocument(document []byte, tenantID string, dek []byte) ([]byte, error) {
	header, err := GenerateHeader(dek, tenantID)
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

func GenerateSignature(dek []byte, nonce []byte, header *icl_proto.SaaSShieldHeader) (*V3HeaderSignature, error) {
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return nil, err
	}
	encryptedHeaderValue, err := EncryptWithNonce(headerBytes, dek, nonce)
	if err != nil {
		return nil, err
	}
	encryptedHeaderLength := len(encryptedHeaderValue)
	tag := encryptedHeaderValue[encryptedHeaderLength-tagLen:]
	return &V3HeaderSignature{tag, nonce}, nil
}

func CreateHeaderProto(dek []byte, tenantID string, nonce []byte) (*icl_proto.V3DocumentHeader, error) {
	saasHeader := icl_proto.SaaSShieldHeader{}
	saasHeader.TenantId = tenantID
	signature, err := GenerateSignature(dek, nonce, &saasHeader)
	if err != nil {
		return nil, err
	}
	v3Header := icl_proto.V3DocumentHeader{}
	v3Header.Sig = signature.GetBytes()
	v3Header.Header = &icl_proto.V3DocumentHeader_SaasShield{SaasShield: &saasHeader}
	return &v3Header, nil
}

func GenerateHeader(dek []byte, tenantID string) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	headerProto, err := CreateHeaderProto(dek, tenantID, nonce)
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

	header := make([]byte, 0, 1+4+len(headerSize)+headerLength)
	header = append(header, documentVersion)
	header = append(header, getDocumentMagic()...)
	header = append(header, headerSize...)
	header = append(header, headerBytes...)

	return header, nil
}

func VerifySignature(dek []byte, header *icl_proto.V3DocumentHeader) bool {
	if header.GetSaasShield() == nil {
		return false
	}
	headerSig := header.Sig
	candidateSig, err := NewV3HeaderSignature(headerSig)
	if err != nil {
		return false
	}
	generatedSign, err := GenerateSignature(dek, candidateSig.nonce, header.GetSaasShield())
	if err != nil {
		return false
	}
	return bytes.Equal(generatedSign.tag, candidateSig.tag)
}

func VerifyPreamble(preamble []byte) bool {
	return len(preamble) == documentHeaderMetaLength &&
		preamble[0] == getCurrentDocumentHeaderVersion() &&
		containsIroncoreMagic(preamble) &&
		getHeaderSize(preamble) >= 0
}

func SplitDocument(document []byte) (*DocumentParts, error) {
	fixedPreamble := document[0:documentHeaderMetaLength]
	if !VerifyPreamble(fixedPreamble) {
		return nil, errors.New("provided bytes were not an IronCore encrypted document")
	}
	headerLength := getHeaderSize(fixedPreamble)
	headerEnd := documentHeaderMetaLength + headerLength
	header := document[documentHeaderMetaLength:headerEnd]
	ciphertext := document[headerEnd:]
	return &DocumentParts{preamble: fixedPreamble, header: header, ciphertext: ciphertext}, nil

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

type V3HeaderSignature struct {
	tag   []byte
	nonce []byte
}

func (s *V3HeaderSignature) GetBytes() []byte {
	return append(s.nonce, s.tag...)
}

func NewV3HeaderSignature(bytes []byte) (*V3HeaderSignature, error) {
	if len(bytes) != nonceLen+tagLen {
		return nil, fmt.Errorf("bytes were not a V3HeaderSignature because their length was %d, not %d", len(bytes), nonceLen+tagLen)
	}
	return &V3HeaderSignature{nonce: bytes[0:nonceLen], tag: bytes[nonceLen : nonceLen+tagLen]}, nil
}

type DocumentParts struct {
	preamble   []byte
	header     []byte
	ciphertext []byte
}
