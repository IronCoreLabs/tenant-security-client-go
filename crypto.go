package tsc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/IronCoreLabs/tenant-security-client-go/icl_proto"
	"google.golang.org/protobuf/proto"
)

const (
	documentHeaderMetaLength int = 7
	maxHeaderSize            int = 65535 // Max IronCore header size. Equals 2^16 - 1 since we do a 2 byte size.
	nonceLen                 int = 12
	tagLen                   int = 16
	keyLen                   int = 32
	magicLen                 int = 4 // Length of magic header string "IRON"
	headerSizeLen            int = 2 // short the header size is encoded into
	documentHeaderVersion    int = 3
)

// createGcm creates the GCM cipher needed for encryption/decryption. Checks to make sure the provided
// key is the correct length.
func createGcm(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, makeErrorf(errorKindCrypto, "encryption key was %d bytes, expected %d", len(key), keyLen)
	}
	c, _ := aes.NewCipher(key) // Can't error as we already verified key length.
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, makeErrorf(errorKindCrypto, "failed to create GCM: %w", err)
	}
	return gcm, nil
}

// generateNonce creates and fills a byte array (size `nonceLen`) with cryptographically-secure random numbers.
func generateNonce() ([]byte, error) {
	nonce := make([]byte, nonceLen)
	// Fill the nonce using a cryptographically secure random number generator.
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, makeErrorf(errorKindCrypto, "read crypto rand: %w", err)
	}
	return nonce, nil
}

// encrypt generates a nonce and uses it and the provided key to encrypt the provided plaintext.
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	return encryptWithNonce(plaintext, key, nonce)
}

// encryptWithNonce uses the provided nonce and key to encrypt the provided plaintext.
func encryptWithNonce(plaintext []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != nonceLen {
		return nil, makeErrorf(errorKindCrypto, "the nonce passed had length %d, expected %d", len(nonce), nonceLen)
	}
	gcm, err := createGcm(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// encryptDocumentBytes generates a header, encrypts the document, and returns the two appended together.
func encryptDocumentBytes(document []byte, tenantID string, dek []byte) ([]byte, error) {
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

// decrypt uses the provided key to decrypt the provided ciphertext.
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) <= nonceLen+tagLen {
		return nil, makeErrorf(errorKindCrypto, "ciphertext is too short (%d bytes) to be well formed", len(ciphertext))
	}
	gcm, err := createGcm(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:nonceLen]
	ciphertextAndTag := ciphertext[nonceLen:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		return nil, makeErrorf(errorKindCrypto, "AES decryption failed: %w", err)
	}
	return plaintext, nil
}

// decryptDocumentBytes splits the document into its prelude, header, and ciphertext, verifies
// the header's signature, and decrypts the ciphertext using the provided DEK.
func decryptDocumentBytes(document []byte, dek []byte) ([]byte, error) {
	documentParts, err := splitDocument(document)
	if err != nil {
		return nil, err
	}
	headerBytes := documentParts.header
	documentHeader := icl_proto.V3DocumentHeader{}
	err = proto.Unmarshal(headerBytes, &documentHeader)
	if err != nil {
		return nil, makeErrorf(errorKindCrypto, "unmarshal document header from protobuf: %w", err)
	}
	ciphertext := documentParts.ciphertext
	if !verifySignature(dek, &documentHeader) {
		return nil, makeErrorf(errorKindCrypto, "the signature computed did not match; the document key is likely incorrect")
	}
	return decrypt(ciphertext, dek)
}

// generateSignature encrypts the header with the provided DEK and nonce, then returns the signature
// composed of the encrypted value and the nonce.
func generateSignature(dek []byte, nonce []byte, header *icl_proto.SaaSShieldHeader) (*v3HeaderSignature, error) {
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return nil, makeErrorf(errorKindCrypto, "marshal document header to protobuf: %w", err)
	}
	encryptedHeaderValue, err := encryptWithNonce(headerBytes, dek, nonce)
	if err != nil {
		return nil, err
	}
	encryptedHeaderLength := len(encryptedHeaderValue)
	tag := encryptedHeaderValue[encryptedHeaderLength-tagLen:]
	return &v3HeaderSignature{tag, nonce}, nil
}

// createHeaderProto generates a SaasShield document header with the provided tenant ID
// and a generated signature.
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

// generateHeader forms the prelude with the header version, the magic IRON bytes, and
// the length of the header; it then appends the protobuf-encoded header bytes.
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
		return nil, makeErrorf(errorKindCrypto, "marshal document header to protobuf: %w", err)
	}
	headerLength := len(headerBytes)
	if headerLength > maxHeaderSize {
		return nil, makeErrorf(errorKindCrypto, "header size %d > max %d", headerLength, maxHeaderSize)
	}
	headerSize := make([]byte, headerSizeLen)
	binary.BigEndian.PutUint16(headerSize, uint16(headerLength))
	documentVersion := getCurrentDocumentHeaderVersion()

	header := make([]byte, 0, 1+magicLen+len(headerSize)+headerLength)
	header = append(header, documentVersion)
	header = append(header, getDocumentMagic()...)
	header = append(header, headerSize...)
	header = append(header, headerBytes...)

	return header, nil
}

// verifySignature generates a signature with the provided DEK and header and compares
// it to the header's signature.
func verifySignature(dek []byte, header *icl_proto.V3DocumentHeader) bool {
	if header.GetSaasShield() == nil {
		return false
	}
	headerSig := header.Sig
	candidateSig, err := newV3HeaderSignature(headerSig)
	if err != nil {
		return false
	}
	generatedSig, err := generateSignature(dek, candidateSig.nonce, header.GetSaasShield())
	if err != nil {
		return false
	}
	return bytes.Equal(generatedSig.tag, candidateSig.tag)
}

// verifyPreamble checks the provided preamble's length and form to ensure it came
// from an IronCore encrypted document header.
func verifyPreamble(preamble []byte) bool {
	return len(preamble) == documentHeaderMetaLength &&
		preamble[0] == getCurrentDocumentHeaderVersion() &&
		containsIroncoreMagic(preamble) &&
		getHeaderSize(preamble) >= 0
}

// splitDocument verifies the preamble and uses it to determine the header size, then
// separates the document into preamble, header, and ciphertext.
func splitDocument(document []byte) (*documentParts, error) {
	fixedPreamble := document[0:documentHeaderMetaLength]
	if !verifyPreamble(fixedPreamble) {
		return nil, makeErrorf(errorKindCrypto, "provided bytes were not an IronCore encrypted document")
	}
	headerLength := getHeaderSize(fixedPreamble)
	headerEnd := documentHeaderMetaLength + headerLength
	header := document[documentHeaderMetaLength:headerEnd]
	ciphertext := document[headerEnd:]
	return &documentParts{preamble: fixedPreamble, header: header, ciphertext: ciphertext}, nil
}

// getDocumentMagic returns the bytes corresponding to "IRON" that are included with
// every IronCore encrypted document.
func getDocumentMagic() []byte {
	// magicLen must match the length of this.
	return []byte("IRON")
}

// containsIroncoreMagic verifies that the bytes corresponding to "IRON" begin at index
// 1 of the provided bytes.
func containsIroncoreMagic(headerBytes []byte) bool {
	// Length should be verified by the first check in `VerifyPreamble`
	return bytes.Equal(headerBytes[1:5], getDocumentMagic())
}

// getHeaderSize translates the two bytes of the preamble corresponding to the
// header length into a big endian unsigned short.
func getHeaderSize(preamble []byte) int {
	headerSizeBytes := preamble[5:7]
	return int(binary.BigEndian.Uint16(headerSizeBytes))
}

// getCurrentDocumentHeaderVersion returns the version of the header that the
// TenantSecurityClient generates.
func getCurrentDocumentHeaderVersion() byte {
	return byte(documentHeaderVersion)
}

// v3HeaderSignature is the signature associated with v3 IronCore headers.
type v3HeaderSignature struct {
	tag   []byte
	nonce []byte
}

// GetBytes returns the concatenation of the nonce and tag.
func (s *v3HeaderSignature) GetBytes() []byte {
	return append(s.nonce, s.tag...)
}

// newV3HeaderSignature verifies that the length of the provided bytes and separates them
// into nonce and tag.
func newV3HeaderSignature(bytes []byte) (*v3HeaderSignature, error) {
	if len(bytes) != nonceLen+tagLen {
		return nil, makeErrorf(errorKindCrypto, "bytes were not a v3HeaderSignature because their length was %d, not %d",
			len(bytes), nonceLen+tagLen)
	}
	return &v3HeaderSignature{nonce: bytes[:nonceLen], tag: bytes[nonceLen:]}, nil
}

// documentParts contains the three parts of an IronCore encrypted document:
// preamble, header, and ciphertext.
type documentParts struct {
	preamble   []byte
	header     []byte
	ciphertext []byte
}
