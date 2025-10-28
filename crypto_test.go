package tsc

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/IronCoreLabs/tenant-security-client-go/icl_proto"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

// These values come from tenant-security-client-php for easy cross-SDK testing.
//
//nolint:lll
const knownGoodEncryptedValueHexString string = "0349524f4e016c0a1c3130eaf8ff88c1a08df550095522aebfdc7b0d060d3adad8836fea7e1acb020ac80274656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e744964bb54218111033f5c68c92feb8fae88c255cc56e902becdfde679defa2628950beb966e0e43d27f42dcdbd98587e8bf5f8458411760fb72ca4442ae79877da90dff7de6df43e549df3085aae5f55f05aa37cdd045ffa7"
const knownDekString string = "3939393939393939393939393939393939393939393939393939393939393939"
const knownDekString2 string = "3838383838383838383838383838383838383838383838383838383838383838"

var knownGoodEncryptedValueHex []byte
var knownDek []byte
var knownDek2 []byte

func init() {
	knownGoodEncryptedValueHex, _ = hex.DecodeString(knownGoodEncryptedValueHexString)
	knownDek, _ = hex.DecodeString(knownDekString)
	knownDek2, _ = hex.DecodeString(knownDekString2)
}

func generateDek() []byte {
	dek := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, dek)
	return dek
}

func TestCryptoEncryptDecryptRoundtrip(t *testing.T) {
	dek := generateDek()
	plaintext := []byte("This is a non base64 string.")
	encryptResult, _ := encrypt(plaintext, dek)
	decryptResult, _ := decrypt(encryptResult, dek)
	assert.Equal(t, plaintext, decryptResult)
}

func TestSignVerify(t *testing.T) {
	dek := generateDek()
	nonce, _ := generateNonce()
	proto, _ := createHeaderProto(dek, "This is my tenant ID", nonce)
	assert.True(t, verifySignature(dek, proto))
}

func TestDecryptingKnownEncryptedValue(t *testing.T) {
	encryptedDocument, _ := hex.DecodeString(knownGoodEncryptedValueHexString)
	decryptedBytes, _ := decryptDocumentBytes(encryptedDocument, knownDek)
	assert.Equal(t, string(decryptedBytes), "I have a fever and the only cure is nine nine nine nine...")
}

func TestKnownHeaderProtoFromJava(t *testing.T) {
	dek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	nonce, _ := hex.DecodeString("3171EF3C899F875E595C2213")
	expectedHexResult :=
		strings.ToLower("0A1C3171EF3C899F875E595C2213CACF9287C78CF196458CD690544980C71A0A0A0874656E616E744964")
	result, _ := createHeaderProto(dek, "tenantId", nonce)
	resultBytes, _ := proto.Marshal(result)
	assert.Equal(t, hex.EncodeToString(resultBytes), expectedHexResult)
}

// This is a known encrypted value with the last byte changed.
func TestDecryptingBadTag(t *testing.T) {
	hexString := knownGoodEncryptedValueHexString[0:len(knownGoodEncryptedValueHexString)-2] + "00"
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := decryptDocumentBytes(encryptedDocument, knownDek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "AES decryption failed")
}

// This is an incorrect preamble.
func TestDecryptInvalidDocument(t *testing.T) {
	hexString := "00000000000000"
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := decryptDocumentBytes(encryptedDocument, knownDek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

// This is an incorrect preamble.
func TestDecryptInvalidDocumentIncorrectLength(t *testing.T) {
	hexString := "00000000000100" // Length of 256
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := decryptDocumentBytes(encryptedDocument, knownDek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

// This is too short to have a preamble.
func TestDecryptInvalidDocumentTooShort(t *testing.T) {
	hexString := "00"
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := decryptDocumentBytes(encryptedDocument, knownDek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

func TestVerifyWithWrongDek(t *testing.T) {
	nonce, _ := generateNonce()
	header, _ := createHeaderProto(knownDek, "tenant", nonce)
	assert.False(t, verifySignature(knownDek2, header))
}

func TestDecryptDocumentWithCorruptHeader(t *testing.T) {
	corruptDocument, _ := hex.DecodeString(strings.Replace(knownGoodEncryptedValueHexString, "f4e016c0", "00000000", 1))
	_, err := decryptDocumentBytes(corruptDocument, knownDek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

func TestEncryptWithBadNonce(t *testing.T) {
	plaintext := []byte("This is a non base64 string.")
	dek := generateDek()
	badNonce := []byte("foobar")
	_, err := encryptWithNonce(plaintext, dek, badNonce)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "the nonce passed had length")
}

func TestDecryptTooShort(t *testing.T) {
	badCiphertext := []byte("foo")
	dek := generateDek()
	_, err := decrypt(badCiphertext, dek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "ciphertext is too short")
}

func TestDecryptDocumentWithIncorrectHeaderLengthInPreamble(t *testing.T) {
	dek := generateDek()
	document := []byte("bytes")
	tenantID := "tenant"
	encrypted, _ := encryptDocumentBytes(document, tenantID, dek)
	encrypted[5], encrypted[6] = 0xFF, 0xFF // indicated header length much greater than document
	_, err := decryptDocumentBytes(encrypted, dek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

func TestRoundtripDocumentBytes(t *testing.T) {
	dek := generateDek()
	document := []byte("bytes")
	tenantID := "tenant"
	encrypted, _ := encryptDocumentBytes(document, tenantID, dek)
	decrypted, _ := decryptDocumentBytes(encrypted, dek)
	assert.Equal(t, decrypted, document)
}

func TestDoubleEncrypt(t *testing.T) {
	dek := generateDek()
	document := []byte("bytes")
	tenantID := "thisTenant"
	encrypted, _ := encryptDocumentBytes(document, tenantID, dek)
	_, err := encryptDocumentBytes(encrypted, tenantID, dek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "already IronCore encrypted")
}

func TestDecryptBadDocument(t *testing.T) {
	dek := generateDek()
	document := []byte("bytes")
	tenantID := "tenant"
	encrypted, _ := encryptDocumentBytes(document, tenantID, dek)
	badDek := []byte("bar")
	_, err := decryptDocumentBytes(encrypted, badDek)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "the signature computed did not match; the document key is likely incorrect")
}

func TestGenerateHeaderTooLarge(t *testing.T) {
	dek := generateDek()
	tenantID := strings.Repeat("g", 100000)
	_, err := generateHeader(dek, tenantID)
	assert.ErrorIs(t, err, ErrKindCrypto)
	assert.ErrorContains(t, err, "header size")
}

func TestVerifyWrongHeader(t *testing.T) {
	// No SaasShieldHeader set
	header := icl_proto.V3DocumentHeader{}
	verify := verifySignature([]byte("dek"), &header)
	assert.False(t, verify)
}
