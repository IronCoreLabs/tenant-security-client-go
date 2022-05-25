package crypto

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

// These values come from tenant-security-client-php for easy cross-SDK testing
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

func generateNonce() []byte {
	nonce := make([]byte, 12)
	_, _ = io.ReadFull(rand.Reader, nonce)
	return nonce
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	dek := generateDek()
	plaintext := []byte("This is a non base64 string.")
	encryptResult, _ := Encrypt(plaintext, dek)
	decryptResult, _ := Decrypt(encryptResult, dek)
	assert.Equal(t, plaintext, decryptResult)
}

func TestSignVerify(t *testing.T) {
	dek := generateDek()
	nonce := generateNonce()
	proto, _ := CreateHeaderProto(dek, "This is my tenant ID", nonce)
	assert.True(t, VerifySignature(dek, proto))
}

func TestDecryptingKnownEncryptedValue(t *testing.T) {
	encryptedDocument, _ := hex.DecodeString(knownGoodEncryptedValueHexString)
	decryptedBytes, _ := DecryptDocument(encryptedDocument, knownDek)
	assert.Equal(t, string(decryptedBytes), "I have a fever and the only cure is nine nine nine nine...")
}

func TestKnownHeaderProtoFromJava(t *testing.T) {
	dek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	nonce, _ := hex.DecodeString("3171EF3C899F875E595C2213")
	expectedHexResult := strings.ToLower("0A1C3171EF3C899F875E595C2213CACF9287C78CF196458CD690544980C71A0A0A0874656E616E744964")
	result, _ := CreateHeaderProto(dek, "tenantId", nonce)
	resultBytes, _ := proto.Marshal(result)
	assert.Equal(t, hex.EncodeToString(resultBytes), expectedHexResult)
}

// This is a known encrypted value with the last byte changed
func TestDecryptingBadTag(t *testing.T) {
	hexString := knownGoodEncryptedValueHexString[0:len(knownGoodEncryptedValueHexString)-2] + "00"
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := DecryptDocument(encryptedDocument, knownDek)
	assert.ErrorContains(t, err, "AES decryption failed")
}

// This is an incorrect preamble.
func TestDecryptInvalidDocument(t *testing.T) {
	hexString := "00000000000000"
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := DecryptDocument(encryptedDocument, knownDek)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

// This is an incorrect preamble.
func TestDecryptInvalidDocumentIncorrectLength(t *testing.T) {
	hexString := "00000000000100" //Length of 256
	encryptedDocument, _ := hex.DecodeString(hexString)
	_, err := DecryptDocument(encryptedDocument, knownDek)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

func TestVerifyWithWrongDek(t *testing.T) {
	nonce := generateNonce()
	header, _ := CreateHeaderProto(knownDek, "tenant", nonce)
	assert.False(t, VerifySignature(knownDek2, header))
}

func TestDecryptDocumentWithCorruptHeader(t *testing.T) {
	corruptDocument, _ := hex.DecodeString(strings.Replace(knownGoodEncryptedValueHexString, "f4e016c0", "00000000", 1))
	_, err := DecryptDocument(corruptDocument, knownDek)
	assert.ErrorContains(t, err, "provided bytes were not an IronCore encrypted document")
}

func TestEncryptWithBadNonce(t *testing.T) {
	plaintext := []byte("This is a non base64 string.")
	dek := generateDek()
	badNonce := []byte("foobar")
	_, err := EncryptWithNonce(plaintext, dek, badNonce)
	assert.ErrorContains(t, err, "the nonce passed was not the correct length")
}

func TestDecryptTooShort(t *testing.T) {
	badCiphertext := []byte("foo")
	dek := generateDek()
	_, err := Decrypt(badCiphertext, dek)
	assert.ErrorContains(t, err, "the ciphertext was not well formed")
}

func TestRoundtripDocument(t *testing.T) {
	dek := generateDek()
	document := []byte("bytes")
	tenantId := "tenant"
	encrypted, _ := EncryptDocument(document, tenantId, dek)
	decrypted, _ := DecryptDocument(encrypted, dek)
	assert.Equal(t, decrypted, document)
}

func TestDecryptBadDocument(t *testing.T) {
	dek := generateDek()
	document := []byte("bytes")
	tenantId := "tenant"
	encrypted, _ := EncryptDocument(document, tenantId, dek)
	badDek := []byte("bar")
	_, err := DecryptDocument(encrypted, badDek)
	assert.ErrorContains(t, err, "the signature computed did not match. The document key is likely incorrect")
}

func TestGenerateHeaderTooLarge(t *testing.T) {
	dek := generateDek()
	tenantId := strings.Repeat("g", 100000)
	_, err := GenerateHeader(dek, tenantId)
	assert.ErrorContains(t, err, "the header is too large")
}

func TestVerifyWrongHeader(t *testing.T) {
	// No SaasShieldHeader set
	header := icl_proto.V3DocumentHeader{}
	verify := VerifySignature([]byte("dek"), &header)
	assert.False(t, verify)
}
