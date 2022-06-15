package tsc

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The TSC keeps a limited number of tokens that allow workers to do CPU intensive tasks.
// This test makes sure we don't leak tokens.
func TestEncryptConcurrency(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	url, err := url.Parse("https://localhost:1234")
	if err != nil {
		t.Fatal(err)
	}
	tsc := NewTenantSecurityClient("unused", url, 2)

	tenantID := "unused tenant"
	mockDek := make([]byte, keyLen)
	// Fill the DEK using a cryptographically secure random number generator.
	_, err = io.ReadFull(rand.Reader, mockDek)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a document to encrypt.
	numFields := 100
	fieldLen := 10
	origDoc := make(map[string][]byte)
	for i := 0; i < numFields; i++ {
		fieldName := fmt.Sprintf("field%d", i)
		var fieldData []byte
		for j := 0; j < fieldLen; j++ {
			fieldData = append(fieldData, byte(i%256))
		}
		origDoc[fieldName] = fieldData
	}

	encFields, err := tsc.encryptDocument(ctx, origDoc, tenantID, mockDek)
	if err != nil {
		t.Fatal(err)
	}

	decDoc, err := tsc.decryptDocument(ctx, encFields, mockDek)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, fmt.Sprint(origDoc), fmt.Sprint(decDoc))
}
