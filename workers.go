package tsc

import (
	"context"
	"log"
)

// Code pertaining to worker pools for batch operations.

type batchRequest struct {
	//nolint:containedctx
	ctx   context.Context
	inner interface{}
}

type batchEncryptRequest struct {
	doc      PlaintextDocument
	tenantID string
	keys     wrapKeyResponse
	answer   chan<- *BatchEncryptResponse
}

type BatchEncryptResponse struct {
	Doc EncryptedDocument
	Err error
}

type batchDecryptRequest struct {
	doc    EncryptedDocument
	keys   unwrapKeyResponse
	answer chan<- *BatchDecryptResponse
}

type BatchDecryptResponse struct {
	Doc DecryptedDocument
	Err error
}

func worker(ctx context.Context, reqs <-chan *batchRequest) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-reqs:
			switch inner := req.inner.(type) {
			case batchEncryptRequest:
				var result BatchEncryptResponse
				//nolint:contextcheck
				doc, err := encryptDocument(req.ctx, &inner.doc, inner.tenantID, inner.keys.Dek.b)
				if err != nil {
					result.Err = err
				} else {
					result.Doc = EncryptedDocument{doc, inner.keys.Edek}
				}
				inner.answer <- &result
				close(inner.answer)

			case batchDecryptRequest:
				var result BatchDecryptResponse
				doc, err := decryptDocument(ctx, &inner.doc, inner.keys.Dek.b)
				if err != nil {
					result.Err = err
				} else {
					result.Doc = DecryptedDocument{doc, inner.doc.Edek}
				}
				inner.answer <- &result
				close(inner.answer)

			default:
				log.Panicf("impossible inner type %T", inner)
			}
		}
	}
}
