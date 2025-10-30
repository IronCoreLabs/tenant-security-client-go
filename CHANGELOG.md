# Changelog

## v0.5.0

- Improve error handling when decrypting documents.
- Change minimum required Go version to 1.24

## v0.4.0

- Add support for `KMS_THROTTLED` and `KMS_ACCOUNT_ISSUE`.

## v0.3.0

- Encryption now returns a Crypto error when trying to encrypt a document that has already been IronCore encrypted.
  - If you have a use case for double-encrypting a document, please open an issue explaining and we can work on accommodating you.
- Change minimum required Go version to 1.19

## v0.2.2

- Retract v0.1.x of the tenant-security-client-go

## v0.2.1

- Handle negatives values for TenantSecurityClient parallelism better

## v0.2.0

- Initial beta release of the SDK
