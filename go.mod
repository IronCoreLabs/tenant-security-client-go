module github.com/IronCoreLabs/tenant-security-client-go

go 1.17

require (
	github.com/stretchr/testify v1.7.1
	google.golang.org/protobuf v1.28.0
)

require (
	github.com/davecgh/go-spew v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

retract [v0.1.0, v0.1.18] // Published accidentally.
