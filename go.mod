module github.com/IronCoreLabs/tenant-security-client-go

go 1.24

require (
	github.com/stretchr/testify v1.11.1
	google.golang.org/protobuf v1.36.10
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract [v0.1.0, v0.1.18] // Published accidentally.
