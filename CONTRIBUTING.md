# Contributing to Tenant Security Client Go

## Tests

This client has both a set of unit tests as well an integration test suite. Because of the complexity of the various services required to run non-unit test suites, these tests require additional setup, which is explained below.

### Unit Tests

Tests that check functionality that is contained within the client.

```
go test
```

#### Complete Integration Tests

We've created a number of accounts within a Config Broker dev environment that have tenants set up for all the different KMS types that we support. This allows us to run a more complete suite of integration tests that exercise more parts of both the client as well as the Tenant Security Proxy. These tests are not runnable by the public. You can view the results of these test runs in [CI](https://github.com/IronCoreLabs/tenant-security-client-go/actions).

The integration tests are run the same way as the regular tests, but require the `API_KEY` environment variable to be set. This value is stored encrypted in `.env.integration.iron`.

## CI Automated Tests

The CI job runs tests using the [tenant-security-proxy](https://github.com/IronCoreLabs/tenant-security-proxy) repo.
If your tests don't build again the default branch of that repo, you can change it by adding a command to the pull request. The
comment should contain the string `CI_branches` and a JSON object like
`{"tenant-security-proxy": "some_branch"}`. You can include formatting, prose, or a haiku,
but no `{` or `}` characters. Example:

```
CI_branches: `{"tenant-security-proxy": "some_branch"}`

This new branch needs to build against some_branch.
```
