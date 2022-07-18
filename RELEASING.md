## Releasing

Because pushing a tag of the form v`x.x.x` publishes to pkg.go.dev, this repo does not automatically bump versions on push to `main`.
Therefore, the release process is simply to manually run the [Bump Version](https://github.com/IronCoreLabs/tenant-security-client-go/actions/workflows/bump-version.yaml)
workflow with the new desired version number (remember to start the version with a `v`).
