// Standalone module for the offset-discovery tool. Decouples the tool's
// build from the parent kloak module so the Dockerfile's `discoverer`
// stage can `go build .` inside `golang:<DISCOVERY_GO_VERSION>` without
// the parent module's go.mod being part of the build context.
module go-tls-offsets

go 1.21
