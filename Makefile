# Command menu for building, testing, and releasing the Upwind Terraform provider.
# Run `make <target>`, e.g. `make build`.

NAME     = upwind
BINARY   = terraform-provider-$(NAME)
VERSION ?= dev

default: build

# Compile the provider binary into the current directory.
build:
	go build -o $(BINARY) -ldflags="-X main.version=$(VERSION)" .

# Install the binary into $GOBIN so local Terraform (via dev_overrides) can find it.
install:
	go install -ldflags="-X main.version=$(VERSION)" .

# Fast unit tests - no real tenant needed.
test:
	go test ./... $(TESTARGS) -timeout 5m

# Acceptance tests - run real Terraform plans/applies against a live tenant.
# Requires TF_ACC=1 and the UPWIND_* credentials in the environment.
testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m

# Static analysis + formatting.
vet:
	go vet ./...

fmt:
	gofmt -s -w -e .

lint:
	golangci-lint run ./...

# Generate registry docs from schema descriptions (requires tfplugindocs).
# --provider-name is pinned because it otherwise defaults to the basename of the
# working directory, so a clone in a differently named folder rewrites page_title
# on every generated page. The value is the repository name, which is what the
# generated titles already read ("... Resource - terraform-provider-upwind") and
# what other framework providers use.
docs:
	tfplugindocs generate --provider-name terraform-provider-upwind

.PHONY: default build install test testacc vet fmt lint docs
