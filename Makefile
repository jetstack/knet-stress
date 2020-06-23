BINDIR   ?= $(CURDIR)/bin

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## build knet-stress
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -v -o ./bin/knet-stress ./cmd/.

image: build ## build docker image
	docker build -t gcr.io/jetstack-josh/knet-stress:v0.1.0-alpha.0 .
	docker push gcr.io/jetstack-josh/knet-stress:v0.1.0-alpha.0

all: image # build all targets
