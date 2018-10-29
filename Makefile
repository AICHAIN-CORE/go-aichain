# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: gait android ios gait-cross swarm evm all test clean
.PHONY: gait-linux gait-linux-386 gait-linux-amd64 gait-linux-mips64 gait-linux-mips64le
.PHONY: gait-linux-arm gait-linux-arm-5 gait-linux-arm-6 gait-linux-arm-7 gait-linux-arm64
.PHONY: gait-darwin gait-darwin-386 gait-darwin-amd64
.PHONY: gait-windows gait-windows-386 gait-windows-amd64

GOBIN = $(shell pwd)/build/bin
GO ?= latest

gait:
	build/env.sh go run build/ci.go install ./cmd/gait
	@echo "Done building."
	@echo "Run \"$(GOBIN)/gait\" to launch gait."

swarm:
	build/env.sh go run build/ci.go install ./cmd/swarm
	@echo "Done building."
	@echo "Run \"$(GOBIN)/swarm\" to launch swarm."

all:
	build/env.sh go run build/ci.go install

android:
	build/env.sh go run build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/gait.aar\" to use the library."

ios:
	build/env.sh go run build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Gait.framework\" to use the library."

test: all
	build/env.sh go run build/ci.go test

lint: ## Run linters.
	build/env.sh go run build/ci.go lint

clean:
	./build/clean_go_build_cache.sh
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

gait-cross: gait-linux gait-darwin gait-windows gait-android gait-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/gait-*

gait-linux: gait-linux-386 gait-linux-amd64 gait-linux-arm gait-linux-mips64 gait-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-*

gait-linux-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/gait
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep 386

gait-linux-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/gait
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep amd64

gait-linux-arm: gait-linux-arm-5 gait-linux-arm-6 gait-linux-arm-7 gait-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep arm

gait-linux-arm-5:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/gait
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep arm-5

gait-linux-arm-6:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/gait
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep arm-6

gait-linux-arm-7:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/gait
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep arm-7

gait-linux-arm64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/gait
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep arm64

gait-linux-mips:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/gait
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep mips

gait-linux-mipsle:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/gait
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep mipsle

gait-linux-mips64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/gait
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep mips64

gait-linux-mips64le:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/gait
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/gait-linux-* | grep mips64le

gait-darwin: gait-darwin-386 gait-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/gait-darwin-*

gait-darwin-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/gait
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/gait-darwin-* | grep 386

gait-darwin-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/gait
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gait-darwin-* | grep amd64

gait-windows: gait-windows-386 gait-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/gait-windows-*

gait-windows-386:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/gait
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/gait-windows-* | grep 386

gait-windows-amd64:
	build/env.sh go run build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/gait
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gait-windows-* | grep amd64
