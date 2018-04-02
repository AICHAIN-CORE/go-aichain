.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/AICHAIN-CORE/go-aichain/cmd/swarm
	go build -o bin/gait     github.com/AICHAIN-CORE/go-aichain/cmd/gait
	go build -o bin/bootnode github.com/AICHAIN-CORE/go-aichain/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/AICHAIN-CORE/go-aichain/swarm/...
