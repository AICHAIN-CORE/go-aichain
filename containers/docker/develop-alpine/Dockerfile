FROM alpine:3.7

RUN \
  apk add --update go git make gcc musl-dev linux-headers ca-certificates && \
  git clone --depth 1 https://github.com/AICHAIN-CORE/go-aichain && \
  (cd go-aichain && make gait) && \
  cp go-aichain/build/bin/gait /gait && \
  apk del go git make gcc musl-dev linux-headers && \
  rm -rf /go-aichain && rm -rf /var/cache/apk/*

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/gait"]
