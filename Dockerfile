# Build Gait in a stock Go builder container
FROM golang:1.11-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers

ADD . /go-aichain
RUN cd /go-aichain && make gait

# Pull Gait into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /go-aichain/build/bin/gait /usr/local/bin/

EXPOSE 9523 9524 30323 30323/udp 30324/udp
ENTRYPOINT ["gait"]
