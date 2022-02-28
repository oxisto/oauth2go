FROM golang as builder

WORKDIR /build

ADD go.mod .
ADD go.sum .

ADD . .

# Disable cgo because our final image will be alpine and will not have the same C stdlib
RUN CGO_ENABLED=0 go build cmd/server/server.go

FROM alpine

COPY --from=builder /build/server /

CMD ["./server"]
