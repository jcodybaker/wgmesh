FROM wgmesh-dev AS builder

WORKDIR /go/src/github.com/jcodybaker/wgmesh

COPY . /go/src/github.com/jcodybaker/wgmesh

RUN go build ./cmd/wgmesh

FROM scratch

COPY --from=builder /go/src/github.com/jcodybaker/wgmesh/wgmesh /wgmesh

CMD ["/wgmesh"]