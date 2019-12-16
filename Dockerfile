FROM wgmesh-dev AS wgmeshbuilder
WORKDIR /go/src/github.com/jcodybaker/wgmesh
COPY . /go/src/github.com/jcodybaker/wgmesh
RUN go build ./cmd/wgmesh

FROM rust:buster AS boringtunbuilder
# Currently pulling master as 0.2.0 fails to build.
RUN curl -Ls https://github.com/cloudflare/boringtun/archive/master.tar.gz | tar -xzvf - --strip-components=1
RUN cargo build --release \
    && strip ./target/release/boringtun

FROM debian:buster-slim
WORKDIR /app
COPY --from=boringtunbuilder /target/release/boringtun /app/boringtun
COPY --from=wgmeshbuilder /go/src/github.com/jcodybaker/wgmesh/wgmesh /app/wgmesh

CMD ["/wgmesh"]