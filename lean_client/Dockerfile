FROM ubuntu:22.04

ARG TARGETARCH

COPY ./bin/$TARGETARCH/lean_client /usr/local/bin/lean_client

ENTRYPOINT ["lean_client"]
