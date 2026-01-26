FROM ubuntu:22.04

ARG COMMIT_SHA
ARG BUILD_DATE
ARG GIT_BRANCH

LABEL org.opencontainers.image.title="grandine"
LABEL org.opencontainers.image.description="High performance Ethereum lean client"
LABEL org.opencontainers.image.authors="Grandine <info@grandine.io>"
LABEL org.opencontainers.image.source=https://github.com/grandinetech/lean
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.revision=$COMMIT_SHA
LABEL org.opencontainers.image.ref.name=$GIT_BRANCH
LABEL org.opencontainers.image.created=$BUILD_DATE

ARG TARGETARCH

COPY ./bin/$TARGETARCH/lean_client /usr/local/bin/lean_client

ENTRYPOINT ["lean_client"]
