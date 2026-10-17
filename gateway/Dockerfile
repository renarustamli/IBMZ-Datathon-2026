# Multi-stage build, native s390x on LinuxONE. No certificates or keys are baked in:
# cert.pem, key.pem and logs/ are mounted at run time (see docker-compose.yml).
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY testclient/ ./testclient/
RUN CGO_ENABLED=0 go build -trimpath -o /out/gateway . && \
    CGO_ENABLED=0 go build -trimpath -o /out/testclient ./testclient

FROM scratch
COPY --from=build /out/gateway /out/testclient /
USER 1000:1000
WORKDIR /data
EXPOSE 8443
ENTRYPOINT ["/gateway", "-cert", "/certs/cert.pem", "-key", "/certs/key.pem", "-notes", "/data/logs/connections.jsonl"]
CMD ["-mode", "strict", "-listen", ":8443", "-backend", "backend:9000"]
