FROM golang:1.25-alpine AS build

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /dpndon .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl tar gzip

# Install OSV Scanner
RUN curl -sL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

COPY --from=build /dpndon /usr/local/bin/dpndon

EXPOSE 8080

ENTRYPOINT ["dpndon"]
CMD ["serve", "-t", "sse", "-H", "0.0.0.0", "-p", "8080"]
