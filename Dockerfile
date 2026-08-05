# Multi-stage image for the Loom CLI/server (Linux).
# Build:
#   docker build -t loom:local .
#   docker buildx build --platform linux/amd64,linux/arm64 -t loom:latest .
#
# Run (dev only — set production env for real deploys):
#   docker run --rm -p 8080:8080 -e LOOM_ADDR=:8080 loom:local serve --addr=:8080

FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
  -o /out/loom ./cmd/loom

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/loom /loom
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/loom"]
CMD ["serve", "--addr=:8080"]
