# Build arguments are overrideable by the release pipeline; no credentials or
# runtime configuration are baked into the image.
ARG GO_VERSION=1.26.1
FROM golang:${GO_VERSION} AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
ARG COMMIT
ARG BUILD_DATE
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/loom ./cmd/loom

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/loom /loom
USER nonroot:nonroot
ENTRYPOINT ["/loom", "serve"]
