FROM golang:1.23.12-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG TARGET
RUN case "$TARGET" in gateway|moderation-worker|action-worker|setup-webhook) ;; *) exit 1 ;; esac \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/service "./cmd/$TARGET"

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/service /service
USER nonroot:nonroot
ENTRYPOINT ["/service"]
