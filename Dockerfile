FROM golang:1.26.10-alpine3.24 AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:3.24

# CVE-2026-111943: ca-certificates 20261020-r0 drops the emSign ECC Root CA - G3. Go reads this
# store, and the webhook calls the httpreq endpoint over HTTPS with it.
RUN apk add --no-cache --upgrade ca-certificates && \
    apk version -t "$(apk info -e -v ca-certificates | sed 's/^ca-certificates-//')" 20261020-r0 | grep -qv '<'

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]
