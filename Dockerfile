FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server
RUN CGO_ENABLED=0 go build -o /out/ql ./cmd/ql

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/server /usr/local/bin/quietline-server
COPY --from=build /out/ql /usr/local/bin/ql
EXPOSE 8080
USER nobody
ENTRYPOINT ["quietline-server"]
