FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go tool templ generate
RUN CGO_ENABLED=1 go build -trimpath -o /bin/openuem-console .

FROM debian:bookworm-slim
COPY --from=build /bin/openuem-console /bin/openuem-console
COPY ./assets /bin/assets
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
EXPOSE 1323
EXPOSE 1324
EXPOSE 1325
WORKDIR /bin
ENTRYPOINT ["/bin/openuem-console"]
