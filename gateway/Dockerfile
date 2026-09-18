FROM golang:alpine AS build
WORKDIR /app
COPY go.mod ./
COPY main.go ./
COPY routes.json ./
RUN go build -o gateway main.go

FROM alpine:latest
WORKDIR /app
COPY --from=build /app/gateway .
COPY --from=build /app/routes.json .
EXPOSE 8000
CMD ["./gateway"]