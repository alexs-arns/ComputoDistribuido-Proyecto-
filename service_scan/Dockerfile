FROM golang:alpine AS build
WORKDIR /app

RUN go mod init service_scan
RUN go get github.com/lib/pq

COPY main.go .

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]