# Imagen oficial de Go como base (versión alpina para que sea ligera)
FROM golang:alpine AS build
# Directorio de trabajo dentro del contenedor
WORKDIR /app
# Inicializar un módulo go y instalar la librería de postgres
RUN go mod init service_hardening
RUN go get github.com/lib/pq
# Copiar el código fuente

COPY main.go .
# Compilar la aplicación

RUN go build -o main .
# Exponer el puerto
EXPOSE 8080
#Arrancar servicio
CMD ["./main"]