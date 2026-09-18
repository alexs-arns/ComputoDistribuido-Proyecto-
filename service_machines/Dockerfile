# Imagen oficial de Go como base (versión alpina para que sea ligera)
FROM golang:alpine AS build
# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Inicializar un módulo go temporal e instalar dependencias
RUN go mod init service_machines
RUN go get github.com/lib/pq

# Copiar el código fuente
COPY main.go .

# Compilar la aplicación
RUN go build -o main .

# Exponer el puerto
EXPOSE 8080

# Comando para arrancar el servicio
CMD ["./main"]