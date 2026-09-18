FROM nginx:alpine
# Copia de archivos estáticos al directorio de Nginx
COPY index.html /usr/share/nginx/html/
COPY style.css /usr/share/nginx/html/
# Se expone el puerto 80 para que Nginx pueda recibir tráfico HTTP
EXPOSE 80