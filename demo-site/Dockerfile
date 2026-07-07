FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY royak-mark.png /usr/share/nginx/html/royak-mark.png
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
