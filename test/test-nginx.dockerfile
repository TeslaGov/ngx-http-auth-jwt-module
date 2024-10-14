ARG BASE_IMAGE
ARG PORT
ARG SSL_PORT

FROM ${BASE_IMAGE} AS NGINX
ARG PORT
ARG SSL_PORT
COPY etc/ /etc/
RUN sed -i "s|%{PORT}|${PORT}|" /etc/nginx/conf.d/test.conf
RUN sed -i "s|%{SSL_PORT}|${SSL_PORT}|" /etc/nginx/conf.d/test.conf
COPY <<` /usr/share/nginx/html/index.html
<html>
  <head>Test</head>
  <body>
    <h1>NGINX Auth-JWT Module Test</h1>
  </body>
</html>
`
