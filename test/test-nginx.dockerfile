ARG BASE_IMAGE

FROM ${BASE_IMAGE} AS NGINX
ARG PORT
ARG SSL_PORT

COPY etc/ /etc/

COPY <<` /usr/share/nginx/html/index.html
<html>
  <head>Test</head>
  <body>
    <h1>NGINX Auth-JWT Module Test</h1>
  </body>
</html>
`

RUN sed -i "s|%{PORT}|${PORT:?required}|" /etc/nginx/conf.d/test.conf
RUN sed -i "s|%{SSL_PORT}|${SSL_PORT:?required}|" /etc/nginx/conf.d/test.conf
