ARG BASE_IMAGE

FROM ${BASE_IMAGE:?required}
ARG PORT
ARG SSL_PORT

RUN <<`
set -e
apt-get update
apt-get install -y curl
apt-get clean
`

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
