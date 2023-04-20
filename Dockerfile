ARG NGINX_VERSION
ARG SOURCE_HASH


FROM debian:bullseye-slim as ngx_http_auth_jwt_builder_base
LABEL stage=ngx_http_auth_jwt_builder
RUN apt-get update &&\
	apt-get install -y curl build-essential


FROM ngx_http_auth_jwt_builder_base as ngx_http_auth_jwt_builder_module
LABEL stage=ngx_http_auth_jwt_builder
ENV LD_LIBRARY_PATH=/usr/local/lib
ARG NGINX_VERSION
RUN set -x &&\
	apt-get install -y libjwt-dev libjwt0 libjansson-dev libjansson4 libpcre2-dev zlib1g-dev libpcre3-dev &&\
	mkdir -p /root/build/ngx-http-auth-jwt-module
WORKDIR /root/build/ngx-http-auth-jwt-module
ARG SOURCE_HASH
RUN echo "Source Hash: ${SOURCE_HASH}"
ADD config ./
ADD src/*.h src/*.c ./src/
WORKDIR /root/build
RUN set -x &&\
  mkdir nginx &&\
	curl -O http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz &&\
	tar -xzf nginx-${NGINX_VERSION}.tar.gz --strip-components 1 -C nginx
WORKDIR /root/build/nginx
RUN ./configure --with-debug --with-compat --add-dynamic-module=../ngx-http-auth-jwt-module &&\
	make modules


FROM nginx:${NGINX_VERSION} AS ngx_http_auth_jwt_builder_nginx
LABEL stage=
RUN rm /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh /etc/nginx/conf.d/default.conf
RUN apt-get update &&\
	apt-get -y install libjansson4 libjwt0 &&\
	cd /etc/nginx &&\
	sed -ri '/pid\s+\/var\/run\/nginx\.pid;$/a load_module \/usr\/lib64\/nginx\/modules\/ngx_http_auth_jwt_module\.so;' nginx.conf
LABEL maintainer="TeslaGov" email="developers@teslagov.com"
COPY --from=ngx_http_auth_jwt_builder_module /root/build/nginx/objs/ngx_http_auth_jwt_module.so /usr/lib64/nginx/modules/
