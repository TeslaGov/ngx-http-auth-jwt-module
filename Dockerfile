ARG NGINX_VERSION


FROM debian:bullseye-slim as BASE_IMAGE
LABEL stage=builder
RUN  apt-get update \
	&& apt-get install -y curl build-essential


FROM BASE_IMAGE as BUILD_IMAGE
LABEL stage=builder
ENV LD_LIBRARY_PATH=/usr/local/lib
ARG NGINX_VERSION
RUN  set -x \
	&& apt-get install -y libjwt-dev libjwt0 libjansson-dev libjansson4 libpcre2-dev zlib1g-dev libpcre3-dev \
	&& mkdir -p /root/build/ngx-http-auth-jwt-module
WORKDIR /root/build/ngx-http-auth-jwt-module
ADD config ./
ADD src/*.h src/*.c ./src/
WORKDIR /root/build
RUN  set -x \
  && mkdir nginx \
	&& curl -O http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
	&& tar -xzf nginx-${NGINX_VERSION}.tar.gz --strip-components 1 -C nginx \
	&& rm nginx-${NGINX_VERSION}.tar.gz
WORKDIR /root/build/nginx
RUN  ./configure --with-compat --add-dynamic-module=../ngx-http-auth-jwt-module \
	&& make modules


FROM nginx:${NGINX_VERSION}
LABEL stage=builder
RUN  apt-get update \
	&& apt-get -y install libjansson4 libjwt0 \
	&& cd /etc/nginx \
	&& sed -ri '/pid\s+\/var\/run\/nginx\.pid;$/a load_module \/usr\/lib64\/nginx\/modules\/ngx_http_auth_jwt_module\.so;' nginx.conf


LABEL stage=
LABEL maintainer="TeslaGov" email="developers@teslagov.com"
COPY --from=BUILD_IMAGE /root/build/nginx/objs/ngx_http_auth_jwt_module.so /usr/lib64/nginx/modules/
