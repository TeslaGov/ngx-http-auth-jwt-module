ARG BASE_IMAGE=${:?required}
ARG NGINX_VERSION
ARG LIBJWT_VERSION

FROM ${BASE_IMAGE} AS ngx_http_auth_jwt_builder
LABEL stage=ngx_http_auth_jwt_builder
ENV PATH="${PATH}:/etc/nginx"
ENV LD_LIBRARY_PATH=/usr/local/lib
ARG NGINX_VERSION
ARG LIBJWT_VERSION

RUN <<`
	set -e
	apt-get update
	apt-get upgrade -y
`

RUN	apt-get install -y curl git zlib1g-dev libpcre3-dev build-essential libpcre2-dev zlib1g-dev libpcre3-dev pkg-config cmake dh-autoreconf

WORKDIR /root/build/libjansson
RUN <<`
	set -e
	git clone --depth 1 --branch v2.14 https://github.com/akheron/jansson .
	cmake . -DJANSSON_BUILD_SHARED_LIBS=1 -DJANSSON_BUILD_DOCS=OFF
	make
	make check
	make install
`

WORKDIR /root/build/libjwt
RUN <<`
	set -e
	git clone --depth 1 --branch v${LIBJWT_VERSION} https://github.com/benmcollins/libjwt .
	autoreconf -i
	./configure
	make all
	make install
`

WORKDIR /root/build/ngx-http-auth-jwt-module
ADD config ./
ADD src/*.h src/*.c ./src/
WORKDIR /root/build
RUN <<`
	set -e
	mkdir nginx
	curl -O http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
	tar -xzf nginx-${NGINX_VERSION}.tar.gz --strip-components 1 -C nginx
`

WORKDIR /root/build/nginx
RUN <<`
	set -e
	BUILD_FLAGS=''
	MAJ=$(echo ${NGINX_VERSION} | cut -f1 -d.)
	MIN=$(echo ${NGINX_VERSION} | cut -f2 -d.)
	REV=$(echo ${NGINX_VERSION} | cut -f3 -d.)

	# NGINX 1.23.0+ changes cookies to use a linked list, and renames `cookies` to `cookie`
	if [ "${MAJ}" -gt 1 ] || [ "${MAJ}" -eq 1 -a "${MIN}" -ge 23 ]; then
		BUILD_FLAGS="${BUILD_FLAGS} --with-cc-opt='-DNGX_LINKED_LIST_COOKIES=1'"
	fi

	./configure \
    --prefix=/etc/nginx \
		--sbin-path=/usr/sbin/nginx \
		--modules-path=/usr/lib64/nginx/modules \
		--conf-path=/etc/nginx/nginx.conf \
		--error-log-path=/var/log/nginx/error.log \
		--http-log-path=/var/log/nginx/access.log \
		--pid-path=/var/run/nginx.pid \
		--lock-path=/var/run/nginx.lock \
		--http-client-body-temp-path=/var/cache/nginx/client_temp \
		--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
		--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
		--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
		--user=nginx \
		--group=nginx \
		--with-compat \
		--with-debug \
		--with-file-aio \
		--with-threads \
		--with-http_addition_module \
		--with-http_auth_request_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_gunzip_module \
		--with-http_gzip_static_module \
		--with-http_mp4_module \
		--with-http_random_index_module \
		--with-http_realip_module \
		--with-http_secure_link_module \
		--with-http_slice_module \
		--with-http_ssl_module \
		--with-http_stub_status_module \
		--with-http_sub_module \
		--with-http_v2_module \
		--with-mail \
		--with-mail_ssl_module \
		--with-stream \
		--with-stream_realip_module \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-1.25.4/debian/debuild-base/nginx-1.25.4=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
		--with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
		--add-dynamic-module=../ngx-http-auth-jwt-module \
		${BUILD_FLAGS}
		# --with-openssl=/usr/local \
`

RUN make modules
RUN make install

WORKDIR /usr/lib/nginx/modules
RUN	mv /root/build/nginx/objs/ngx_http_auth_jwt_module.so .
RUN rm -rf /root/build

RUN <<`
	set -e
  apt-get remove -y curl git zlib1g-dev libpcre3-dev build-essential libpcre2-dev zlib1g-dev libpcre3-dev pkg-config cmake dh-autoreconf
  # apt-get install -y gnupg2 ca-certificates lsb-release debian-archive-keyring
	apt-get clean
`

RUN <<`
	set -e
	groupadd nginx
	useradd -g nginx nginx
`

# RUN <<`
#   set -e
#   curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg
#   printf "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/debian `lsb_release -cs` nginx\n" > /etc/apt/sources.list.d/nginx.list
#   printf "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" > /etc/apt/preferences.d/99nginx
# `

# RUN <<`
#   set -e
#   apt-get update
#   apt-get install -y nginx
# `

COPY <<` /etc/nginx/nginx.conf
daemon off;
user nginx;
pid /var/run/nginx.pid;

load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;

worker_processes 1;

events {
	worker_connections 1024;
}

http {
	include mime.types;
	default_type application/octet-stream;

	log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
	                '\$status \$body_bytes_sent "\$http_referer" '
	                '"\$http_user_agent" "\$http_x_forwarded_for"';

	access_log /var/log/nginx/access.log main;
	include conf.d/*.conf;
}
`

WORKDIR /var/cache/nginx
RUN chown nginx:nginx .

WORKDIR /
CMD ["nginx"]
