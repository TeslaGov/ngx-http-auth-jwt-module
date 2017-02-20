# Intro
This is an NGINX module to check for a valid JWT and proxy to an upstream server or redirect to a login page.

# Build Requirements
This module depends on the [JWT C Library](https://github.com/benmcollins/libjwt)

Transitively, that library depends on a JSON Parser called [Jansson](https://github.com/akheron/jansson) as well as the OpenSSL library.

# NGINX Directives
This module requires several new nginx.conf directives, which can be specified in on the `main` `server` or `location` level.

```
auth_jwt_key "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
auth_jwt_loginurl "https://yourdomain.com/loginpage";
auth_jwt_enabled on;
```

So, a typical use would be to specify the key and loginurl on the main level and then only turn on the locations that you want to secure (not the login page).

To compile nginx with this module, use an `--add-module` option to `configure`

```
./configure --add-module=path/to/this/module/directory
```

# Full ubuntu install example

```
apt-get -y install curl wget git-core build-essential libjansson-dev libssl-dev libsslcommon2-dev libpcre3-dev software-properties-common openssl libjansson-dev autoconf libgeoip-dev

git clone https://github.com/benmcollins/libjwt
cd libjwt
autoreconf -i
./configure --prefix=/usr --mandir=\${prefix}/share/man --infodir=\${prefix}/share/info
make all
make install

curl -s http://nginx.org/download/nginx-1.11.10.tar.gz | tar -zxf -
git clone https://github.com/freman/ngx-http-auth-jwt-module
cd nginx-1.11.10
./configure \
	--user=www-data \
	--group=www-data \
	--prefix=/etc/nginx \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--pid-path=/var/run/nginx.pid \
	--lock-path=/var/run/nginx.lock \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \ 
	--with-http_addition_module \
	--with-http_geoip_module \
	--with-http_gzip_static_module \
	--with-http_stub_status_module \
	--with-http_ssl_module \
	--with-pcre \
	--add-module=../ngx-http-auth-jwt-module
```