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

# All commands
Here's a list of all of the commands I used on a fresh CentOS VM to get this up and running

```
yum update
yum -y groupinstall 'Development Tools'
yum -y install unzip zip gunzip wget httpd-devel pcre perl pcre-devel zlib zlib-devel GeoIP GeoIP-devel openssl openssl-devel cmake git
cd
mkdir dl
cd dl
wget https://github.com/akheron/jansson/archive/2.8.zip
unzip 2.8.zip
ln -sf jansson-2.8 jansson
cd jansson
cmake .
make
make install
cd ~/dl
wget https://github.com/benmcollins/libjwt/archive/master.zip
unzip master.zip
ln -sf libjwt-master libjwt
cd libjwt
```

To compile libjwt on my mac I had to edit the `CMakeLists.txt` file and add this line at the top:

```
	include_directories(/usr/local/Cellar/openssl/1.0.2h_1/include/)
```

To compile libjwt on my CentOS VM I had to edit the `CMakeLists.txt` file and add this flag to the list of `CMAKE_C_FLAGS`:

```
	-std=gnu99
```

Edit `include/jwt.h` and `libjwt/jwt.c` according to my comments above.

```
vi include/jwt.h
vi libjwt/jwt.c
vi CMakeLists.txt
cmake .
make jwt_static

cd ~/dl
git clone https://github.com/TeslaGov/ngx-http-auth-jwt-module

cd ~/dl
wget http://nginx.org/download/nginx-1.10.1.tar.gz
tar -xzf nginx-1.10.1.tar.gz
ln -sf nginx-1.10.1 nginx
cd nginx
```

You may need to change this configure line to support your needs

```
./configure 
	--user=nginx \
	--group=nginx \
	--prefix=/etc/nginx \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--pid-path=/var/run/nginx.pid \
	--lock-path=/var/run/nginx.lock \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \ 
	--with-http_gzip_static_module \
	--with-http_stub_status_module \
	--with-http_ssl_module \
	--with-pcre \
	--add-module=/root/dl/ngx-http-auth-jwt-module/src
```

At this point I needed to edit the Makefile.  I couldn't figure out how to link in the dependent libraries via the configure command so I added them in by hand.

I appended this to my CLFAGS line:

```
	-I /root/dl/libjwt/include -I /root/dl/jansson/src -std=gnu99
```

I added these lines to objs/nginx list:

```
	objs/addon/ngx_http_auth_jwt_module/ngx_http_auth_jwt_module.o \
    /root/dl/libjwt/lib/libjwt.a \
    /usr/local/lib/libjansson.a
```

I added these lines to the link command:

```
	objs/addon/ngx_http_auth_jwt_module/ngx_http_auth_jwt_module.o \
    -L /root/dl/libjwt/lib \
    -L /usr/local/lib \
    -ldl -lpthread -lcrypt -lpcre -lssl -lcrypto -ldl -lz -ljwt -ljansson \
    -Wl,-E
```

```
vi Makefile
make
make install
/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
```
