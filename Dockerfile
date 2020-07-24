FROM centos:7

LABEL maintainer="TeslaGov" email="developers@teslagov.com"

ARG NGINX_VERSION=1.16.1
ARG JANSSON_VERSION=2.10
ARG LIBJWT_VERSION=1.9.0

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/share/pkgconfig

RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum -y update && \
    yum -y groupinstall 'Development Tools' && \
    yum -y install pcre-devel pcre zlib-devel openssl-devel wget cmake check-devel check && \
    yum -y install nginx-$NGINX_VERSION

# for compiling for epel7
RUN yum -y install libxml2 libxslt libxml2-devel libxslt-devel gd gd-devel perl-ExtUtils-Embed geoip geoip-devel google-perftools google-perftools-devel

RUN mkdir -p /root/dl
WORKDIR /root/dl

# build jansson
RUN wget https://github.com/akheron/jansson/archive/v$JANSSON_VERSION.zip && \
    unzip v$JANSSON_VERSION.zip && \
    rm v$JANSSON_VERSION.zip && \
    ln -sf jansson-$JANSSON_VERSION jansson && \
    cd /root/dl/jansson && \
    cmake . -DJANSSON_BUILD_SHARED_LIBS=1 -DJANSSON_BUILD_DOCS=OFF && \
    make && \
    make check && \
    make install

# build libjwt
RUN wget https://github.com/benmcollins/libjwt/archive/v$LIBJWT_VERSION.zip && \
    unzip v$LIBJWT_VERSION.zip && \
    rm v$LIBJWT_VERSION.zip && \
    ln -sf libjwt-$LIBJWT_VERSION libjwt && \
    cd /root/dl/libjwt && \
    autoreconf -i && \
    ./configure && \
    make all && \
    make install

ADD . /root/dl/ngx-http-auth-jwt-module

# after 1.11.5 when compiling for a server that was compiled with --with-compat use this command
# ./configure --with-compat --add-dynamic-module=../ngx-http-auth-jwt-module --with-cc-opt='-std=gnu99'
# cp /root/dl/nginx/objs/ngx_http_auth_jwt_module.so /etc/nginx/modules/.
# build nginx module against nginx sources
#
# 1.10.2 from nginx by default use config flags... I had to add the -std=c99 and could not achieve "binary compatibility"
# ./configure --add-dynamic-module=../ngx-http-auth-jwt-module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-file-aio --with-threads --with-ipv6 --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_ssl_module --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -std=c99'
#
# rh-nginx110 uses these config flags
# ./configure --add-dynamic-module=../ngx-http-auth-jwt-module --prefix=/opt/rh/rh-nginx110/root/usr/share/nginx --sbin-path=/opt/rh/rh-nginx110/root/usr/sbin/nginx --modules-path=/opt/rh/rh-nginx110/root/usr/lib64/nginx/modules --conf-path=/etc/opt/rh/rh-nginx110/nginx/nginx.conf --error-log-path=/var/opt/rh/rh-nginx110/log/nginx/error.log --http-log-path=/var/opt/rh/rh-nginx110/log/nginx/access.log --http-client-body-temp-path=/var/opt/rh/rh-nginx110/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/opt/rh/rh-nginx110/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/opt/rh/rh-nginx110/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/opt/rh/rh-nginx110/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/opt/rh/rh-nginx110/lib/nginx/tmp/scgi --pid-path=/var/opt/rh/rh-nginx110/run/nginx/nginx.pid --lock-path=/var/opt/rh/rh-nginx110/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic -std=c99' --with-ld-opt='-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E'
#
# epel7 version 1.12.1 uses these config flags
# ./configure --add-dynamic-module=../ngx-http-auth-jwt-module --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic -std=gnu99' --with-ld-opt='-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E'
#
# epel7 version 1.16.1 uses these config flags
# ./configure --add-dynamic-module=../ngx-http-auth-jwt-module --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic' --with-ld-opt='-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E'

# ARG CACHEBUST=1

RUN wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz && \
    tar -xzf nginx-$NGINX_VERSION.tar.gz && \
    rm nginx-$NGINX_VERSION.tar.gz && \
    ln -sf nginx-$NGINX_VERSION nginx && \
    cd /root/dl/nginx && \
    ./configure --add-dynamic-module=../ngx-http-auth-jwt-module --prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt='-O2 -g -pipe -Werror=unused-variable -Wno-unused-variable -Wno-error=unused-but-set-variable -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic -std=gnu99' --with-ld-opt='-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E' && \
    make modules && \
    cp /root/dl/nginx/objs/ngx_http_auth_jwt_module.so /usr/lib64/nginx/modules/.

# Get nginx ready to run
COPY resources/nginx.conf /etc/nginx/nginx.conf

ENTRYPOINT ["/usr/sbin/nginx"]

EXPOSE 8000