FROM centos:7

MAINTAINER Tesla Government email: developers@teslagov.com

RUN yum -y update

RUN yum -y groupinstall 'Development Tools'
RUN yum -y install pcre-devel pcre
RUN yum -y install zlib-devel openssl-devel
RUN yum -y install wget
RUN yum -y install cmake
RUN yum -y install check-devel check
# RUN yum -y install subunit-devel subunit libsubunit

RUN mkdir -p /root/dl

# get our JWT module
WORKDIR /root/dl
# change this to get a specific version?
RUN wget https://github.com/TeslaGov/ngx-http-auth-jwt-module/archive/master.zip
RUN unzip master.zip
RUN rm master.zip
RUN ln -sf ngx-http-auth-jwt-module-master ngx-http-auth-jwt-module

# build jansson
WORKDIR /root/dl
RUN wget https://github.com/akheron/jansson/archive/v2.10.zip
RUN unzip v2.10.zip
RUN rm v2.10.zip
RUN ln -sf jansson-2.10 jansson
WORKDIR /root/dl/jansson
RUN cmake .
RUN make
RUN make check
RUN make install

# build libjwt
WORKDIR /root/dl
RUN wget https://github.com/benmcollins/libjwt/archive/v1.8.0.zip
RUN unzip v1.8.0.zip
RUN rm v1.8.0.zip
RUN ln -sf libjwt-1.8.0 libjwt
WORKDIR /root/dl/libjwt
RUN autoreconf -i
RUN ./configure JANSSON_CFLAGS=/usr/local/include JANSSON_LIBS=/usr/local/lib
RUN make all
# this does not work because it can't find JANSSON
# RUN make check
RUN make install

WORKDIR /root/dl
RUN wget http://nginx.org/download/nginx-1.12.0.tar.gz
RUN tar -xzf nginx-1.12.0.tar.gz
RUN rm nginx-1.12.0.tar.gz
RUN ln -sf nginx-1.12.0 nginx
WORKDIR /root/dl/nginx
RUN ./configure --with-compat --add-dynamic-module=../ngx-http-auth-jwt-module --with-cc-opt='-std=gnu99'
RUN make modules


EXPOSE 80
VOLUME ["/etc/nginx/sites-enabled", "/etc/nginx/certs", "/etc/nginx/conf.d", "/var/log/nginx", "/var/www/html"]
WORKDIR /etc/nginx

