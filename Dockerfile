FROM centos:7

LABEL maintainer="TeslaGov" email="developers@teslagov.com"

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN yum -y update && \
	yum -y groupinstall 'Development Tools' && \
	yum -y install pcre-devel pcre zlib-devel openssl-devel wget cmake check-devel check

RUN mkdir -p /root/dl
WORKDIR /root/dl

# get our JWT module
# change this to get a specific version?
RUN wget https://github.com/TeslaGov/ngx-http-auth-jwt-module/archive/master.zip && \
	unzip master.zip && \
	rm master.zip && \
	ln -sf ngx-http-auth-jwt-module-master ngx-http-auth-jwt-module

# build jansson
RUN wget https://github.com/akheron/jansson/archive/v2.10.zip && \
	unzip v2.10.zip && \
	rm v2.10.zip && \
	ln -sf jansson-2.10 jansson && \
	cd /root/dl/jansson && \
	cmake . -DJANSSON_BUILD_SHARED_LIBS=1 -DJANSSON_BUILD_DOCS=OFF && \
	make && \
	make check && \
	make install

# build libjwt
RUN wget https://github.com/benmcollins/libjwt/archive/v1.8.0.zip && \
	unzip v1.8.0.zip && \
	rm v1.8.0.zip && \
	ln -sf libjwt-1.8.0 libjwt && \
	cd /root/dl/libjwt && \
	autoreconf -i && \
	./configure JANSSON_CFLAGS=/usr/local/include JANSSON_LIBS=/usr/local/lib && \
	make all && \
	make install

# build nginx module against nginx sources
RUN wget http://nginx.org/download/nginx-1.12.0.tar.gz && \
	tar -xzf nginx-1.12.0.tar.gz && \
	rm nginx-1.12.0.tar.gz && \
	ln -sf nginx-1.12.0 nginx && \
	cd /root/dl/nginx && \
	./configure --with-compat --add-dynamic-module=../ngx-http-auth-jwt-module --with-cc-opt='-std=gnu99' && \
	make modules
