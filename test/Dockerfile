FROM centos:7

LABEL maintainer="TeslaGov" email="developers@teslagov.com"

ENV LD_LIBRARY_PATH=/usr/local/lib

COPY nginx.repo /etc/yum.repos.d/nginx.repo

# setup a test for the new module
# download and run nginx binary
RUN yum -y update && \
	yum -y install nginx-1.12.0 && \
	cp -r /usr/share/nginx/html /usr/share/nginx/secure

EXPOSE 8000