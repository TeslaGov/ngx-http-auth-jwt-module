#!/bin/bash -eu

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

export ORG_NAME=${ORG_NAME:-teslagov}
export IMAGE_NAME=${IMAGE_NAME:-jwt-nginx}
export FULL_IMAGE_NAME=${ORG_NAME}/${IMAGE_NAME}
export CONTAINER_NAME_PREFIX=${CONTAINER_NAME_PREFIX:-jwt-nginx-test}
export NGINX_VERSION=${NGINX_VERSION:-1.22.0}

all() {
	build_nginx
	start_nginx
	test
}

fetch_headers() {
	printf "${BLUE} Fetching NGINX headers...${NC}"
	local files='src/core/ngx_core.h src/http/ngx_http.h'

	for f in ${files}; do
		curl "https://raw.githubusercontent.com/nginx/nginx/release-${NGINX_VERSION}/${f}" -o src/lib/$(basename ${f})
	done
}

build_nginx() {
	local dockerArgs=${1:-}

	printf "${BLUE}  Building...${NC}"
	docker image pull debian:bullseye-slim
	docker image pull nginx:${NGINX_VERSION}
	docker image build -t ${FULL_IMAGE_NAME}:latest -t ${FULL_IMAGE_NAME}:${NGINX_VERSION} --build-arg NGINX_VERSION=${NGINX_VERSION} ${dockerArgs} .
	
	if [ "$?" -ne 0 ]; then
		printf "${RED}  Build failed ${NC}"
	else
		printf "${GREEN}✓ Successfully built NGINX module ${NC}"
	fi

	docker rmi -f $(docker images --filter=label=stage=builder --quiet)
}

rebuild_nginx() {
	build_nginx --no-cache
}

start_nginx() {
	docker run --rm --name "${IMAGE_NAME}" -d -p 8000:80 ${FULL_IMAGE_NAME}
}

stop_nginx() {
	docker stop "${IMAGE_NAME}"
}

cp_bin() {
	printf "${BLUE}  Copying binaries...${NC}"
	rm -rf bin
	mkdir bin
	docker exec "${IMAGE_NAME}" sh -c "tar -chf - \
		/usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so \
		/usr/lib/x86_64-linux-gnu/libjansson.so.* \
		/usr/lib/x86_64-linux-gnu/libjwt.*" 2>/dev/null | tar -xf - -C bin &>/dev/null
}

build_test_runner() {
	local dockerArgs=${1:-}

	printf "${BLUE}  Building test runner...${NC}"
	docker compose -f ./test/docker-compose-test.yml build ${dockerArgs}
}

rebuild_test_runner() {
	build_test_runner --no-cache
}

test() {
	printf "${BLUE}  Running tests...${NC}"
	docker compose -f ./test/docker-compose-test.yml up --no-start
	docker start ${CONTAINER_NAME_PREFIX}
	docker start -a ${CONTAINER_NAME_PREFIX}-runner
	docker compose -f ./test/docker-compose-test.yml down
}

for fn in $@; do
	"$fn"
done