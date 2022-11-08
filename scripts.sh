#!/bin/bash -eu

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

DOCKER_ORG_NAME=${DOCKER_ORG_NAME:-teslagov}
DOCKER_IMAGE_NAME=${DOCKER_IMAGE_NAME:-jwt-nginx}
DOCKER_FULL_IMAGE_NAME=${DOCKER_ORG_NAME}/${DOCKER_IMAGE_NAME}
CONTAINER_NAME_PREFIX=${CONTAINER_NAME_PREFIX:-jwt-nginx-test}
NGINX_VERSION=${NGINX_VERSION:-1.22.0}

all() {
	build_nginx
	start_nginx
	test
}

build_nginx() {
	DOCKER_ARGS=${1:-}

	printf "${BLUE}  Building...${NC}"
	docker image pull debian:bullseye-slim
	docker image pull nginx:${NGINX_VERSION}
	docker image build -t ${DOCKER_FULL_IMAGE_NAME}:latest -t ${DOCKER_FULL_IMAGE_NAME}:${NGINX_VERSION} --build-arg NGINX_VERSION=${NGINX_VERSION} ${DOCKER_ARGS} .
	
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
	docker run --rm --name "${DOCKER_IMAGE_NAME}" -d -p 8000:80 ${DOCKER_FULL_IMAGE_NAME}
}

stop_nginx() {
	docker stop "${DOCKER_IMAGE_NAME}"
}

cp_bin() {
	printf "${BLUE}  Copying binaries...${NC}"
	rm -rf bin
	mkdir -p bin
	docker exec jwt-nginx sh -c "tar -chf - \
		/usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so \
		/usr/lib/x86_64-linux-gnu/libjansson.so.* \
		/usr/lib/x86_64-linux-gnu/libjwt.*" 2>/dev/null | tar -xf - -C bin &>/dev/null
}

build_test_runner() {
	DOCKER_ARGS=${1:-}

	export CONTAINER_NAME_PREFIX
	export IMAGE_NAME=${IMAGE_NAME:-${DOCKER_FULL_IMAGE_NAME}}
	export IMAGE_VERSION=${NGINX_VERSION}

	printf "${BLUE}  Building test runner...${NC}"
	docker compose -f ./test/docker-compose-test.yml build ${DOCKER_ARGS}
}

rebuild_test_runner() {
	build_test_runner --no-cache
}

test() {
	export CONTAINER_NAME_PREFIX
	export IMAGE_NAME=${IMAGE_NAME:-${DOCKER_FULL_IMAGE_NAME}}
	export IMAGE_VERSION=${NGINX_VERSION}

	printf "${BLUE}  Running tests...${NC}"
	docker compose -f ./test/docker-compose-test.yml up --no-start
	docker start ${CONTAINER_NAME_PREFIX}
	docker start -a ${CONTAINER_NAME_PREFIX}-runner
	docker compose -f ./test/docker-compose-test.yml down
}

for fn in $@; do
	"$fn"
done