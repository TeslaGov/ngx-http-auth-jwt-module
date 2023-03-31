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
	build_module
	build_test_runner
	test
}

build_module() {
	local dockerArgs=${1:-}
	local sourceHash=$(get_hash config src/*)

	printf "${BLUE}Pulling images...${NC}\n"
	docker image pull debian:bullseye-slim
	docker image pull nginx:${NGINX_VERSION}

	printf "${BLUE}Building module...${NC}\n"
	docker image build -t ${FULL_IMAGE_NAME}:latest -t ${FULL_IMAGE_NAME}:${NGINX_VERSION} ${dockerArgs} \
		--build-arg NGINX_VERSION=${NGINX_VERSION} \
		--build-arg SOURCE_HASH=${sourceHash} \.
	
	if [ "$?" -ne 0 ]; then
		printf "${RED}✘ Build failed ${NC}\n"
	else
		printf "${GREEN}✔ Successfully built NGINX module ${NC}\n"
	fi

	docker rmi -f $(docker images --filter=label=stage=ngx_http_auth_jwt_builder --quiet) 2> /dev/null || true
}

rebuild_module() {
	build_module --no-cache
}

start_nginx() {
	printf "${BLUE}Starting NGINX...${NC}\n"
	docker run --rm --name "${IMAGE_NAME}" -d -p 8000:80 ${FULL_IMAGE_NAME}
}

stop_nginx() {
	docker stop "${IMAGE_NAME}"
}

cp_bin() {
	if [ "$(docker container inspect -f '{{.State.Running}}' ${IMAGE_NAME})" != "true" ]; then
		start_nginx
	fi

	printf "${BLUE}Copying binaries...${NC}\n"
	rm -rf bin
	mkdir bin
	docker exec "${IMAGE_NAME}" sh -c "cd /; tar -chf - \
		usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so \
		usr/lib/x86_64-linux-gnu/libjansson.so.* \
		usr/lib/x86_64-linux-gnu/libjwt.*" | tar -xf - -C bin &>/dev/null
}

build_test_runner() {
	local dockerArgs=${1:-}
	local configHash=$(get_hash $(find test -type f -not -name 'test.sh' -not -name '*.yml' -not -name 'Dockerfile*'))
	local sourceHash=$(get_hash test/test.sh)

	printf "${BLUE}Building test runner...${NC}\n"
	docker compose -f ./test/docker-compose-test.yml build ${dockerArgs} \
		--build-arg CONFIG_HASH=${configHash}\
		--build-arg SOURCE_HASH=${sourceHash}
}

rebuild_test_runner() {
	build_test_runner --no-cache
}

test() {
	build_test_runner

	printf "${BLUE}Running tests...${NC}\n"
	docker compose -f ./test/docker-compose-test.yml up --no-start
	docker start ${CONTAINER_NAME_PREFIX}
	
	if [ "$(docker container inspect -f '{{.State.Running}}' ${CONTAINER_NAME_PREFIX})" != "true" ]; then
		printf "${RED}Failed to start NGINX test container. See logs below:\n"
		docker logs ${CONTAINER_NAME_PREFIX}
		printf "${NC}\n"
	else
		docker start -a ${CONTAINER_NAME_PREFIX}-runner
	fi

	#docker compose -f ./test/docker-compose-test.yml down
}

test_now() {
	docker start -a ${CONTAINER_NAME_PREFIX}-runner
}

get_hash() {
	sha1sum $@ | sed -E 's|\s+|:|' | tr '\n' ' ' | sha1sum | head -c 40
}

if [ $# -eq 0 ]; then
	all
else
	for fn in $@; do
		"$fn"
	done
fi
