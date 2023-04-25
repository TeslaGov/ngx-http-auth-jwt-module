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
		--build-arg SOURCE_HASH=${sourceHash} .
	
	if [ "$?" -ne 0 ]; then
		printf "${RED}✘ Build failed ${NC}\n"
	else
		printf "${GREEN}✔ Successfully built NGINX module ${NC}\n"
	fi
}

rebuild_module() {
	clean_module
	build_module --no-cache
}

clean_module() {
	docker rmi -f $(docker images --filter=label=stage=ngx_http_auth_jwt_builder --quiet) 2> /dev/null || true
}

start_nginx() {
	local port=$(get_port)

	printf "${BLUE}Starting NGINX container (${IMAGE_NAME}) on port ${port}...${NC}\n"
	docker run --rm --name "${IMAGE_NAME}" -d -p ${port}:80 ${FULL_IMAGE_NAME} >/dev/null
}

stop_nginx() {
	docker stop "${IMAGE_NAME}" >/dev/null
}

cp_bin() {
	local destDir=bin
	local stopContainer=0;

	if [ "$(docker container inspect -f '{{.State.Running}}' ${IMAGE_NAME} | true)" != "true" ]; then
		start_nginx
		stopContainer=1
	fi

	printf "${BLUE}Copying binaries to: ${destDir}${NC}\n"
	rm -rf ${destDir}/*
	mkdir -p ${destDir}
	docker exec "${IMAGE_NAME}" sh -c "cd /; tar -chf - \
		usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so \
		usr/lib/x86_64-linux-gnu/libjansson.so.* \
		usr/lib/x86_64-linux-gnu/libjwt.*" | tar -xf - -C ${destDir} &>/dev/null
	
	if [ $stopContainer ]; then
		printf "${BLUE}Stopping NGINX container (${IMAGE_NAME})...${NC}\n"
		stop_nginx
	fi
}

make_release() {
	printf "${BLUE}Making release for version ${NGINX_VERSION}...${NC}\n"

	build_module
	cp_bin

	mkdir -p release
	tar -czvf release/ngx_http_auth_jwt_module_${NGINX_VERSION}.tgz \
		README.md \
		-C bin/usr/lib64/nginx/modules ngx_http_auth_jwt_module.so > /dev/null
}

# Create releases for the current mainline and stable version, as well as the 2 most recent "legacy" versions.
#   See: https://nginx.org/en/download.html
make_releases() {
	VERSIONS=(1.20.2 1.22.1 1.24.0 1.23.4)
	
	rm -rf release/*

	for v in ${VERSIONS[@]}; do
		NGINX_VERSION=${v} make_release
	done
}


build_test_runner() {
	local dockerArgs=${1:-}
	local configHash=$(get_hash $(find test -type f -not -name 'test.sh' -not -name '*.yml' -not -name 'Dockerfile*'))
	local sourceHash=$(get_hash test/test.sh)
	local port=$(get_port)
	
	printf "${BLUE}Building test runner using port ${port}...${NC}\n"
	docker compose -f ./test/docker-compose-test.yml build ${dockerArgs} \
		--build-arg CONFIG_HASH=${configHash}\
		--build-arg SOURCE_HASH=${sourceHash} \
		--build-arg PORT=${port}
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
		test_now
	fi

	docker compose -f ./test/docker-compose-test.yml down
}

test_now() {
	docker start -a ${CONTAINER_NAME_PREFIX}-runner
}

get_hash() {
	sha1sum $@ | sed -E 's|\s+|:|' | tr '\n' ' ' | sha1sum | head -c 40
}

get_port() {
	for p in $(seq 8000 8100); do
		if ! ss -ln | grep -q ":${p} "; then
			echo ${p}
			break
		fi
	done
}

if [ $# -eq 0 ]; then
	all
else
	for fn in "$@"; do
		${fn}
	done
fi
