#!/bin/bash -eu

MAGENTA='\u001b[35m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# supported SSL versions
SSL_VERSION_1_1_1w='1.1.1w'
SSL_VERSION_3_0_11='3.0.11'
SSL_VERSION_3_2_1='3.2.1'
SSL_VERSIONS=(${SSL_VERSION_3_2_1})
SSL_VERSION=${SSL_VERSION:-$SSL_VERSION_3_0_11}

declare -A SSL_IMAGE_MAP
SSL_IMAGE_MAP[$SSL_VERSION_1_1_1w]="bullseye-slim:openssl-${SSL_VERSION_1_1_1w}"
SSL_IMAGE_MAP[$SSL_VERSION_3_0_11]="bookworm-slim:openssl-${SSL_VERSION_3_0_11}"
SSL_IMAGE_MAP[$SSL_VERSION_3_2_1]="bookworm-slim:openssl-${SSL_VERSION_3_2_1}"

# supported NGINX versions -- for binary distribution
NGINX_VERSION_LEGACY_1='1.20.2'
NGINX_VERSION_LEGACY_2='1.22.1'
NGINX_VERSION_LEGACY_3='1.24.0'
NGINX_VERSION_STABLE='1.26.2'
NGINX_VERSION_MAINLINE='1.27.2'
NGINX_VERSIONS=(${NGINX_VERSION_LEGACY_1} ${NGINX_VERSION_LEGACY_2} ${NGINX_VERSION_LEGACY_3} ${NGINX_VERSION_STABLE} ${NGINX_VERSION_MAINLINE})
NGINX_VERSION=${NGINX_VERSION:-${NGINX_VERSION_STABLE}}

IMAGE_NAME=${IMAGE_NAME:-nginx-auth-jwt}
FULL_IMAGE_NAME=${ORG_NAME:-teslagov}/${IMAGE_NAME}

TEST_CONTAINER_NAME_PREFIX="${IMAGE_NAME}-test"

all() {
	build_module
	build_test
	test_all
}

verify_and_build_base_image() {
	local image=${SSL_IMAGE_MAP[$SSL_VERSION]}
	local baseImage=${image%%:*}

	if [ -z ${image} ]; then
		echo "Base image not set for SSL version :${SSL_VERSION}"
		exit 1
	else
		printf "${MAGENTA}Building ${baseImage} base image for SSL ${SSL_VERSION}...${NC}\n"
		docker buildx build \
		  --build-arg BASE_IMAGE=debian:${baseImage} \
			--build-arg SSL_VERSION=${SSL_VERSION} \
			-f openssl.dockerfile \
			-t ${image} .
	fi
}

build_module() {
	local dockerArgs=${1:-}
	local baseImage=${SSL_IMAGE_MAP[$SSL_VERSION]}
	
	verify_and_build_base_image

	printf "${MAGENTA}Building module for NGINX ${NGINX_VERSION}...${NC}\n"
	docker buildx build \
		-f nginx.dockerfile \
		-t ${FULL_IMAGE_NAME}:${NGINX_VERSION} \
	  --build-arg BASE_IMAGE=${baseImage} \
		--build-arg NGINX_VERSION=${NGINX_VERSION} \
		${dockerArgs} .
	
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

	printf "${MAGENTA}Starting NGINX container (${IMAGE_NAME}) on port ${port}...${NC}\n"
	docker run --rm --name "${IMAGE_NAME}" -d -p ${port}:80 ${FULL_IMAGE_NAME}:${NGINX_VERSION} >/dev/null
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

	printf "${MAGENTA}Copying binaries to: ${destDir}${NC}\n"
	rm -rf ${destDir}/*
	mkdir -p ${destDir}
	docker exec "${IMAGE_NAME}" sh -c "cd /; tar -chf - \
		usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so \
		usr/lib/x86_64-linux-gnu/libjansson.so.* \
		usr/lib/x86_64-linux-gnu/libjwt.*" | tar -xf - -C ${destDir} &>/dev/null
	
	if [ $stopContainer ]; then
		printf "${MAGENTA}Stopping NGINX container (${IMAGE_NAME})...${NC}\n"
		stop_nginx
	fi
}

make_release() {
	local moduleVersion=${1}
	
	NGINX_VERSION=${2}

	printf "${MAGENTA}Making release for version ${moduleVersion} for NGINX ${NGINX_VERSION}...${NC}\n"

	rebuild_module
	rebuild_test
	test
	cp_bin

	mkdir -p release
	tar -czvf release/ngx_http_auth_jwt_module_${moduleVersion}_nginx_${NGINX_VERSION}.tgz \
		README.md \
		-C bin/usr/lib64/nginx/modules ngx_http_auth_jwt_module.so > /dev/null
}

# Create releases for the current mainline and stable version, as well as the 2 most recent "legacy" versions.
#   See: https://nginx.org/en/download.html
make_releases() {
	local moduleVersion=$(git describe --tags --abbrev=0)

	rm -rf release/*

	for v in ${NGINX_VERSIONS[@]}; do
		make_release ${moduleVersion} ${v}
	done
}

build_test() {
	local dockerArgs=${1:-}
	local port=$(get_port)
	local sslPort=$(get_port $((port + 1)))
	local runnerBaseImage=${SSL_IMAGE_MAP[$SSL_VERSION]}
	
	export TEST_CONTAINER_NAME_PREFIX
	export FULL_IMAGE_NAME
	export NGINX_VERSION

	printf "${MAGENTA}Building test NGINX & runner using port ${port}...${NC}\n"
	docker compose \
	  -p ${TEST_CONTAINER_NAME_PREFIX} \
	  -f ./test/docker-compose-test.yml build \
	  --build-arg RUNNER_BASE_IMAGE=${runnerBaseImage} \
		--build-arg PORT=${port} \
		--build-arg SSL_PORT=${sslPort} \
		 ${dockerArgs}
}

rebuild_test() {
	build_test --no-cache
}

test_all() {
	for SSL_VERSION in "${SSL_VERSIONS[@]}"; do
		for NGINX_VERSION in "${NGINX_VERSIONS[@]}"; do
			test
		done
	done
}

test() {
	build_module
	build_test

	printf "${MAGENTA}Running tests...${NC}\n"
	docker compose \
	  -p ${TEST_CONTAINER_NAME_PREFIX} \
		-f ./test/docker-compose-test.yml up \
		--no-start


	trap 'docker compose -f ./test/docker-compose-test.yml down' 0

	test_now
}

test_now() {
	nginxContainerName="${TEST_CONTAINER_NAME_PREFIX}-nginx"
	runnerContainerName="${TEST_CONTAINER_NAME_PREFIX}-runner"

	docker start ${nginxContainerName}
	
	if [ "$(docker container inspect -f '{{.State.Running}}' ${nginxContainerName})" != "true" ]; then
		printf "${RED}Failed to start container \"${nginxContainerName}\". See logs below:\n"
		docker logs ${nginxContainerName}
		printf "${NC}\n"
		return
	fi

	docker start -a ${runnerContainerName}

	echo
	echo "Tests were executed with the following options:"
	echo "    SSL Version: ${SSL_VERSION}"
	echo "  NGINX Version: ${NGINX_VERSION}"
}

get_port() {
	startPort=${1:-8000}
	endPort=$((startPort + 100))

	for p in $(seq ${startPort} ${endPort}); do
		if ! ss -ln | grep -q ":${p} "; then
			echo ${p}
			break
		fi
	done
}

if [ $# -eq 0 ]; then
	all
else
	fn=$1
	shift
	
	${fn} "$@"
fi
