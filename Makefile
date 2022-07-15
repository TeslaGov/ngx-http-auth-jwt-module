SHELL += -eu

BLUE  := \033[0;34m
GREEN := \033[0;32m
RED   := \033[0;31m
NC    := \033[0m

DOCKER_ORG_NAME ?= teslagov
DOCKER_IMAGE_NAME ?= jwt-nginx
COMPOSE_PROJECT_NAME ?= jwt-nginx-test
NGINX_VERSION ?= 1.22.0

.PHONY: all
all:
	@$(MAKE) build-nginx
	@$(MAKE) start-nginx
	@$(MAKE) test

.PHONY: build-nginx
build-nginx:
	@echo "${BLUE}  Building...${NC}"
	@docker image pull debian:bullseye-slim
	@docker image pull nginx:${NGINX_VERSION}
	@docker image build -t ${DOCKER_ORG_NAME}/${DOCKER_IMAGE_NAME}:latest -t ${DOCKER_ORG_NAME}/${DOCKER_IMAGE_NAME}:${NGINX_VERSION} --build-arg NGINX_VERSION=${NGINX_VERSION} . ; \
	SUCCESS=$$? ; \
	docker rmi $$(docker images --filter=label=stage=builder --quiet); \
	if [ "$$SUCCESS" -ne 0 ] ; \
	then echo "${RED}  Build failed ${NC}"; \
	else echo "${GREEN}✓ Successfully built NGINX module ${NC}"; fi

.PHONY: rebuild-nginx
rebuild-nginx:
	@echo "${BLUE}  Rebuilding...${NC}"
	@docker image pull debian:bullseye-slim
	@docker image pull nginx:${NGINX_VERSION}
	@docker image build -t ${DOCKER_ORG_NAME}/${DOCKER_IMAGE_NAME}:latest -t ${DOCKER_ORG_NAME}/${DOCKER_IMAGE_NAME}:${NGINX_VERSION} --build-arg NGINX_VERSION=${NGINX_VERSION} --no-cache .; \
	SUCCESS=$$? ; \
	docker rmi $$(docker images --filter=label=stage=builder --quiet); \
	if [ "$$SUCCESS" -ne 0 ] ; \
	then echo "${RED}  Build failed ${NC}"; \
	else echo "${GREEN}✓ Successfully rebuilt NGINX module ${NC}"; fi

.PHONY: stop-nginx
stop-nginx:
	docker stop "${DOCKER_IMAGE_NAME}"

.PHONY: start-nginx
start-nginx:
	docker run --rm --name "${DOCKER_IMAGE_NAME}" -d -p 8000:80 ${DOCKER_ORG_NAME}/${DOCKER_IMAGE_NAME}

.PHONY: cp-bin
cp-bin: start-nginx
	rm -rf bin
	mkdir -p bin
	docker exec jwt-nginx sh -c "tar -chf - \
		/usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so \
		/usr/lib/x86_64-linux-gnu/libjansson.so.* \
		/usr/lib/x86_64-linux-gnu/libjwt.*" 2>/dev/null | tar -xf - -C bin &>/dev/null

.PHONY: build-test-runner
build-test-runner:
	IMAGE_VERSION=${NGINX_VERSION} docker compose -f ./docker-compose-test.yml build

.PHONY: rebuild-test-runner
rebuild-test-runner:
	IMAGE_VERSION=${NGINX_VERSION} docker compose -f ./docker-compose-test.yml build --no-cache

.PHONY: test
test:
	IMAGE_VERSION=${NGINX_VERSION} docker compose -f ./docker-compose-test.yml up --no-start
	docker start ${COMPOSE_PROJECT_NAME}-nginx-1
	docker start -a ${COMPOSE_PROJECT_NAME}-runner-1
	docker compose -f ./docker-compose-test.yml down
