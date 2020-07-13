SHELL += -eu

BLUE  := \033[0;34m
GREEN := \033[0;32m
RED   := \033[0;31m
NC    := \033[0m

DOCKER_ORG_NAME = teslagov
DOCKER_IMAGE_NAME = jwt-nginx

.PHONY: all
all:
	@$(MAKE) build-nginx
	@$(MAKE) build-test-runner
	@$(MAKE) start-nginx
	@$(MAKE) test

.PHONY: build-nginx
build-nginx:
	@echo "${BLUE}  Building...${NC}"
	@docker image build -t $(DOCKER_ORG_NAME)/$(DOCKER_IMAGE_NAME) . ; \
	if [ $$? -ne 0 ] ; \
		then echo "${RED}  Build failed :(${NC}" ; \
	else echo "${GREEN}✓ Successfully built NGINX module ${NC}" ; fi

.PHONY: rebuild-nginx
rebuild-nginx:
	@echo "${BLUE}  Rebuilding...${NC}"
	@docker image build -t $(DOCKER_ORG_NAME)/$(DOCKER_IMAGE_NAME) . --no-cache ; \
	if [ $$? -ne 0 ] ; \
		then echo "${RED}  Build failed :(${NC}" ; \
	else echo "${GREEN}✓ Successfully rebuilt NGINX module ${NC}" ; fi

.PHONY: stop-nginx
stop-nginx:
	docker stop $(shell docker inspect --format="{{.Id}}" "$(DOCKER_IMAGE_NAME)-cont") ||:

.PHONY: start-nginx
start-nginx:
	docker run --rm --name "$(DOCKER_IMAGE_NAME)-cont" -d -p 8000:8000 $(DOCKER_ORG_NAME)/$(DOCKER_IMAGE_NAME)
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so .
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/local/lib/libjansson.so.4.13.0 .
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/local/lib/libjwt.a .
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/local/lib/libjwt.la .
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/local/lib/libjwt.so.0.7.0 .
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/local/lib/pkgconfig/jansson.pc .
	docker cp $(DOCKER_IMAGE_NAME)-cont:/usr/local/lib/pkgconfig/libjwt.pc .

.PHONY: build-test-runner
build-test-runner:
	docker image build -f Dockerfile-test -t $(DOCKER_ORG_NAME)/jwt-nginx-test-runner .

.PHONY: frebuild-test-runner
rebuild-test-runner:
	docker image build -f Dockerfile-test -t $(DOCKER_ORG_NAME)/jwt-nginx-test-runner . --no-cache

.PHONY: test
test:
	docker run --rm $(DOCKER_ORG_NAME)/jwt-nginx-test-runner
