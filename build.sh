#!/bin/bash

# build
DOCKER_IMAGE_NAME=jwt-nginx
docker build -t ${DOCKER_IMAGE_NAME} .
CONTAINER_ID=$(docker run -itd ${DOCKER_IMAGE_NAME} sh)

# setup test
rm -rf ./lib
rm -rf ./modules
mkdir modules
DOCKER_TEST_IMAGE_NAME=jwt-nginx-test
docker build -t ${DOCKER_TEST_IMAGE_NAME} test/.
CONTAINER_TEST_ID=$(docker run -p 8000:8000 -itd ${DOCKER_TEST_IMAGE_NAME} sh)
docker cp ${CONTAINER_ID}:/usr/local/lib .
docker cp lib ${CONTAINER_TEST_ID}:/usr/local
docker cp ${CONTAINER_ID}:/root/dl/nginx/objs/ngx_http_auth_jwt_module.so modules/.
docker cp modules/ngx_http_auth_jwt_module.so ${CONTAINER_TEST_ID}:/usr/lib64/nginx/modules/.
docker cp resources/test-jwt-nginx.conf ${CONTAINER_TEST_ID}:/etc/nginx/conf.d/test-jwt-nginx.conf
docker cp resources/nginx.conf ${CONTAINER_TEST_ID}:/etc/nginx/.

docker exec -d ${CONTAINER_TEST_ID} /bin/bash -c "export LD_LIBRARY_PATH=/usr/local/lib && nginx" 




