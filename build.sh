#!/bin/bash

# build
DOCKER_IMAGE_NAME=jwt-nginx
docker build -t ${DOCKER_IMAGE_NAME} .
CONTAINER_ID=$(docker run --name "${DOCKER_IMAGE_NAME}-cont" -d -p 8000:8000 ${DOCKER_IMAGE_NAME})

MACHINE_IP=`docker-machine ip`

RED='\033[01;31m'
GREEN='\033[01;32m'
NONE='\033[00m'

VALIDJWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwgImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwgInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwgImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwgImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.TvDD63ZOqFKgE-uxPDdP5aGIsbl5xPKz4fMul3Zlti4

TEST_INSECURE_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000`
if [ "$TEST_INSECURE_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Insecure test pass ${TEST_INSECURE_EXPECT_200}${NONE}";
else
  echo -e "${RED}Insecure test fail ${TEST_INSECURE_EXPECT_200}${NONE}";
fi

TEST_SECURE_EXPECT_302=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html`
if [ "$TEST_SECURE_EXPECT_302" -eq "302" ];then
  echo -e "${GREEN}Secure test without jwt pass ${TEST_SECURE_EXPECT_302}${NONE}";
else
  echo -e "${RED}Secure test without jwt fail ${TEST_SECURE_EXPECT_302}${NONE}";
fi

TEST_SECURE_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html -H 'cache-control: no-cache' --cookie "rampartjwt=${VALIDJWT}"`
if [ "$TEST_SECURE_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with jwt pass ${TEST_SECURE_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with jwt fail ${TEST_SECURE_EXPECT_200}${NONE}";
fi

TEST_SECURE_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html -H 'cache-control: no-cache' --header "Authorization: Bearer ${VALIDJWT}" --cookie "rampartjwt=${VALIDJWT}"`
if [ "$TEST_SECURE_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with jwt and auth header pass ${TEST_SECURE_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with jwt and auth header fail ${TEST_SECURE_EXPECT_200}${NONE}";
fi
