#!/bin/bash

RED='\033[01;31m'
GREEN='\033[01;32m'
NONE='\033[00m'

# build
DOCKER_IMAGE_NAME=jwt-nginx
docker build -t ${DOCKER_IMAGE_NAME} .
if [ $? -ne 0 ]
then
  echo -e "${RED}Build Failed${NONE}";
  exit 1;
fi

CONTAINER_ID=$(docker run --name "${DOCKER_IMAGE_NAME}-cont" -d -p 8000:8000 ${DOCKER_IMAGE_NAME})

if ! MACHINE_IP=`docker-machine ip 2>/dev/null`; then
  MACHINE_IP='0.0.0.0' # fix for MacOS
fi

docker cp ${CONTAINER_ID}:/usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so .

VALIDJWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwgImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwgInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwgImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwgImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.TvDD63ZOqFKgE-uxPDdP5aGIsbl5xPKz4fMul3Zlti4
MISSING_SUB_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdE5hbWUiOiJoZWxsbyIsImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwicm9sZXMiOlsidGhpcyIsInRoYXQiLCJ0aGVvdGhlciJdLCJpc3MiOiJpc3N1ZXIiLCJwZXJzb25JZCI6Ijc1YmIzY2M3LWI5MzMtNDRmMC05M2M2LTE0N2IwODJmYWRiNSIsImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.lD6jUsazVtzeGhRTNeP_b2Zs6O798V2FQql11QOEI1Q
MISSING_EMAIL_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwiaXNzIjoiaXNzdWVyIiwicGVyc29uSWQiOiI3NWJiM2NjNy1iOTMzLTQ0ZjAtOTNjNi0xNDdiMDgyZmFkYjUiLCJleHAiOjE5MDg4MzUyMDAsImlhdCI6MTQ4ODgxOTYwMCwidXNlcm5hbWUiOiJoZWxsby53b3JsZCJ9.tJoAl_pvq95hK7GKqsp5TU462pLTbmSYZc1fAHzcqWM
VALID_RS256_JWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwgImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwgInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwgImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwgImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.cn5Gb75XL-r7TMsPuqzWoKZ06ZsyF_VZIG0Ohn8uZZFeF8dFUhSrEOYe8WFN6Eon8a8LC0OCI9eNdGiD4m_e9TD1Iz2juqaeos-6yd7SWuODr4YS8KD3cqfXndnLRPzp9PC_UIpATsbqOmxGDrRKvHsQq0TuIXImU3rM_m3kFJFgtoJFHx3KmZUo_Ozkyhhc6Pukikhy6odNAtEyLHP5_tabMXtkeAuIlG8dhjAxef4mJLexYFclG-vl7No5VBU4JrMbfgyxtobcYoE-bDIpmQHywrwo6Li7X0hgHJ17sfS3G2YMHmE-Ij_W2Lf9kf5r2r12DUvg44SLIfM58pCINQ

TEST_INSECURE_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000 -H 'cache-control: no-cache'`
if [ "$TEST_INSECURE_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Insecure test pass ${TEST_INSECURE_EXPECT_200}${NONE}";
else
  echo -e "${RED}Insecure test fail ${TEST_INSECURE_EXPECT_200}${NONE}";
fi

TEST_SECURE_COOKIE_EXPECT_302=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html -H 'cache-control: no-cache'`
if [ "$TEST_SECURE_COOKIE_EXPECT_302" -eq "302" ];then
  echo -e "${GREEN}Secure test without jwt cookie pass ${TEST_SECURE_COOKIE_EXPECT_302}${NONE}";
else
  echo -e "${RED}Secure test without jwt cookie fail ${TEST_SECURE_COOKIE_EXPECT_302}${NONE}";
fi

TEST_SECURE_COOKIE_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html -H 'cache-control: no-cache' --cookie "rampartjwt=${VALIDJWT}"`
if [ "$TEST_SECURE_COOKIE_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with jwt cookie pass ${TEST_SECURE_COOKIE_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with jwt cookie fail ${TEST_SECURE_COOKIE_EXPECT_200}${NONE}";
fi

TEST_SECURE_HEADER_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure-auth-header/index.html -H 'cache-control: no-cache' --header "Authorization: Bearer ${VALIDJWT}"`
if [ "$TEST_SECURE_HEADER_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with jwt auth header pass ${TEST_SECURE_HEADER_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with jwt auth header fail ${TEST_SECURE_HEADER_EXPECT_200}${NONE}";
fi

TEST_SECURE_HEADER_EXPECT_302=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure-auth-header/index.html -H 'cache-control: no-cache'`
if [ "$TEST_SECURE_HEADER_EXPECT_302" -eq "302" ];then
  echo -e "${GREEN}Secure test without jwt auth header pass ${TEST_SECURE_HEADER_EXPECT_302}${NONE}";
else
  echo -e "${RED}Secure test without jwt auth header fail ${TEST_SECURE_HEADER_EXPECT_302}${NONE}";
fi

TEST_SECURE_NO_REDIRECT_EXPECT_401=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure-no-redirect/index.html -H 'cache-control: no-cache'`
if [ "$TEST_SECURE_NO_REDIRECT_EXPECT_401" -eq "401" ];then
  echo -e "${GREEN}Secure test without jwt no redirect pass ${TEST_SECURE_NO_REDIRECT_EXPECT_401}${NONE}";
else
  echo -e "${RED}Secure test without jwt no redirect fail ${TEST_SECURE_NO_REDIRECT_EXPECT_401}${NONE}";
fi

TEST_WITH_NO_SUB_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html -H 'cache-control: no-cache' --cookie "rampartjwt=${MISSING_SUB_JWT}"`
if [ "$TEST_WITH_NO_SUB_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with jwt cookie pass ${TEST_WITH_NO_SUB_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with jwt cookie fail ${TEST_WITH_NO_SUB_EXPECT_200}${NONE}";
fi

TEST_WITH_NO_EMAIL_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure/index.html -H 'cache-control: no-cache' --cookie "rampartjwt=${MISSING_EMAIL_JWT}"`
if [ "$TEST_WITH_NO_EMAIL_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with jwt cookie pass ${TEST_WITH_NO_EMAIL_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with jwt cookie fail ${TEST_WITH_NO_EMAIL_EXPECT_200}${NONE}";
fi

TEST_SECURE_RS256_COOKIE_EXPECT_200=`curl -X GET -o /dev/null --silent --head --write-out '%{http_code}\n' http://${MACHINE_IP}:8000/secure-rs256/index.html -H 'cache-control: no-cache' --cookie "rampartjwt=${VALID_RS256_JWT}"`
if [ "$TEST_SECURE_RS256_COOKIE_EXPECT_200" -eq "200" ];then
  echo -e "${GREEN}Secure test with rs256 jwt cookie pass ${TEST_SECURE_RS256_COOKIE_EXPECT_200}${NONE}";
else
  echo -e "${RED}Secure test with rs256 jwt cookie fail ${TEST_SECURE_RS256_COOKIE_EXPECT_200}${NONE}";
fi


