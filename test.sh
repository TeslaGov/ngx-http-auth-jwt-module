#!/usr/bin/env bash

set -e

RED='\033[01;31m'
GREEN='\033[01;32m'
NONE='\033[00m'

DOCKER_IMAGE_NAME=jwt-nginx
CONTAINER_ID=$(docker run --rm --name "${DOCKER_IMAGE_NAME}-cont" -d -p 8000:8000 ${DOCKER_IMAGE_NAME})

if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux"* ]]; then
  # Mac OSX / Linux
  MACHINE_IP='localhost'
else
  # Windows
  MACHINE_IP=`docker-machine ip 2> /dev/null`
fi

docker cp ${CONTAINER_ID}:/usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so .

VALIDJWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwgImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwgInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwgImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwgImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.TvDD63ZOqFKgE-uxPDdP5aGIsbl5xPKz4fMul3Zlti4
MISSING_SUB_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdE5hbWUiOiJoZWxsbyIsImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwicm9sZXMiOlsidGhpcyIsInRoYXQiLCJ0aGVvdGhlciJdLCJpc3MiOiJpc3N1ZXIiLCJwZXJzb25JZCI6Ijc1YmIzY2M3LWI5MzMtNDRmMC05M2M2LTE0N2IwODJmYWRiNSIsImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.lD6jUsazVtzeGhRTNeP_b2Zs6O798V2FQql11QOEI1Q
MISSING_EMAIL_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwiaXNzIjoiaXNzdWVyIiwicGVyc29uSWQiOiI3NWJiM2NjNy1iOTMzLTQ0ZjAtOTNjNi0xNDdiMDgyZmFkYjUiLCJleHAiOjE5MDg4MzUyMDAsImlhdCI6MTQ4ODgxOTYwMCwidXNlcm5hbWUiOiJoZWxsby53b3JsZCJ9.tJoAl_pvq95hK7GKqsp5TU462pLTbmSYZc1fAHzcqWM
VALID_RS256_JWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwgImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwgInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwgImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwgImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.cn5Gb75XL-r7TMsPuqzWoKZ06ZsyF_VZIG0Ohn8uZZFeF8dFUhSrEOYe8WFN6Eon8a8LC0OCI9eNdGiD4m_e9TD1Iz2juqaeos-6yd7SWuODr4YS8KD3cqfXndnLRPzp9PC_UIpATsbqOmxGDrRKvHsQq0TuIXImU3rM_m3kFJFgtoJFHx3KmZUo_Ozkyhhc6Pukikhy6odNAtEyLHP5_tabMXtkeAuIlG8dhjAxef4mJLexYFclG-vl7No5VBU4JrMbfgyxtobcYoE-bDIpmQHywrwo6Li7X0hgHJ17sfS3G2YMHmE-Ij_W2Lf9kf5r2r12DUvg44SLIfM58pCINQ

test_jwt () {
  name=$1
  path=$2
  expect=$3
  extra=$4

  cmd="curl -X GET -o /dev/null --silent --head --write-out '%{http_code}' http://$MACHINE_IP:8000$path -H 'cache-control: no-cache' $extra"

  test=$( eval ${cmd} )
  if [ "$test" -eq "$expect" ];then
    echo -e "${GREEN}${name}: passed (${test})${NONE}";
  else
    echo -e "${RED}${name}: failed (${test})${NONE}";
  fi
}

test_jwt "Insecure test" "/" "200"

test_jwt "Secure test without jwt cookie" "/secure/" "302"

test_jwt "Secure test with jwt cookie" "/secure/" "200" "--cookie \"rampartjwt=${VALIDJWT}\""

test_jwt "Secure test with jwt auth header" "/secure-auth-header/" "200" "--header \"Authorization: Bearer ${VALIDJWT}\""

test_jwt "Secure test without jwt auth header" "/secure-auth-header/" "302"

test_jwt "Secure test without jwt auth header" "/secure-no-redirect/" "401"

test_jwt "Secure test with jwt cookie - with no sub" "/secure/" "200" " --cookie \"rampartjwt=${MISSING_SUB_JWT}\""

test_jwt "Secure test with jwt cookie - with no email" "/secure/" "200" " --cookie \"rampartjwt=${MISSING_EMAIL_JWT}\""

test_jwt "Secure test with rs256 jwt cookie" "/secure-rs256/" "200" " --cookie \"rampartjwt=${VALID_RS256_JWT}\""

docker stop ${CONTAINER_ID} > /dev/null
