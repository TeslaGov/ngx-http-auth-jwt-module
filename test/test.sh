#!/bin/bash

# set a test # here to execute only that test and output additional info
DEBUG=

RED='\e[31m'
GREEN='\e[32m'
GRAY='\e[90m'
NC='\e[00m'

NUM_TESTS=0;
NUM_SKIPPED=0;
NUM_FAILED=0;

run_test () {
  NUM_TESTS=$((${NUM_TESTS} + 1));

  if [ "${DEBUG}" == '' ] || [ ${DEBUG} == ${NUM_TESTS} ]; then
    local OPTIND;
    local name=''
    local path=''
    local expectedCode=''
    local expectedResponseRegex=''
    local extraCurlOpts=''
    local curlCommand=''
    local exitCode=''
    local response=''
    local testNum="${GRAY}${NUM_TESTS}${NC}\t"

    while getopts "n:p:r:c:x:" option; do
      case $option in
      n)
        name=$OPTARG;;
      p)
        path=$OPTARG;;
      c)
        expectedCode=$OPTARG;;
      r)
        expectedResponseRegex=$OPTARG;;
      x)
        extraCurlOpts=$OPTARG;;
      \?) # Invalid option
        printf "Error: Invalid option\n";
        exit;;
      esac
    done

    curlCommand="curl -s -v http://nginx:8000${path} -H 'Cache-Control: no-cache' ${extraCurlOpts} 2>&1"
    response=$(eval "${curlCommand}")
    exitCode=$?
    
    printf "\n${testNum}"

    if [ "${exitCode}" -ne "0" ]; then
      printf "${RED}${name} -- unexpected exit code from cURL\n\tcURL Exit Code: ${exitCode}";
      NUM_FAILED=$((${NUM_FAILED} + 1));
    else
      OKAY=1

      if [ "${expectedCode}" != "" ]; then
        local responseCode=$(echo "${response}" | grep -Eo 'HTTP/1.1 ([0-9]{3})' | awk '{print $2}')

        if [ "${expectedCode}" != "${responseCode}" ]; then
          printf "${RED}${name} -- unexpected status code\n\tExpected: ${expectedCode}\n\tActual: ${responseCode}\n\tPath: ${path}"
          NUM_FAILED=$((${NUM_FAILED} + 1))
          OKAY=0
        fi
      fi

      if [ "${OKAY}" == "1" ] && [ "${expectedResponseRegex}" != "" ] && echo "${response}" | grep -Eq "${expectedResponseRegex}"; then
        printf "${RED}${name} -- regex not found in response\n\tPath: ${path}\n\tRegEx: ${expectedResponseRegex}"
        NUM_FAILED=$((${NUM_FAILED} + 1))
        OKAY=0
      fi
      
      if [ "${OKAY}" == "1" ]; then
        printf "${GREEN}${name}";
      fi
    fi

    if [ "${DEBUG}" == "${NUM_TESTS}" ]; then
      printf '\n\tcURL Command: %s' "${curlCommand:---}"
      printf '\n\tResponse: %s' "${response:---}"
    fi

    printf "${NC}\n"
  else
    NUM_SKIPPED=$((${NUM_SKIPPED} + 1))
  fi
}

main() {
  local JWT_HS256_VALID=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsImVtYWlsQWRkcmVzcyI6ImhlbGxvd29ybGRAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ0aGlzIiwidGhhdCIsInRoZW90aGVyIl0sImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDAsInVzZXJuYW1lIjoiaGVsbG8ud29ybGQifQ.r8tG8IZheiQ-i6HqUYyJj9V6dipgcQ4ZIdxau6QCZDo
  local JWT_HS256_MISSING_SUB=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdE5hbWUiOiJoZWxsbyIsImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwicm9sZXMiOlsidGhpcyIsInRoYXQiLCJ0aGVvdGhlciJdLCJpc3MiOiJpc3N1ZXIiLCJwZXJzb25JZCI6Ijc1YmIzY2M3LWI5MzMtNDRmMC05M2M2LTE0N2IwODJmYWRiNSIsImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.lD6jUsazVtzeGhRTNeP_b2Zs6O798V2FQql11QOEI1Q
  local JWT_HS256_MISSING_EMAIL=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwiaXNzIjoiaXNzdWVyIiwicGVyc29uSWQiOiI3NWJiM2NjNy1iOTMzLTQ0ZjAtOTNjNi0xNDdiMDgyZmFkYjUiLCJleHAiOjE5MDg4MzUyMDAsImlhdCI6MTQ4ODgxOTYwMCwidXNlcm5hbWUiOiJoZWxsby53b3JsZCJ9.tJoAl_pvq95hK7GKqsp5TU462pLTbmSYZc1fAHzcqWM
  local JWT_HS384_VALID=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsImVtYWlsQWRkcmVzcyI6ImhlbGxvd29ybGRAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ0aGlzIiwidGhhdCIsInRoZW90aGVyIl0sImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDAsInVzZXJuYW1lIjoiaGVsbG8ud29ybGQifQ.SS57j7PEybjbsp3g5W-IhhJHBmG5K-97qvgBKL16xj9ey-uMeEenWjGbB2vVp0kq
  local JWT_HS512_VALID=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsImVtYWlsQWRkcmVzcyI6ImhlbGxvd29ybGRAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ0aGlzIiwidGhhdCIsInRoZW90aGVyIl0sImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDAsInVzZXJuYW1lIjoiaGVsbG8ud29ybGQifQ.xtSU6EWN2LILVsYzJFJpKnRkqjn_3qjz-J2ttNKnhZ60_5YjFeC8io4k8k1u77zlohSWvWMdugD9ZaB3vjJo-w
  local JWT_RS256_VALID=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwgImxhc3ROYW1lIjoid29ybGQiLCJlbWFpbEFkZHJlc3MiOiJoZWxsb3dvcmxkQGV4YW1wbGUuY29tIiwgInJvbGVzIjpbInRoaXMiLCJ0aGF0IiwidGhlb3RoZXIiXSwgImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwgImV4cCI6MTkwODgzNTIwMCwiaWF0IjoxNDg4ODE5NjAwLCJ1c2VybmFtZSI6ImhlbGxvLndvcmxkIn0.cn5Gb75XL-r7TMsPuqzWoKZ06ZsyF_VZIG0Ohn8uZZFeF8dFUhSrEOYe8WFN6Eon8a8LC0OCI9eNdGiD4m_e9TD1Iz2juqaeos-6yd7SWuODr4YS8KD3cqfXndnLRPzp9PC_UIpATsbqOmxGDrRKvHsQq0TuIXImU3rM_m3kFJFgtoJFHx3KmZUo_Ozkyhhc6Pukikhy6odNAtEyLHP5_tabMXtkeAuIlG8dhjAxef4mJLexYFclG-vl7No5VBU4JrMbfgyxtobcYoE-bDIpmQHywrwo6Li7X0hgHJ17sfS3G2YMHmE-Ij_W2Lf9kf5r2r12DUvg44SLIfM58pCINQ
  local JWT_RS256_INVALID=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsImVtYWlsQWRkcmVzcyI6ImhlbGxvd29ybGRAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ0aGlzIiwidGhhdCIsInRoZW90aGVyIl0sImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDAsInVzZXJuYW1lIjoiaGVsbG8ud29ybGQifQ._aQmIBL4CVBxU1fNMOHp0kkagFaaX2TvAEenizytwd0
  local JWT_RS384_VALID=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsImVtYWlsQWRkcmVzcyI6ImhlbGxvd29ybGRAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ0aGlzIiwidGhhdCIsInRoZW90aGVyIl0sImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDAsInVzZXJuYW1lIjoiaGVsbG8ud29ybGQifQ.H35bTcZRhepWIoa8pKCbUMRuAOkVX9K5hJjc6tPmQwWmTw8lrktsvmMzJg_rgqnJLnAkciSIQw5EDj7fngS5zX2ThyRxrkPuE2Uiyw2Ect-mo9Kg1lrWgnyZCuCgq-Up9HQRAv0160mePlm8Gs4TOY6CPr38zwTcDZsy_Keq93igDQV8WuuWAGICaGd5ZyUOPjjzGShRjTU8Szz7fnpZpTtYRCYVo0pc5yfRWYm0fdn-4AseyGvd8JJ2xfnAEe4kZOkz7X1MLKtL0slKg3m2PH1lD7HwxIawXRTPWxArhJ9dcTNiDUrqtde2juGwOuMD_zTsb2Jj0_rmRb0Q6aljNw
  local JWT_RS512_VALID=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJzdWIiOiJzb21lLWxvbmctdXVpZCIsImZpcnN0TmFtZSI6ImhlbGxvIiwibGFzdE5hbWUiOiJ3b3JsZCIsImVtYWlsQWRkcmVzcyI6ImhlbGxvd29ybGRAZXhhbXBsZS5jb20iLCJyb2xlcyI6WyJ0aGlzIiwidGhhdCIsInRoZW90aGVyIl0sImlzcyI6Imlzc3VlciIsInBlcnNvbklkIjoiNzViYjNjYzctYjkzMy00NGYwLTkzYzYtMTQ3YjA4MmZhZGI1IiwiZXhwIjoxOTA4ODM1MjAwLCJpYXQiOjE0ODg4MTk2MDAsInVzZXJuYW1lIjoiaGVsbG8ud29ybGQifQ.iUupyKypfXJ5aZWfItSW-mOmx9a4C4X7Yr5p5Fk8W75ZhkOq0EeNfstTxx870brhkdPovBhO2LYI44_HoH9XicQNL6JnFprE0r61eJFngbuzlhRQiWpq0xYrazJWc9zB7_GgL2ZCwtw-Ts3G23Q0632wVm6-d7MKvG7RS8aEjN-MuVGdtLglH3forpItmFxw-if40EQsBL7hncN_XNcQTO4KPHkqmlpac_oKXRrLFDIIt2tB6OOpvY4QcpERoxexp4pi2f-JoINnWX_dU5JnIs3ypVJLQPfoJvxg8fsg3zYrOvMYnfsqOCYoHtZGK0O7jyfFmcGo5v2hLT-CpoF3Zw

  run_test -n 'when auth disabled, should return 200' \
           -p '/' \
           -c '200'
  
  run_test -n 'when auth enabled with default algorithm and no JWT in Authorization header, returns 302' \
           -p '/secure/auth-header/default' \
           -c '302'

  run_test -n 'when auth enabled with default algorithm with no redirect and Authorization header missing Bearer, should return 401' \
           -p '/secure/auth-header/default/no-redirect' \
           -c '401' \
           -x '--header "Authorization: X"'

  run_test -n 'when auth enabled with default algorithm and no JWT cookie, returns 302' \
           -p '/secure/cookie/default' \
           -c '302'

  run_test -n 'when auth enabled with default algorithm with no redirect and no JWT cookie, should return 401' \
           -p '/secure/cookie/default/no-redirect' \
           -c '401'

  run_test -n 'when auth enabled with default algorithm and valid JWT cookie, returns 200' \
           -p '/secure/cookie/default' \
           -c '200' \
           -x "--cookie jwt=${JWT_HS256_VALID}"

  run_test -n 'when auth enabled with default algorithm and valid JWT cookie with no sub, returns 200' \
           -p '/secure/cookie/default' \
           -c '200' \
           -x ' --cookie "jwt=${JWT_HS256_MISSING_SUB}"'

  run_test -n 'when auth enabled with default algorithm and valid JWT cookie with no sub when sub validated, returns 302' \
           -p '/secure/cookie/default/validate-sub' \
           -c '302' \
           -x ' --cookie "jwt=${JWT_HS256_MISSING_SUB}"'

  run_test -n 'when auth enabled with default algorithm and valid JWT cookie with no email, returns 200' \
           -p '/secure/cookie/default' \
           -c '200' \
           -x ' --cookie "jwt=${JWT_HS256_MISSING_EMAIL}"'

  run_test -n 'when auth enabled with HS256 algorithm and valid JWT cookie, returns 200' \
           -p '/secure/cookie/hs256/' \
           -c '200' \
           -x '--cookie "jwt=${JWT_HS256_VALID}"'

  run_test -n 'when auth enabled with HS384 algorithm and valid JWT cookie, returns 200' \
           -p '/secure/cookie/hs384' \
           -c '200' \
           -x '--cookie "jwt=${JWT_HS384_VALID}"'

  run_test -n 'when auth enabled with HS512 algorithm and valid JWT cookie, returns 200' \
           -p '/secure/cookie/hs512' \
           -c '200' \
           -x '--cookie "jwt=${JWT_HS512_VALID}"'

  run_test -n 'when auth enabled with RS256 algorithm and valid JWT cookie, returns 200' \
           -p '/secure/cookie/rs256' \
           -c '200' \
           -x ' --cookie "jwt=${JWT_RS256_VALID}"'

  run_test -n 'when auth enabled with RS256 algorithm via file and valid JWT in Authorization header, returns 200' \
           -p '/secure/auth-header/rs256/file' \
           -c '200' \
           -x '--header "Authorization: Bearer ${JWT_RS256_VALID}"'

  run_test -n 'when auth enabled with RS256 algorithm via file and invalid JWT in Authorization header, returns 401' \
           -p '/secure/auth-header/rs256/file' \
           -c '302' \
           -x '--header "Authorization: Bearer ${JWT_RS256_INVALID}"'

  run_test -n 'when auth enabled with RS384 algorithm via file and valid JWT in Authorization header, returns 200' \
           -p '/secure/auth-header/rs384/file' \
           -c '200' \
           -x '--header "Authorization: Bearer ${JWT_RS256_VALID}"'

  run_test -n 'when auth enabled with RS512 algorithm via file and valid JWT in Authorization header, returns 200' \
           -p '/secure/auth-header/rs512/file' \
           -c '200' \
           -x '--header "Authorization: Bearer ${JWT_RS256_VALID}"'

  run_test -n 'extracts single claim to request header' \
           -p '/secure/extract-claim/request/sub' \
           -r '^Test: sub=some-long-uuid$' \
           -x '--header "Authorization: Bearer ${JWT_HS256_VALID}"'

  run_test -n 'extracts multiple claims (single directive) to request header' \
           -p '/secure/extract-claim/request/name-1' \
           -r '^Test: hello world$' \
           -x '--header "Authorization: Bearer ${JWT_HS256_VALID}"'

  run_test -n 'extracts multiple claims (multiple directives) to request header' \
           -p '/secure/extract-claim/request/name-2' \
           -r '^Test: hello world$' \
           -x '--header "Authorization: Bearer ${JWT_HS256_VALID}"'

  run_test -n 'extracts single claim to response header' \
           -p '/secure/extract-claim/response/sub' \
           -r '^Test: sub=some-long-uuid$' \
           -x '--header "Authorization: Bearer ${JWT_HS256_VALID}"'

  run_test -n 'extracts multiple claims (single directive) to response header' \
           -p '/secure/extract-claim/response/name-1' \
           -r '^Test: hello world$' \
           -x '--header "Authorization: Bearer ${JWT_HS256_VALID}"'

  run_test -n 'extracts multiple claims (multiple directives) to response header' \
           -p '/secure/extract-claim/response/name-2' \
           -r '^Test: hello world$' \
           -x '--header "Authorization: Bearer ${JWT_HS256_VALID}"'

  if [[ "${NUM_FAILED}" = '0' ]]; then
    printf "\nRan ${NUM_TESTS} tests successfully (skipped ${NUM_SKIPPED}).\n"
    return 0
  else
    printf "\nRan ${NUM_TESTS} tests: ${GREEN}$((${NUM_TESTS} - ${NUM_FAILED})) passed${NC}; ${RED}${NUM_FAILED} failed${NC}; ${NUM_SKIPPED} skipped\n"
    return 1
  fi
}

if [ "${DEBUG}" != '' ]; then
 printf "\n${RED}Some tests will be skipped since DEBUG is set.${NC}\n"
fi

main
