ARG RUNNER_BASE_IMAGE
ARG PORT
ARG SSL_PORT

FROM ${RUNNER_BASE_IMAGE}
ARG PORT
ARG SSL_PORT
ENV PORT=${PORT}
ENV SSL_PORT=${SSL_PORT}
RUN <<`
  set -e
  apt-get update
  apt-get install -y curl bash
`
COPY test.sh .
CMD ./test.sh ${PORT} ${SSL_PORT}
