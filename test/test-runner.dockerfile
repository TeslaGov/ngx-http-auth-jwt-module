ARG RUNNER_BASE_IMAGE

FROM ${RUNNER_BASE_IMAGE:?required}
ARG PORT
ARG SSL_PORT

ENV PORT=${PORT:?required}
ENV SSL_PORT=${SSL_PORT:?required}

RUN <<`
  set -e
  apt-get update
  apt-get install -y curl bash
`

COPY test.sh .

CMD ["./test.sh"]
