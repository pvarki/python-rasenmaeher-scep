#!/bin/bash -l
set -e
# shellcheck disable=SC1091
. /container-init.sh
if [ "$#" -eq 0 ]; then
  # Create the SCEP RA identity before any worker starts. Devices encrypt their certificate
  # requests to this key, and four workers meeting an empty volume would each generate one: the
  # last writer wins and the rest of them can decrypt nothing. Idempotent, so this is a no-op on
  # every start after the first.
  rmscep init-ra
  # FIXME: can we know the traefik/nginx internal docker ip easily ?
  exec gunicorn "rmscep.web.application:get_app()" --bind 0.0.0.0:8000 --forwarded-allow-ips='*' -w 4 -k uvicorn.workers.UvicornWorker
else
  exec "$@"
fi
