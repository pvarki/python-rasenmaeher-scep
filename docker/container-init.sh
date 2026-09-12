#!/bin/bash -l
set -e
# Make sure the RASENMAEHER endpoints point to the correct IP, 127.0.0.1 is this containers localhost...
test -x /pvarki/hosts_script.sh && . /pvarki/hosts_script.sh

# Make sure the data directories exist
DATA_DIR=${RMSCEP_DATA_DIR:-/data/persistent}
test -d "${DATA_DIR}/private" || ( mkdir -p "${DATA_DIR}/private" && chmod og-rwx "${DATA_DIR}/private" )
test -d "${DATA_DIR}/public" || mkdir -p "${DATA_DIR}/public"
