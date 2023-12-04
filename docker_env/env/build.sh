#!/bin/bash

set -eu
set -o pipefail
cd $(dirname $0)

source config.sh
cd ..
echo "starting build"
docker build --build-arg USER_UID="$(id -u)" --build-arg USER_GID="$(id -g)" $@ -t $IMAGE_NAME .
