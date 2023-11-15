#!/bin/bash

set -eu
set -o pipefail
cd $(dirname $0)

source config.sh

cd ..
docker build --build-arg USER_UID="$(id -u)" --build-arg USER_GID="$(id -g)" $@ -t $IMAGE_NAME .
