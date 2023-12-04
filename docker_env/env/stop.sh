#!/bin/bash

set -eu
set -o pipefail
cd $(dirname $0)

source config.sh
cd ..

CNAME=${1:-}
if [ -n "$CNAME" ]; then
   CONTAINER_NAME="$CNAME"
fi

container="$(docker ps --filter="name=$CONTAINER_NAME" --latest --quiet)"
if [[ -n "$container" ]]; then
    echo "Found running instance $container, stopping..."
    cmd="docker stop -t 5 $container"
    echo "$cmd"
    $cmd
    cmd="docker rm -f $container"
    echo "$cmd"
    $cmd
else
    echo "No running instance found..."
fi

exit 0
