#!/bin/bash

USER_SUFFIX="$(id -u -n)"
NAME="sileo"
IMAGE_NAME="${NAME}-${USER_SUFFIX}:latest"
CONTAINER_NAME="${NAME}-${USER_SUFFIX}"

