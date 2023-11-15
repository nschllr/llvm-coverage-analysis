#!/bin/bash

USER_SUFFIX="$(id -u -n)"
NAME="llvm-calcov"
IMAGE_NAME="${NAME}-${USER_SUFFIX}:latest"
CONTAINER_NAME="${NAME}-${USER_SUFFIX}"

