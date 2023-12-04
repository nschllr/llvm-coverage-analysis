#!/bin/bash

#set -eu
#set -o pipefail
cd $(dirname $0)

source config.sh
cd ..

function yes_no() {
    if [[ "$1" == "yes" || "$1" == "y" ]]; then
        return 0
    else
        return 1
    fi
}

CNAME=${1:-}



if [ -n "$CNAME" ]; then
   CONTAINER_NAME="$CNAME"
fi

container="$(docker ps --filter="name=$CONTAINER_NAME" --latest --quiet)"


if [[ -n "$container" ]]; then
    # Connec to already running container
    echo "[+] Found running instance: $container, connecting..."
    cmd="docker start $container"
    echo "$cmd"
    $cmd
    if [[ -v NO_TTY ]]; then
        HAS_TTY=""
    else
        HAS_TTY="-t"
    fi
    cmd="docker exec -i $HAS_TTY --workdir /home/user/$NAME $container zsh"
    echo "$cmd"
    $cmd
    exit 0
fi

mkdir -p "$PWD/data"
touch "$PWD/data/bash_history"
touch "$PWD/data/zsh_history"
mkdir -p "$PWD/data/ccache"
mkdir -p "$PWD/data/vscode-data"

echo "[+] Creating new container..."
cmd="docker run -t -d --privileged \
    -v $PWD:/home/user/$NAME \
    -v $PWD/data/zshrc:/home/user/.zshrc \
    -v $PWD/data/zsh_history:/home/user/.zsh_history \
    -v $PWD/data/bash_history:/home/user/.bash_history \
    -v $PWD/data/init.vim:/home/user/.config/nvim/init.vim \
    -v $PWD/data/ccache:/ccache
    -v $PWD/data/vscode-data:/home/user/.config/Code
    -v $(readlink -f "$SSH_AUTH_SOCK"):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent \
    --mount type=tmpfs,destination=/tmp,tmpfs-mode=777 \
    --ulimit msgqueue=2097152000 \
    --shm-size=16G \
    --name $CONTAINER_NAME \
    -e AFL_DISABLE_TRIM=1 \
    -e AFL_FAST_CAL=1 \
    -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    -e AFL_IGNORE_UNKNOWN_ENVS=1 \
    -e AFL_KILL_SIGNAL=9 \
    -e AFL_NO_AFFINITY=1 \
    -e AFL_NO_UI=1 \
    -e AFL_SHUFFLE_QUEUE=1 \
    -e AFL_SKIP_CPUFREQ=1 \
    -e AFL_SKIP_CRASHES=1 \
    -e AFL_TESTCACHE_SIZE=2"

# Use local gitconfig if any
if [[ -f "/home/$USER/.gitconfig" ]]; then
    cmd+=" -v /home/$USER/.gitconfig:/home/user/.gitconfig"
fi

CPU_PIN=${2-0}

if [[ $CPU_PIN == *-* ]]; then
    echo "Pinning to CPUs: $CPU_PIN"
    cmd+=" --cpuset-cpus $CPU_PIN"
else
    echo "Pinning to CPU: $CPU_PIN"
    cmd+=" --cpuset-cpus $CPU_PIN-$CPU_PIN"
fi

shift
shift
CMD=${*:-}
if [ -n "$CMD" ]; then
    cmd+=" --workdir /home/user/$NAME "
    cmd+=" ${IMAGE_NAME} $CMD"
    echo "$cmd"
    $cmd
else
    cmd+=" ${IMAGE_NAME} /usr/bin/cat"
    echo "$cmd"
    $cmd
fi


echo "[+] Rerun start.sh to connect to the new container."
