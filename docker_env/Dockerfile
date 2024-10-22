FROM ubuntu:22.04

ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND noninteractive
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=25G

RUN yes | unminimize
RUN apt update -y
RUN apt install -y \
    man build-essential clang clangd \
    zsh powerline fonts-powerline \
    wget htop curl git sudo neovim file \
    gcc gdb strace ltrace tree nasm \
    ninja-build bear cmake pkg-config libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
    patchelf python3 python3-pip python3-dev automake cmake flex bison libglib2.0-dev libpixman-1-dev nano \
    python3-setuptools cargo libgtk-3-dev texinfo tmux lsb-release wget software-properties-common gnupg \
    imagemagick

LLVM_VERSION=14

RUN apt install -y lld-$LLVM_VERSION llvm-$LLVM_VERSION llvm-$LLVM_VERSION-dev clang-$LLVM_VERSION || apt install -y lld llvm llvm-dev clang
RUN apt install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

COPY env/check_env.sh /usr/local/bin/

RUN echo "/project/target/debug" > /etc/ld.so.conf.d/frt.conf

#Enable sudo group
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Create default user "user"
RUN groupadd -g ${USER_GID} user
RUN useradd -l --shell /bin/bash -c "" -m -u ${USER_UID} -g user -G sudo user

RUN mkdir /project
RUN chown -R ${USER_UID}:${USER_GID} /project

RUN LLVM_CONFIG=llvm-config-$LLVM_VERSION make all -j
RUN make install

USER user

WORKDIR /home/user/

# Install zsh
RUN sh -c "$(wget -O- https://raw.githubusercontent.com/deluan/zsh-in-docker/master/zsh-in-docker.sh)"
RUN export LLVM_CONFIG=llvm-config-$LLVM_VERSION

RUN pip install inotify psutil matplotlib natsort
