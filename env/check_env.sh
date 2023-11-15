#!/bin/bash

set -e

text_red=$(tput setaf 1)    # Red
text_green=$(tput setaf 2)  # Green
text_bold=$(tput bold)      # Bold
text_reset=$(tput sgr0)     # Reset your text


function log_error {
    echo "${text_bold}${text_red}${1}${text_reset}"
}

function log_success {
    echo "${text_bold}${text_green}${1}${text_reset}"
}

function rebuild {
    log_success "[+] Building missing files: cd /home/user/fuzztruction/ && cargo build --workspace --all-targets"
    cd /home/user/fuzztruction
    if ! cargo build --workspace --all-targets; then
        log_error "[!] Hmm... build failed... Wrong rustc version?"
        exit 1
    fi
    log_success "[+] Build was successfull!"
}

sudo ldconfig
if ! ldconfig -N -v 2>/dev/null | grep -q "libsource_agent.so"; then
    log_error "[!] Failed to find libsource_agent.so!"
    rebuild
fi
if ! find ~/fuzztruction/source -name fuzztruction-source-rt.a -or -name fuzztruction-source-llvm-pass.so | grep -q .; then
    log_error "[!] Failed to find fuzztruction-source-rt.a or fuzztruction-source-llvm-pass.so !"
    rebuild
fi

log_success "[+] Your environment looks superb .. just like you do!"
