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

sudo ldconfig
if ! ldconfig -N -v 2>/dev/null | grep -q "libsource_agent.so"; then
    log_error "[!] Failed to find libsource_agent.so!"
    rebuild
fi

log_success "[+] Your environment looks superb .. just like you do!"
