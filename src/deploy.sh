#!/bin/bash

# Deployment test on local host.
# Author: zhsh.
# Environment: Debian-based(or Ubuntu-based), apt.

# Get started.
sudo apt update && sudo apt install -y direnv
curl -sfL https://direnv.net/install.sh | bash
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
direnv allow
make build
# Failed. How to cause error is unknown for development group.
# Error Message:
# cd src && gcc template.bpf.c template.htemplate.bpf.c:3:10: fatal error: vmlinux.h: No such file or directory
# 3#include "vmlinux .h"
# >2222222222compilation terminated.template.h:16:9: error: unknown type name
# bool exit_event;16
# >222
# make: x** [Makefile:2: build] Error 1