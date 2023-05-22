#!/bin/bash

# Function test on local host.
# Author: zhsh.
# Environment: Debian-based(or Ubuntu-based), apt.

# How to use built file to achieve project gaol.
# 1. Run the binary file.
ecli run src/package.json

# 2. Run with Github Packages locally.
# docker run --rm -it --privileged -v $(pwd):/examples ghcr.io/eunomia-bpf/eunomia-template:latest