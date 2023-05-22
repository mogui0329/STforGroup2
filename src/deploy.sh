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
# Failed. Error unknown.