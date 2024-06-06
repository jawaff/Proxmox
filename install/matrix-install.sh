#!/usr/bin/env bash

# Copyright (c) 2021-2024 tteck
# Author: tteck (tteckster)
# License: MIT
# https://github.com/tteck/Proxmox/raw/main/LICENSE

source /dev/stdin <<< "$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Installing Dependencies"
$STD apt-get install -y curl
$STD apt-get install -y mc
# Dependencies are downloaded according to this document.
# https://github.com/spantaleev/matrix-docker-ansible-deploy/blob/master/docs/prerequisites.md
$STD apt-get install -y sudo
$STD apt-get install -y \
  python3 \
  python3-dev \
  python3-pip
$STD apt-get install -y ansible-core 
$STD pip install passlib
$STD apt-get install -y git
msg_ok "Installed Dependencies"

msg_info "Installing Matrix"
$STD mkdir -p /opt
$STD cd /opt
$STD git clone https://github.com/spantaleev/matrix-docker-ansible-deploy.git
msg_ok "Installed Matrix"

motd_ssh
customize

msg_info "Cleaning up"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"
