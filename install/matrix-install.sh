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
$STD apt-get install -y ca-certificates
$STD apt-get install -y gpg
$STD apt-get install -y wget
UBUNTU_CODENAME=jammy
$STD wget -qO- "https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=get&search=0x6125E2A8C77F2818FB7BD15B93C4A3FD7BB9C367" | gpg --dearmour -o /usr/share/keyrings/ansible-archive-keyring.gpg
$STD echo "deb [signed-by=/usr/share/keyrings/ansible-archive-keyring.gpg] http://ppa.launchpad.net/ansible/ansible/ubuntu $UBUNTU_CODENAME main" | tee /etc/apt/sources.list.d/ansible.list
$STD apt update && apt-get install ansible
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
