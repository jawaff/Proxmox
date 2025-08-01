#!/usr/bin/env bash
source <(curl -s https://raw.githubusercontent.com/jawaff/Proxmox/main/misc/build.func)
# Copyright (c) 2021-2024 tteck
# Author: tteck (tteckster)
# License: MIT
# https://github.com/tteck/Proxmox/raw/main/LICENSE

function header_info {
clear
cat <<"EOF"
    __  ___      __       _     
   /  |/  /___ _/ /______(_)  __
  / /|_/ / __ `/ __/ ___/ / |/_/
 / /  / / /_/ / /_/ /  / />  <  
/_/  /_/\__,_/\__/_/  /_/_/|_|  
EOF
}
header_info
echo -e "Loading..."
APP="Matrix"
var_disk="50"
var_cpu="4"
var_ram="4096"
var_os="debian"
var_version="12"
variables
color
catch_errors

function default_settings() {
  CT_TYPE="1"
  PW=""
  CT_ID=$NEXTID
  HN=$NSAPP
  DISK_SIZE="$var_disk"
  CORE_COUNT="$var_cpu"
  RAM_SIZE="$var_ram"
  BRG="vmbr0"
  NET="dhcp"
  GATE=""
  APT_CACHER=""
  APT_CACHER_IP=""
  DISABLEIP6="no"
  MTU=""
  SD=""
  NS=""
  MAC=""
  VLAN=""
  SSH="no"
  VERB="no"
  echo_default
}

function update_script() {
header_info
if [[ ! -f /etc/systemd/system/matrix.service ]]; then msg_error "No ${APP} Installation Found!"; exit; fi
msg_info "Updating $APP LXC"
apt-get update &>/dev/null
pip install passlib --upgrade
cd /opt/matrix-docker-ansible-deploy
./just update
ansible-playbook -i inventory/hosts setup.yml --tags=setup-all
msg_ok "Updated $APP LXC"
exit
}

start
build_container
description

msg_ok "Completed Successfully!\n"
