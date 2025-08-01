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
$STD apt-get install -y pwgen
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
$STD curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /opt/matrix-docker-ansible-deploy/
$STD cd matrix-docker-ansible-deploy
$STD chmod +x just
$STD ./just roles
msg_ok "Installed Matrix"

msg_info "Creating Default Configurations"
$STD mkdir /opt/matrix-docker-ansible-deploy/inventory
$STD cat <<'EOF' >/opt/matrix-docker-ansible-deploy/inventory/hosts
[matrix_servers]
matrix.BASE_DOMAIN ansible_host=MATRIX_HOST ansible_ssh_user=root
EOF

$STD mkdir -p /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com
$STD cat <<'EOF' >/opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
---
# The bare domain name which represents your Matrix identity.
# Matrix user ids for your server will be of the form (`@user:<matrix-domain>`).
#
# Note: this playbook does not touch the server referenced here.
# Installation happens on another server ("matrix.<matrix-domain>").
#
# If you've deployed using the wrong domain, you'll have to run the Uninstalling step,
# because you can't change the Domain after deployment.
matrix_domain: BASE_DOMAIN

# Serves the well-known file for the base domain.
matrix_static_files_container_labels_base_domain_enabled: true

# The Matrix homeserver software to install.
# See:
#  - `roles/custom/matrix-base/defaults/main.yml` for valid options
# - the `docs/configuring-playbook-IMPLEMENTATION_NAME.md` documentation page, if one is available for your implementation choice
matrix_homeserver_implementation: synapse

# A secret used as a base, for generating various other secrets.
# You can put any string here, but generating a strong one is preferred (e.g. `pwgen -s 64 1`).
matrix_homeserver_generic_secret_key: 'GENERIC_SECRET_KEY'

matrix_synapse_enable_registration: true
matrix_synapse_registration_requires_token: true

matrix_registration_enabled: true
matrix_registration_admin_secret: "REGISTRATION_ADMIN_SECRET"

matrix_synapse_admin_enabled: true

matrix_client_element_enabled: true
matrix_client_element_themes_enabled: true
matrix_client_element_configuration_extension_json: '{
  "features": {
    "feature_video_rooms": true,
    "feature_element_call_video_rooms": true,
    "feature_group_calls": true
  }
}'

# Whitelist for only supporting federation with certain servers.
#matrix_synapse_federation_domain_whitelist:
#  - BASE_DOMAIN
#  - another.com
matrix_synapse_allow_public_rooms_over_federation: true

# By default, the playbook manages its own Traefik (https://doc.traefik.io/traefik/) reverse-proxy server.
# It will retrieve SSL certificates for you on-demand and forward requests to all other components.
# For alternatives, see `docs/configuring-playbook-own-webserver.md`.
matrix_playbook_reverse_proxy_type: playbook-managed-traefik

# Ensure that public urls use https
matrix_playbook_ssl_enabled: true

# Disable the web-secure (port 443) endpoint, which also disables SSL certificate retrieval.
# This has the side-effect of also automatically disabling TLS for the matrix-federation entrypoint
# (by toggling `matrix_federation_traefik_entrypoint_tls`).
traefik_config_entrypoint_web_secure_enabled: false

# If your reverse-proxy runs on another machine, consider using `0.0.0.0:81`, just `81` or `SOME_IP_ADDRESS_OF_THIS_MACHINE:81`
traefik_container_web_host_bind_port: '0.0.0.0:81'

# We bind to `127.0.0.1` by default (see above), so trusting `X-Forwarded-*` headers from
# a reverse-proxy running on the local machine is safe enough.
# If you're publishing the port (`traefik_container_web_host_bind_port` above) to a public network interface:
# - remove the `traefik_config_entrypoint_web_forwardedHeaders_insecure` variable definition below
# - uncomment and adjust the `traefik_config_entrypoint_web_forwardedHeaders_trustedIPs` line below
#traefik_config_entrypoint_web_forwardedHeaders_insecure: true
traefik_config_entrypoint_web_forwardedHeaders_trustedIPs: ['REVERSE_PROXY_HOST']

matrix_playbook_public_matrix_federation_api_traefik_entrypoint_host_bind_port: '0.0.0.0:8449'

# Depending on the value of `matrix_playbook_public_matrix_federation_api_traefik_entrypoint_host_bind_port` above,
# this may need to be reconfigured. See the comments above.
matrix_playbook_public_matrix_federation_api_traefik_entrypoint_config_custom:
  forwardedHeaders:
    #  insecure: true
    trustedIPs: ['REVERSE_PROXY_HOST']

# A Postgres password to use for the superuser Postgres user (called `matrix` by default).
#
# The playbook creates additional Postgres users and databases (one for each enabled service)
# using this superuser account.
postgres_connection_password: 'POSTGRES_PASSWORD'

exim_relay_sender_address: "matrix@BASE_DOMAIN"
exim_relay_relay_use: true
exim_relay_relay_host_name: "smtp.gmail.com"
exim_relay_relay_host_port: 587
exim_relay_relay_auth: true
exim_relay_relay_auth_username: "example@gmail.com"
exim_relay_relay_auth_password: "getThisFromYourGmailAccount"

# Jitsi is disabled by default due to difficulty in NAT environments getting LAN clients to work with WAN clients.
# LAN to LAN and WAN to WAN clients did work though.
jitsi_enabled: false

# Coturn is also disabled by default due to difficulty in NAT environments. LAN to LAN clients work fine, but WAN clients
# are difficult to get supported.
#matrix_coturn_turn_external_ip_address: "PUBLIC_IP"
matrix_coturn_enabled: false

# This assumes an external turn server is used. Update your DNS record for turn.BASE_DOMAIN to point to your turn server.
# Then update the shared secret below with the turn server's shared secret.
# It's recommended to use a shared secret over the username and password for Jitsi support.
#matrix_synapse_turn_shared_secret: 'INSERT TURN SHARED SECRET HERE'
#matrix_synapse_turn_username: ''
#matrix_synapse_turn_password: ''
#matrix_synapse_turn_uris:
#  - turn:turn.BASE_DOMAIN?transport=udp
#  - turn:turn.BASE_DOMAIN?transport=tcp

#jitsi_web_stun_servers:
#  - stun:turn.BASE_DOMAIN

# By default internal auth will be used with the below moderator account as the only moderator. Refer to the commented out UVS lines below
# to switch over to the matrix authentication strategy for Jitsi.
#jitsi_enable_auth: true
#jitsi_enable_guests: true
#jitsi_auth_type: matrix

# Refer to https://github.com/spantaleev/matrix-docker-ansible-deploy/blob/master/docs/configuring-playbook-user-verification-service.md
# We need to install matrix and obtain an access token using element before we can install UVS.
#matrix_user_verification_service_enabled: true
#matrix_user_verification_service_uvs_access_token: "INSERT ACCESS TOKEN HERE"
#matrix_user_verification_service_uvs_pin_openid_verify_server_name: false

#jitsi_jvb_container_extra_arguments:
#  - '--env "JVB_ADVERTISE_IPS=MATRIX_HOST"'

#etherpad_enabled: true
#etherpad_admin_username: admin
#etherpad_admin_password: ETHERPAD_ADMIN_PASSWORD

# Uncomment the following and configure your external postgres server.
#postgres_enabled: false
#matrix_synapse_database_host: "your-postgres-server-hostname"
#matrix_synapse_database_user: "your-postgres-server-username"
#matrix_synapse_database_password: "your-postgres-server-password"
#matrix_synapse_database_database: "your-postgres-server-database-name"

matrix_sliding_sync_enabled: true

matrix_bot_maubot_enabled: false
# Uncomment and adjust this part if you'd like to use a username different than the default
#matrix_bot_maubot_login: mau.bot
# Generate a strong password here. Consider generating it with `pwgen -s 64 1`
#matrix_bot_maubot_initial_password: MAUBOT_PASSWORD
#matrix_bot_maubot_admins:
#  - <user>: <password>

# Video Call Configurations
matrix_element_call_enabled: true
matrix_rtc_enabled: true
matrix_element_call_hostname: element-call.BASE_DOMAIN
matrix_synapse_allow_guest_access: true

EOF

read -r -p "Enter your base domain (not the matrix subdomain): " BASE_DOMAIN
read -r -p "Enter your reverse proxy IP: " REVERSE_PROXY_HOST
#BASE_DOMAIN=$(whiptail --backtitle "Proxmox VE Helper Scripts" --inputbox "Enter your base domain (not the matrix subdomain):" 8 58 --title "BASE DOMAIN" 3>&1 1>&2 2>&3)
#REVERSE_PROXY_HOST=$(whiptail --backtitle "Proxmox VE Helper Scripts" --inputbox "Enter your reverse proxy IP:" 8 58 --title "REVERSE PROXY" 3>&1 1>&2 2>&3)
PUBLIC_IP=$(curl -s ifconfig.me) 

$STD sed -i "s/BASE_DOMAIN/${BASE_DOMAIN}/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/BASE_DOMAIN/${BASE_DOMAIN}/g" /opt/matrix-docker-ansible-deploy/inventory/hosts
$STD sed -i "s/GENERIC_SECRET_KEY/$(pwgen -s 64 1)/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/REGISTRATION_ADMIN_SECRET/$(pwgen -s 64 1)/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/POSTGRES_PASSWORD/$(pwgen -s 64 1)/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/REVERSE_PROXY_HOST/${REVERSE_PROXY_HOST}/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/MATRIX_HOST/$(hostname -I | awk '{print $1}')/g" /opt/matrix-docker-ansible-deploy/inventory/hosts
$STD sed -i "s/MATRIX_HOST/$(hostname -I | awk '{print $1}')/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/PUBLIC_IP/${PUBLIC_IP}/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/JITSI_PASSWORD/$(pwgen -s 64 1)/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/ETHERPAD_ADMIN_PASSWORD/$(pwgen -s 64 1)/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml
$STD sed -i "s/MAUBOT_PASSWORD/$(pwgen -s 64 1)/g" /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml

$STD mkdir -p "/opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.${BASE_DOMAIN}/"
$STD mv /opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.example.com/vars.yml "/opt/matrix-docker-ansible-deploy/inventory/host_vars/matrix.${BASE_DOMAIN}/vars.yml"
msg_ok "Created Default Configurations"


get_latest_release() {
  curl -sL https://api.github.com/repos/$1/releases/latest | grep '"tag_name":' | cut -d'"' -f4
}

DOCKER_LATEST_VERSION=$(get_latest_release "moby/moby")
PORTAINER_LATEST_VERSION=$(get_latest_release "portainer/portainer")
PORTAINER_AGENT_LATEST_VERSION=$(get_latest_release "portainer/agent")

msg_info "Installing Docker $DOCKER_LATEST_VERSION"
DOCKER_CONFIG_PATH='/etc/docker/daemon.json'
mkdir -p $(dirname $DOCKER_CONFIG_PATH)
echo -e '{\n  "log-driver": "journald"\n}' >/etc/docker/daemon.json
sh <(curl -sSL https://get.docker.com)
msg_ok "Installed Docker $DOCKER_LATEST_VERSION"

read -r -p "Would you like to add Portainer? <y/N> " prompt
if [[ ${prompt,,} =~ ^(y|yes)$ ]]; then
  msg_info "Installing Portainer $PORTAINER_LATEST_VERSION"
  docker volume create portainer_data >/dev/null
  $STD docker run -d \
    -p 8000:8000 \
    -p 9443:9443 \
    --name=portainer \
    --restart=always \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    portainer/portainer-ce:latest
  msg_ok "Installed Portainer $PORTAINER_LATEST_VERSION"
else
  read -r -p "Would you like to add the Portainer Agent? <y/N> " prompt
  if [[ ${prompt,,} =~ ^(y|yes)$ ]]; then
    msg_info "Installing Portainer agent $PORTAINER_AGENT_LATEST_VERSION"
    $STD docker run -d \
      -p 9001:9001 \
      --name portainer_agent \
      --restart=always \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v /var/lib/docker/volumes:/var/lib/docker/volumes \
      portainer/agent
    msg_ok "Installed Portainer Agent $PORTAINER_AGENT_LATEST_VERSION"
  fi
fi

motd_ssh
customize

msg_info "Cleaning up"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"
