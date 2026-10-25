#!/bin/bash
# Runs inside each lab agent container before wazuh-control start.
# Creates the files that the lab ossec.conf monitors.
set -e

# Fake auth log read by logcollector (log_format syslog)
mkdir -p /var/log/lab
touch /var/log/lab/auth.log

# FIM directory (realtime) with a couple of baseline files
mkdir -p /lab/fim
[ -f /lab/fim/app.conf ] || printf 'listen_port=8080\ndebug=false\n' > /lab/fim/app.conf
[ -f /lab/fim/legacy.cfg ] || echo 'mode=legacy' > /lab/fim/legacy.cfg
[ -f /lab/fim/authorized_keys ] || echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILabKeyOnlyForTheWazuhLab lab@lab' > /lab/fim/authorized_keys

# Rootcheck bait: a hidden file under /dev is reported as a host anomaly
touch /dev/.lab-hidden-bait
