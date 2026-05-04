#!/usr/bin/env bash
# Install and configure LXD on a GitHub-hosted Ubuntu runner so we can launch
# RHEL 9 VMs with IPv4 NAT to the runner's external interface.
#
# Run as root (e.g. `sudo ./setup-lxd.sh`). No env-var inputs.
#
# Not idempotent: `lxd init --auto` errors if LXD is already initialized.

set -euo pipefail

snap install lxd
sleep 15
lxd init --auto
chown ":$SUDO_USER" /var/snap/lxd/common/lxd/unix.socket

# IPv4 NAT bridge with managed DNS
lxc network set lxdbr0 ipv4.address auto
lxc network set lxdbr0 ipv4.nat true
lxc network set lxdbr0 dns.mode managed
lxc network set lxdbr0 dns.domain lxd
lxc network set lxdbr0 dns.nameservers 1.1.1.1,8.8.8.8

# GH runners ship with restrictive FORWARD policy and rp_filter; relax for lxdbr0
sysctl -w net.ipv4.conf.all.forwarding=1 net.ipv4.conf.default.forwarding=1
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1 net.bridge.bridge-nf-call-ip6tables=1
sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
iptables -P FORWARD ACCEPT

EXTIF=$(ip -4 route show default | awk '{print $5}' | head -n1)
SUBNET=$(ip -4 addr show dev lxdbr0 | awk '/inet /{print $2}')
iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$EXTIF" -j MASQUERADE
iptables -I FORWARD 1 -i lxdbr0 -o "$EXTIF" -j ACCEPT
iptables -I FORWARD 1 -i "$EXTIF" -o lxdbr0 -m state --state RELATED,ESTABLISHED -j ACCEPT
