#!/bin/bash
# setup.sh  -  run with: sudo bash setup.sh
set -e

# 1. create namespaces
for ns in pc1 dev1 mitm dev2 pc2; do
  ip netns del $ns 2>/dev/null || true
  ip netns add $ns
done

# 2. create veth pairs
ip link add pc1_eth type veth peer name d1_lan
ip link add d1_wan  type veth peer name m_p1
ip link add m_p2    type veth peer name d2_wan
ip link add d2_lan  type veth peer name pc2_eth

# 3. move them into namespaces
ip link set pc1_eth netns pc1
ip link set d1_lan  netns dev1
ip link set d1_wan  netns dev1
ip link set m_p1    netns mitm
ip link set m_p2    netns mitm
ip link set d2_wan  netns dev2
ip link set d2_lan  netns dev2
ip link set pc2_eth netns pc2

# 4. PC1 and PC2  (MTU 1340 -> MSS 1300)
ip netns exec pc1 ip addr add 10.10.10.1/24 dev pc1_eth
ip netns exec pc1 ip link set pc1_eth mtu 1340 up
ip netns exec pc1 ip link set lo up
ip netns exec pc1 ip route add 10.20.20.0/24 dev pc1_eth

ip netns exec pc2 ip addr add 10.20.20.2/24 dev pc2_eth
ip netns exec pc2 ip link set pc2_eth mtu 1340 up
ip netns exec pc2 ip link set lo up
ip netns exec pc2 ip route add 10.10.10.0/24 dev pc2_eth

# 5. Device1  (lan side no IP, wan side has IP only for the handshake)
ip netns exec dev1 ip link set d1_lan mtu 1340 up promisc on
ip netns exec dev1 ip addr add 172.16.0.1/24 dev d1_wan
ip netns exec dev1 ip link set d1_wan up promisc on

# 6. Device2
ip netns exec dev2 ip link set d2_lan mtu 1340 up promisc on
ip netns exec dev2 ip addr add 172.16.0.2/24 dev d2_wan
ip netns exec dev2 ip link set d2_wan up promisc on

# 7. MITM = simple bridge (just forwards frames)
ip netns exec mitm ip link add br0 type bridge
ip netns exec mitm ip link set m_p1 master br0
ip netns exec mitm ip link set m_p2 master br0
ip netns exec mitm ip link set m_p1 up
ip netns exec mitm ip link set m_p2 up
ip netns exec mitm ip link set br0 up

# 8. turn off offloading (so checksums/sizes are normal) and IPv6 (less noise)
for x in pc1:pc1_eth dev1:d1_lan dev1:d1_wan mitm:m_p1 mitm:m_p2 dev2:d2_wan dev2:d2_lan pc2:pc2_eth; do
  ns=${x%%:*}; ifc=${x##*:}
  ip netns exec $ns ethtool -K $ifc tx off rx off sg off tso off gso off gro off >/dev/null 2>&1 || true
done
for ns in pc1 dev1 mitm dev2 pc2; do
  ip netns exec $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done

echo "Network ready."
