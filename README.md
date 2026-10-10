# Secure inline channel in C: PC1 -> Device1 -> MITM -> Device2 -> PC2

## Install (once)
    sudo apt update
    sudo apt install -y build-essential libssl-dev ethtool tcpdump iproute2

## Build
    make

## Run (each terminal in this folder)
| Terminal | Command |
|---|---|
| 0 | `sudo bash setup.sh` then `head -c 5M /dev/urandom > test.bin` |
| 1 | `sudo ip netns exec dev2 ./device 2`  (start first) |
| 2 | `sudo ip netns exec dev1 ./device 1` |
| 2b | when both print "Session key ready": `sudo ip netns exec pc1 ping -c 2 10.20.20.2` |
| 3 | `sudo ip netns exec mitm tcpdump -i br0 -X tcp port 5000` |
| 4 | `sudo ip netns exec pc2 ./receiver 5000 received.bin` |
| 5 | `sudo ip netns exec pc1 ./sender 10.20.20.2 5000 test.bin` |

## Proof
    sha256sum test.bin received.bin     # hashes must be identical
tcpdump on the MITM shows random bytes instead of the file content.

## Cleanup
    sudo bash cleanup.sh
    make clean

## Troubleshooting
- Ping only works AFTER both devices print "Session key ready".
- "Bad tag -> packet dropped" means a packet was lost/reordered (counters out of step). Restart both devices.
- Look at frames: `sudo ip netns exec mitm tcpdump -i br0 -n`
