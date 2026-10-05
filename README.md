# Transparent TCP Encryption Between Two Devices (AES-256-GCM)

An educational C project: two "devices" sit in the middle of a link between two computers and **transparently** encrypt the traffic between them. The computers know nothing about the encryption, and a man in the middle (MITM) sees only random bytes.

Everything runs on a single Linux machine. Nodes are isolated with network namespaces and connected with virtual cables (veth).

## Topology

```
 PC1 ──── Device1 ──── MITM ──── Device2 ──── PC2
10.10.10.1   │    (bridge, tcpdump)   │    10.20.20.2
             └── 172.16.0.1 ◄──► 172.16.0.2 ──┘
                 (key exchange, port 6000)
```

| Node | Namespace | Role |
|---|---|---|
| PC1 | `pc1` | sends a file (`sender`) |
| Device1 | `dev1` | encrypts packets from PC1, decrypts packets from Device2 |
| MITM | `mitm` | a bridge that forwards frames and lets you sniff them |
| Device2 | `dev2` | same as Device1, on the other side |
| PC2 | `pc2` | receives the file (`receiver`) |

## What Was Built

1. **Network lab** (`setup.sh`). Creates 5 namespaces, 4 veth pairs and a bridge on the MITM node. PC1 and PC2 use MTU 1340, so that after the 16-byte tag is added a packet still fits into the standard 1500 MTU on the link between the devices. Hardware offloads (checksum, TSO, GRO, etc.) are disabled so that packet sizes and checksums are "real".

2. **Diffie-Hellman key exchange** (`device.c`, function `handshake`). RFC 3526 group 14 (2048-bit, g = 2). Device1 acts as the client, Device2 as the server, over TCP port 6000. Each side generates a random secret, exchanges its public value and computes the shared secret. The peer's public value is validated (must satisfy 1 < y < p − 1). The AES key is derived as `SHA-256(shared secret)`.

3. **On-the-fly encryption** (`device.c`, function `process`). Each device listens on two interfaces using raw sockets (`AF_PACKET`):
   - frame arrives from its own computer → encrypt and forward toward the link;
   - frame arrives from the link → verify the tag, decrypt and forward to its own computer.

4. **What is encrypted.** Only the TCP payload. Ethernet, IP and TCP headers stay in the clear so that packets are still routed and TCP keeps working.

5. **Integrity and tamper protection.** AES-256-GCM is used:
   - a 16-byte tag is appended to the ciphertext (so each packet grows by 16 bytes);
   - the AAD (data that is authenticated but not encrypted) contains the IP addresses, ports and the TCP sequence number (16 bytes). Modifying any of these fields makes the tag check fail and the packet is dropped;
   - the 12-byte nonce = 4-byte "device prefix" + 8-byte packet counter. The two devices use different prefixes (1 and 2), so the two directions never reuse a nonce under the same key.

6. **Header recomputation.** Encryption/decryption changes the packet length, so the device recomputes the IP total length, the IP header checksum and the TCP checksum (including the pseudo-header).

7. **Other traffic.** ARP and non-TCP packets (e.g. ping) pass through unchanged. Key-exchange traffic between the devices on the link side is ignored by the packet processor.

## Files

| File | Purpose |
|---|---|
| `device.c` | the device: key exchange, encryption, decryption, forwarding |
| `sender.c` | client: sends a file over TCP |
| `receiver.c` | server: receives a file over TCP and saves it |
| `Makefile` | build |
| `setup.sh` | creates the network lab |
| `cleanup.sh` | removes the lab |

## Requirements

Linux with root privileges (needed for namespaces and raw sockets).

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev ethtool tcpdump iproute2
```

## Build

```bash
make
```

## Run

Run each command in a separate terminal, from the project folder.

**1. Prepare the network and a test file**
```bash
sudo bash setup.sh
head -c 5M /dev/urandom > test.bin
```

**2. Start the devices** (Device2 first, it waits for the connection)
```bash
sudo ip netns exec dev2 ./device 2
```
```bash
sudo ip netns exec dev1 ./device 1
```
Wait until both print `Session key ready`.

**3. Check connectivity**
```bash
sudo ip netns exec pc1 ping -c 2 10.20.20.2
```

**4. Start sniffing on the MITM**
```bash
sudo ip netns exec mitm tcpdump -i br0 -X tcp port 5000
```
Or save a capture to analyze in Wireshark:
```bash
sudo ip netns exec mitm tcpdump -i br0 -w mitm_capture.pcap tcp port 5000
```

**5. Receive and send the file**
```bash
sudo ip netns exec pc2 ./receiver 5000 received.bin
```
```bash
sudo ip netns exec pc1 ./sender 10.20.20.2 5000 test.bin
```

## Verifying the Result

The file arrived intact:
```bash
sha256sum test.bin received.bin
```
The hashes must be identical.

The traffic is encrypted: in the `tcpdump` output on the MITM (or in the pcap file) the TCP payload is random bytes, not the file content. For comparison you can sniff on PC1's side (`sudo ip netns exec pc1 tcpdump -i pc1_eth -X tcp port 5000`), where the data is in plaintext.

## Cleanup

```bash
sudo bash cleanup.sh
make clean
```

## Limitations

- **No authentication of the parties.** The DH exchange is not protected against an *active* MITM (substituting public values). Here the MITM is passive: it only reads frames. Protecting against an active attacker would require signatures or pre-shared keys/certificates.
- **Counters must stay in sync.** The nonce is built from a packet counter. If an encrypted packet is lost or reordered on the link between the devices, the receiving side prints `Bad tag -> packet dropped` and the devices must be restarted.
- IPv4 and TCP only (everything else is forwarded unencrypted).
- No rekeying during a session.

## Troubleshooting

- **Ping fails**: it only works after both devices print `Session key ready`.
- **`Bad tag -> packet dropped`**: the counters are out of sync, restart both devices.
- **Inspect what is on the wire**: `sudo ip netns exec mitm tcpdump -i br0 -n`
