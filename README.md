# 🛰️ rnmap

Nmap-style port scanning rewritten in Rust. One binary. No dependencies.
---

## 🎯 What it is

A drop-in port scanner you can use anywhere Nmap feels too heavy. Same flags you already type. One binary you copy onto a box. No package managers. No `libpcap`. No setup ritual. You run it. It scans. You move on.

---

## ✨ Features

- 🔌 TCP connect scan. Works without root.
- ⚡ TCP SYN scan. Raw packets. Falls back to connect when you lack `CAP_NET_RAW`.
- 📡 Host discovery. ICMP echo. TCP ping. Skip with `-Pn`.
- 🔍 Service detection. Banner grabbing. Regex matching. Knows SSH, HTTP, FTP, SMTP, MySQL, Redis, more.
- 🎯 Targets in every shape. Single IP. Hostname. CIDR. Dashed range. File list.
- 📋 Top-ports list baked in. `--top-ports 100` works out of the box.
- ⏱️ Timing templates `-T0` through `-T5`. Same meaning as Nmap.
- 📤 Output formats. Normal. XML. JSON. Write all three at once with `-oA`.
- 🪶 Single 2.8 MB static binary. No `libpcap`. No runtime deps.

---

## 📦 Install

Clone the repo. Build it.

```bash
git clone https://github.com/krainium/rnmap.git
cd rnmap
cargo build --release
```

Binary lands at `target/release/rnmap`. Drop it anywhere on your `$PATH`.

```bash
sudo cp target/release/rnmap /usr/local/bin/
```

---

## 🚀 Usage

Same flags as Nmap. If you know Nmap you already know `rnmap`.

```bash
# Top 100 ports of one host. Skip ping.
rnmap -Pn --top-ports 100 192.168.1.1

# Specific ports. Service detection. Hide closed ports.
rnmap -Pn -p 22,80,443,8080 -sV --open scanme.nmap.org

# Whole subnet. Output all three formats.
rnmap -Pn --top-ports 50 -oA homescan 192.168.1.0/24

# SYN scan. Needs root or CAP_NET_RAW.
sudo rnmap -sS -p 1-1000 10.0.0.5

# Range syntax. Verbose.
rnmap -Pn -p 22,80 -v 192.168.1.10-50
```

---

## 🏷️ Flag reference

| Flag                | Meaning                                   |
|---------------------|-------------------------------------------|
| `-Pn`               | Skip host discovery                       |
| `-PE`               | ICMP echo discovery                       |
| `-PS<ports>`        | TCP SYN ping on chosen ports              |
| `-sT`               | TCP connect scan (default)                |
| `-sS`               | TCP SYN scan (raw packets)                |
| `-sV`               | Service version detection                 |
| `-p <spec>`         | Port spec. `22,80` or `1-1024` or `-`     |
| `--top-ports N`     | Scan the N most common ports              |
| `-T0` … `-T5`       | Timing template. Higher means faster.     |
| `--open`            | Show only open ports                      |
| `-n`                | Skip reverse DNS                          |
| `-v`                | Verbose                                   |
| `-iL <file>`        | Read targets from file                    |
| `-oN <file>`        | Normal output                             |
| `-oX <file>`        | XML output                                |
| `-oJ <file>`        | JSON output                               |
| `-oA <basename>`    | All three formats with one base name      |

---

## 📊 Output sample

```
# rnmap 0.1.0 scan initiated 2026-04-29 10:36 UTC
# args: rnmap -Pn -p 22,80,53,8080 -sV --open 127.0.0.1

rnmap scan report for localhost (127.0.0.1)
Host is up (skipped)
PORT      STATE        SERVICE         VERSION
22/tcp    open         ssh             OpenSSH 9.6
53/tcp    open         dns
80/tcp    open         http            nginx 1.25
8080/tcp  open         http

# rnmap done: 1 host scanned, 1 up, 4 open ports in 8.26s
```

JSON output round-trips through any parser. XML parses with the same DTD as Nmap for the bits that overlap.

---

## ⚡ Speed

Top 200 ports against `127.0.0.1` finish in 73 ms on a `T4` profile. SYN scan goes faster on real networks because it never finishes the handshake.

---

## 🧪 Tests

```bash
cargo test
```

35 tests run. 32 unit tests cover the scanner internals. 3 integration tests bind real listeners then scan them.

---

## 🧠 How it works

`rnmap` is a Cargo workspace with two crates.

- `rnmap-core` holds every scan primitive. Port parsing. Target parsing. Timing profiles. Discovery probes. The packet builder. The output renderers.
- `rnmap` is the CLI binary. It rewrites Nmap-style compound short flags like `-Pn` into long form before clap sees them. Then it drives the scan with a `tokio` semaphore that bounds in-flight probes per host.

The SYN scanner builds the full IP header. It computes its own checksums. It writes the packet to a raw IPv4 socket with `IP_HDRINCL` set. Reads come back through the same socket. No `libpcap` anywhere.

---

## 🚧 Not in scope yet

Things real Nmap does that `rnmap` does not.

- UDP scan
- OS fingerprinting
- NSE script engine
- IPv6
- Full nmap-services file with all 21k entries

These are tracked. None are blockers for a fast TCP scan workflow.
