# 🌐 NullSec NetSeer

<div align="center">

![Haskell](https://img.shields.io/badge/Haskell-GHC%209.4+-5D4F85?style=for-the-badge&logo=haskell)
![Security](https://img.shields.io/badge/Security-Secure-red?style=for-the-badge&logo=shield)
![Type Safety](https://img.shields.io/badge/Type%20Safety-Strong-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-Proprietary-purple?style=for-the-badge)

**Secure Passive Network Traffic Analyzer**

*Pure functional design with strong type safety and immutable data structures*

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Security](#security)

</div>

---

## 🎯 Overview

NullSec NetSeer is a Secure passive network traffic analyzer written in Haskell. It leverages the power of pure functional programming to provide mathematically provable security guarantees through strong typing and immutability.

## ✨ Features

- **📊 Traffic Analysis** - Deep packet inspection and flow analysis
- **🔍 Protocol Detection** - Identify protocols in network streams
- **📈 Statistics** - Real-time traffic statistics and metrics
- **🛡️ Type-Safe** - Strong typing prevents entire classes of bugs
- **♻️ Immutable** - No side effects in core analysis logic
- **📝 Reports** - Comprehensive traffic reports

## 🛡️ Security Security

```
┌─────────────────────────────────────────────┐
│        NullSec NetSeer v2.0.0              │
├─────────────────────────────────────────────┤
│  ✓ Pure Functional Design                  │
│  ✓ Strong Type Safety (Newtypes)           │
│  ✓ Smart Constructors for Validation       │
│  ✓ Bounded Data Structures                 │
│  ✓ Immutable Data Throughout               │
│  ✓ Explicit Error Handling (No Exceptions) │
│  ✓ Memory Exhaustion Prevention            │
└─────────────────────────────────────────────┘
```

## 📦 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-netseer.git
cd nullsec-netseer

# Build with Cabal
cabal update
cabal build

# Or with Stack
stack build

# Install
cabal install
```

### Requirements

- GHC 9.4 or later
- Cabal 3.8+ or Stack 2.9+
- libpcap development libraries

### Dependencies

```yaml
- base >= 4.16
- bytestring >= 0.11
- containers >= 0.6
- time >= 1.12
- directory >= 1.3
```

## 🚀 Usage

```bash
# Analyze pcap file
./nullsec-netseer --input capture.pcap

# Live capture (requires root)
sudo ./nullsec-netseer --interface eth0

# Generate statistics report
./nullsec-netseer --input capture.pcap --stats

# Filter by protocol
./nullsec-netseer --input capture.pcap --protocol tcp

# Export analysis
./nullsec-netseer --input capture.pcap --output analysis.json
```

### Command Line Options

| Flag | Description |
|------|-------------|
| `--input <file>` | Input pcap file to analyze |
| `--interface <if>` | Live capture interface |
| `--stats` | Show traffic statistics |
| `--protocol <proto>` | Filter by protocol |
| `--top <n>` | Show top N flows |
| `--output <file>` | Output file for reports |
| `--verbose` | Enable verbose output |
| `--version` | Show version information |

## 📊 Output Example

```
███╗   ██╗███████╗████████╗███████╗███████╗███████╗██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝██╔══██╗
██╔██╗ ██║█████╗     ██║   ███████╗█████╗  █████╗  ██████╔╝
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██╔══╝  ██╔══██╗
██║ ╚████║███████╗   ██║   ███████║███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
             bad-antics • Network Traffic Analyzer

[*] Analyzing: capture.pcap
[+] Packets processed: 142,857
[+] Flows identified: 3,421

┌──────────────────────────────────────────┐
│           Traffic Statistics             │
├──────────────────────────────────────────┤
│  Total Bytes:     2.4 GB                 │
│  Total Packets:   142,857                │
│  Unique IPs:      1,234                  │
│  Duration:        3h 24m 15s             │
├──────────────────────────────────────────┤
│  Protocol Breakdown:                     │
│    TCP:    78.4%  (111,999 pkts)        │
│    UDP:    19.2%  (27,428 pkts)         │
│    ICMP:    2.4%  (3,430 pkts)          │
└──────────────────────────────────────────┘
```

## 🔐 Type Safety Architecture

```haskell
-- Smart constructors ensure validation at creation
mkValidIP :: Word32 -> Either String ValidIP
mkValidPort :: Word16 -> Either String ValidPort
mkValidPath :: FilePath -> Either String ValidPath

-- Newtypes prevent mixing different data types
newtype ValidIP = ValidIP { getIP :: Word32 }
newtype ValidPort = ValidPort { getPort :: Word16 }

-- Pure functions with no side effects
analyzePacket :: ValidPacket -> Either AnalysisError PacketInfo
```

## 📜 License

NullSec Proprietary License - See LICENSE file for details.

## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Discord: [discord.gg/killers](https://discord.gg/killers)

---

<div align="center">

**Part of the NullSec Security Framework**

*"Mathematically provable security through pure functional programming"*

</div>
