# MihomoYAML


MihomoYAML is a personal rule library designed for [Mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta), providing AD-Blocking, Privacy Protection, and AntiAntiFraud features.

## ✨ Features

- 🛡️ **Anti-Fraud Protection** - Strongly blocks anti-fraud programs on mobile phones, including automatic uploading of app lists
- 🚫 **Ad Blocking** - Blocks ads and telemetry data
- ⚡ **PCDN Blocking** - Blocks **P2P CDN** to accelerate streaming access
- 🔒 **Privacy Protection** - Protects user privacy and prevents data leakage


- 🎮 **Gaming Download Traffic Saving** - Provides direct connections for games that support China access to save bandwidth
- 🔧 **Server/IP Abuse Provention** - Prevents proxy tools and P2P download software from using the proxy

## 📋 Core Rule

| Rule Name | Description |
|-----------|-------------|
| **DirectProcess** | Prevents proxy tools and P2P download software from using the proxy |
| **AntiAntiFraud** | Strongly blocks anti-fraud programs on mobile phones, including automatic uploading of app lists |
| **AntiPCDN** | Blocks P2P CDN to accelerate streaming access |
| **217heidai/adblockfilters** | Blocks ads and telemetry for all device |
| **AWAvenue** | Blocks ads and telemetry for mobile phone |
| **category-games@cn** | Allows games that support China access to use direct connections to save bandwidth |
| **Bulk of Routing rules** | Open AI, Google, Microsoft, Netflex, HBO and so on

## 🚀 Quick Start

Scripts compatible with both **FlClash** and **Sparkle**.

| Script | URL |
|--------|-----|
| **PLUS** (Full) | `https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Override/FlClash_PLUS.js` |
| **STD** (Light) | `https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Override/FlClash_STD.js` |

> ### 🔴 WARNING: Modify `yourSalt` (line 15) in the script to a unique string before use!

**FlClash:** Tools → Advanced configuration → Script → add URL → Profiles → ... → More → Override → Script mode → select script → save → resync

**Sparkle:** Override Configuration → add script URL → enable Global Application → save


## 🛠️ Project Structure

```text
MihomoYAML/
├── Source/
│   ├── Addition/           # Additional rule files
│   │   ├── AntiAntiFraud.yaml
│   │   ├── AntiPCDN.yaml
│   │   ├── AntiPCDNFix.yaml
│   │   └── DirectProcess.yaml
│   └── Override/          # Override configuration files
│        ├── PLUS.js   # Full-featured script (FlClash & Sparkle)
│        ├── STD.js    # Lightweight script (FlClash & Sparkle)
├── LICENSE
└── README.md
```

## 🤝 Special Thanks

Special thanks to the following open source projects:

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) - Powerful proxy core
- [chen08209/FlClash](https://github.com/chen08209/FlClash) - Clash meta client
- [zsokami/ACL4SSR](https://github.com/zsokami/ACL4SSR) - SSR/Clash rules (be inspired)
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) - Ad-blocking hosts
- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) - Ad-blocking rules
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) - Ad-blocking rules

---
## 📄 License

This project follows the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) license. Using the rules implies agreement with the licensing terms.

---
