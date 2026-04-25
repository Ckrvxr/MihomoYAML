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

### Client 1: FlClash

#### FlClash_PLUS (Full-Featured)

```url
https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Override/FlClash_PLUS.js
```

#### FlClash_STD (Lightweight)

```url
https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Override/FlClash_STD.js
```

#### Setup Steps

1. Open the FlClash panel
2. Switch to **"Tools"** page
3. Click **"Advanced configuration"** option
4. Click **"Script"** option
5. Add the script URL (PLUS or STD) provided above
6. Switch to **"Profiles"** page
7. Click **"..."** button
8. Click **"More"** option
9. Click **"Override"** option
10. Switch Override mode to **"Script"** and select our script, then save
11. Resync our subscriptions

### Client 2: Sparkle (Deprecated)

```url
https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Override/Sparkle_STD.yaml
```

**Steps:**

1. Download the configuration file
2. Open the Sparkle panel
3. Go to the **"Override Configuration"** interface and upload the file
4. Enable the **"Global Application"** switch of script
5. Save


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
│        ├── FlClash_PLUS.js   # Full-featured FlClash script
│        ├── FlClash_STD.js    # Lightweight FlClash script
│        └── Sparkle_STD.yaml
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
