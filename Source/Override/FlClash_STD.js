// Auther: CocoaDuck
// jdsdelivr mirror:
// 1. https://fastly.jsdelivr.net/gh/
// 2. https://gcore.jsdelivr.net/gh/
// 3. https://testingcf.jsdelivr.net/
// 3. https://cdn.jsdmirror.com/gh
// 4. https://cdn.jsdmirror.cn/gh
// 5. https://cdn.jsdmirror.com/gh

const main = (config) => {
    // CDN Slect
    const cdnBase = "https://fastly.jsdelivr.net/gh/";

    // Password Generation
    const yourSalt = "";
    const fnv256 = (str) => {
        const seeds = [
            0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
            0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
        ];
        const h = new Uint32Array(seeds);
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            for (let j = 0; j < 8; j++) {
                h[j] = Math.imul(h[j] ^ char, 16777619);
            }
        }
        var res = "";
        for (var k = 0; k < 8; k++) {
            res += (h[k] >>> 0).toString(16).padStart(8, '0');
        }
        return res;
    };
    if (!yourSalt || yourSalt === 0) {
        throw new Error("🛑 [CONFIG ERROR] yourSalt is EMPTY! You must set a unique salt to generate passwords.");
    }
    config["secret"] = fnv256(yourSalt + "control");
    config["authentication"] = ["Mihomo:" + fnv256(yourSalt + "lan")];
    config["skip-auth-prefixes"] = [
        "127.0.0.1/8",
        "::1/128"
    ];

    // Basic Config
    config["log-level"] = "error";
    config["mode"] = "rule";
    config["unified-delay"] = true;
    config["profile"] = { "store-selected": true, "store-fake-ip": true };
    config["ipv6"] = false;
    config["find-process-mode"] = "strict";
    config["tun"] = {
        "enable": true,
        "stack": "system",
        "auto-route": true,
        "auto-redirect": true,
        "auto-detect-interface": true,
        "strict-route": true,
        "mtu": 9000,
        "dns-hijack": [
            "udp://any:53",
            "tcp://any:53"
        ]
    };
    config["dns"] = {
        "enable": true,
        "listen": "127.0.0.1:1053",
        "cache-algorithm": "arc",
        "ipv6": false,
        "default-nameserver": [
            "223.5.5.5",
            "119.29.29.29"
        ],
        "nameserver": [
            "https://dns.alidns.com/dns-query",
            "https://doh.pub/dns-query"
        ],
        "nameserver-policy": {
            "geosite:private": ["system"]
        },
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter-mode": "rule",
        "fake-ip-filter": [
            // 1. Local Domain, Reserved Domain, Dotless Domain;
            //    Router Manage Pages; xxxxx.arpa; Tailscale Magic DNS.
            "GEOSITE,private,real-ip",
            // 2. NTP Servers
            "GEOSITE,category-ntp,real-ip",
            "DOMAIN-REGEX,^(time|ntp).*\..*$,real-ip",
            // 3. Connectivity Checkers
            "GEOSITE,connectivity-check,real-ip",
            "DOMAIN-REGEX,^(connectivitycheck|ipv6check).*\..*$,real-ip",
            // 4. P2P Trackers
            "GEOSITE,category-public-tracker,real-ip",
            "DOMAIN-KEYWORD,tracker,real-ip",
            // 5. STUN Servers
            "DOMAIN-REGEX,^(stun|turn).*\..*$,real-ip",
            "DOMAIN-SUFFIX,stunprotocol.org,real-ip",
            "DOMAIN-SUFFIX,srv.nintendo.net,real-ip",
            "DOMAIN-SUFFIX,steamserver.net,real-ip",
            "DOMAIN-SUFFIX,xboxlive.com,real-ip",
            "DOMAIN-SUFFIX,discovery-lookup.syncthing.net,real-ip",
            // 6. XiaoMi-Bibles
            "DOMAIN-SUFFIX,mijia.tech,real-ip",
            "DOMAIN-SUFFIX,Mijia Cloud,real-ip",
            // 8.Google Push Framework (FCM)
            "GEOSITE,googlefcm,real-ip",
            // 9. Others use fake-ip
            "MATCH,fake-ip"
        ]
    };
    config["sniffer"] = {
        "enable": true,
        "parse-pure-ip": true,
        "sniff": {
            "QUIC": { "ports": [443, 8443] },
            "TLS": { "ports": [443, 8443] },
            "HTTP": { "ports": [80, "8080-8880"], "override-destination": true }
        },
        "skip-domain": [
            "Mijia Cloud",
            "+.mijia.tech",
            "+.push.apple.com",
        ]
    };

    // Ruleset
    config["geodata-mode"] = true;
    config["geodata-loader"] = "standard";
    config["geosite-matcher"] = "mph";
    config["geo-auto-update"] = true;
    config["geo-update-interval"] = 12; // 12H
    config["geox-url"] = {
        "geoip": `${cdnBase}MetaCubeX/meta-rules-dat@release/geoip.dat`,
        "geosite": `${cdnBase}MetaCubeX/meta-rules-dat@release/geosite.dat`
    };
    config["rule-providers"] = {
        "AntiAntiFraud": {
            "type": "http",
            "behavior": "classical",
            "format": "yaml",
            "interval": 43200, // 12H
            "url": `https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Addition/AntiAntiFraud.yaml`
        },
        "AntiPCDNFix": {
            "type": "http",
            "behavior": "classical",
            "format": "yaml",
            "interval": 43200, // 12H
            "url": `https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Addition/AntiPCDNFix.yaml`
        },
        "AntiPCDN": {
            "type": "http",
            "behavior": "classical",
            "format": "yaml",
            "interval": 43200, // 12H
            "url": `https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Addition/AntiPCDN.yaml`
        },
        "217heidaiAdblockFilters": {
            "type": "http",
            "behavior": "domain",
            "format": "yaml",
            "interval": 43200, // 12H
            "url": `${cdnBase}217heidai/adblockfilters@main/rules/adblockmihomo.yaml`
        },
        "DirectProcess": {
            "type": "http",
            "behavior": "classical",
            "format": "yaml",
            "interval": 43200, // 12H
            "url": `https://codeberg.org/CocoaDuck/Snippets/raw/master/MihomoYAML/Source/Addition/DirectProcess.yaml`
        },
        "firehol_level1": {
            "type": "http",
            "behavior": "ipcidr",
            "format": "text",
            "interval": 7200,  // 2H
            "url": `https://iplists.firehol.org/files/firehol_level1.netset`
        }
    };

    // Node Preprocessing
    const emojiData = [
        { match: /Afghanistan|阿富汗|\bAF(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇫" },
        { match: /Albania|阿尔巴尼亚|阿爾巴尼亞|\bAL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇱" },
        { match: /Algeria|阿尔及利亚|阿爾及利亞|\bDZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇩🇿" },
        { match: /Andorra|安道尔|安道爾|\bAD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇩" },
        { match: /Angola|安哥拉|\bAO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇴" },
        { match: /Antigua and Barbuda|安提瓜和巴布达|安提瓜和巴布達|\bAG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇬" },
        { match: /Argentina|阿根廷|\bAR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇷" },
        { match: /Armenia|亚美尼亚|亞美尼亞|\bAM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇲" },
        { match: /Australia|澳大利亚|澳大利亞|澳洲|Canberra|堪培拉|Sydney|悉尼|Melbourne|墨尔本|墨爾本|\bAU(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇺" },
        { match: /Austria|奥地利|Vienna|维也纳|維也納|\bAT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇹" },
        { match: /Azerbaijan|阿塞拜疆|亞塞拜然|\bAZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇿" },
        { match: /Bahamas|巴哈马|巴哈馬|\bBS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇸" },
        { match: /Bahrain|巴林|\bBH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇭" },
        { match: /Bangladesh|孟加拉国|孟加拉國|\bBD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇩" },
        { match: /Barbados|巴巴多斯|\bBB(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇧" },
        { match: /Belarus|白俄罗斯|白俄羅斯|\bBY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇾" },
        { match: /Belgium|比利时|比利時|\bBE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇪" },
        { match: /Belize|伯利兹|伯利茲|\bBZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇿" },
        { match: /Benin|贝宁|貝寧|\bBJ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇯" },
        { match: /Bhutan|不丹|\bBT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇹" },
        { match: /Bolivia|玻利维亚|玻利維亞|\bBO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇴" },
        { match: /Bosnia and Herzegovina|波斯尼亚和黑塞哥维那|波斯尼亞和黑塞哥維那|Sarajevo|萨拉热窝|薩拉熱窩|Banja Luka|巴尼亚卢卡|巴尼亞盧卡|\bBA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇦" },
        { match: /Botswana|博茨瓦纳|博茨瓦納|\bBW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇼" },
        { match: /Brazil|巴西|Brasília|巴西利亚|巴西利亞|São Paulo|圣保罗|聖保羅|Rio de Janeiro|里约热内卢|里約熱內盧|\bBR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇷" },
        { match: /Brunei|文莱|汶萊|\bBN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇳" },
        { match: /Bulgaria|保加利亚|保加利亞|\bBG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇬" },
        { match: /Burkina Faso|布基纳法索|布基納法索|\bBF(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇫" },
        { match: /Burundi|布隆迪|\bBI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇧🇮" },
        { match: /Cabo Verde|Cape Verde|佛得角|\bCV(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇻" },
        { match: /Cambodia|柬埔寨|Phnom Penh|金边|金邊|\bKH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇭" },
        { match: /Cameroon|喀麦隆|喀麥隆|\bCM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇲" },
        { match: /Canada|加拿大|Ottawa|渥太华|渥太華|Toronto|多伦多|多倫多|Vancouver|温哥华|溫哥華|Montreal|蒙特利尔|蒙特利爾|Edmonton|埃德蒙顿|埃德蒙頓|Winnipeg|温尼伯|溫尼伯|\bCA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇦" },
        { match: /Central African Republic|中非|\bCF(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇫" },
        { match: /Chad|乍得|\bTD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇩" },
        { match: /Chile|智利|\bCL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇱" },
        { match: /China|中国|中國|中华人民共和国|中華人民共和國|Beijing|北京|Tianjin|天津|Shanghai|上海|Guangzhou|广州|廣州|Shenzhen|深圳|Hangzhou|杭州|Suzhou|苏州|Nanjing|南京|\bCN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇳" },
        { match: /Colombia|哥伦比亚|哥倫比亞|\bCO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇴" },
        { match: /Comoros|科摩罗|科摩羅|\bKM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇲" },
        { match: /Congo, Democratic Republic of the|刚果民主共和国|剛果民主共和國|\bCD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇩" },
        { match: /Congo, Republic of the|刚果共和国|剛果共和國|\bCG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇬" },
        { match: /Costa Rica|哥斯达黎加|哥斯大黎加|\bCR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇷" },
        { match: /Croatia|克罗地亚|克羅地亞|\bHR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇭🇷" },
        { match: /Cuba|古巴|Havana|哈瓦那|\bCU(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇺" },
        { match: /Cyprus|塞浦路斯|\bCY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇾" },
        { match: /Czech Republic|捷克|\bCZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇿" },
        { match: /Denmark|丹麦|丹麥|\bDK(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇩🇰" },
        { match: /Djibouti|吉布提|\bDJ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇩🇯" },
        { match: /Dominica|多米尼克|\bDM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇩🇲" },
        { match: /Dominican Republic|多米尼加|多明尼加|\bDO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇩🇴" },
        { match: /Ecuador|厄瓜多尔|厄瓜多爾|\bEC(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇪🇨" },
        { match: /Egypt|埃及|阿拉伯埃及共和國|阿拉伯埃及共和国|Cairo|开罗|開羅|\bEG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇪🇬" },
        { match: /El Salvador|萨尔瓦多|薩爾瓦多|\bSV(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇻" },
        { match: /Equatorial Guinea|赤道几内亚|赤道幾內亞|\bGQ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇶" },
        { match: /Eritrea|厄立特里亚|厄立特里亞|\bER(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇪🇷" },
        { match: /Estonia|爱沙尼亚|愛沙尼亞|\bEE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇪🇪" },
        { match: /Eswatini|斯威士兰|斯威士蘭|\bSZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇿" },
        { match: /Ethiopia|埃塞俄比亚|埃塞俄比亞|\bET(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇪🇹" },
        { match: /Fiji|斐济|斐濟|\bFJ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇫🇯" },
        { match: /Finland|芬兰|芬蘭|\bFI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇫🇮" },
        { match: /France|法国|法國|法兰西|法蘭西|Paris|巴黎|Marseille|马赛|馬賽|\bFR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇫🇷" },
        { match: /Gabon|加蓬|\bGA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇦" },
        { match: /Gambia|冈比亚|岡比亞|\bGM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇲" },
        { match: /Georgia|格鲁吉亚|格魯吉亞|\bGE(?!(mini|[a-zA-Z]))(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇪" },
        { match: /Germany|德国|德國|德意志|Berlin|柏林|Hamburg|汉堡|漢堡|Munich|慕尼黑|\bDE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇩🇪" },
        { match: /Ghana|加纳|加納|\bGH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇭" },
        { match: /Greece|希腊|希臘|Athens|雅典|\bGR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇷" },
        { match: /Grenada|格林纳达|格林納達|\bGD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇩" },
        { match: /Guatemala|危地马拉|危地馬拉|\bGT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇹" },
        { match: /Guinea|几内亚|幾內亞|\bGN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇳" },
        { match: /Guinea-Bissau|几内亚比绍|幾內亞比紹|\bGW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇼" },
        { match: /Guyana|圭亚那|圭亞那|\bGY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇾" },
        { match: /Haiti|海地|\bHT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇭🇹" },
        { match: /Honduras|洪都拉斯|宏都拉斯|\bHN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇭🇳" },
        { match: /Hong Kong|香港|\bHK(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇭🇰" },
        { match: /Hungary|匈牙利|\bHU(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇭🇺" },
        { match: /Iceland|冰岛|\bIS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇸" },
        { match: /India|印度|New Delhi|新德里|Mumbai|孟买|孟買|Bangalore|班加罗尔|班加羅爾|\bIN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇳" },
        { match: /Indonesia|印度尼西亚|印度尼西亞|印尼|Jakarta|雅加达|雅加達|Bandung|万隆|萬隆|\bID(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇩" },
        { match: /Iran|伊朗|\bIR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇷" },
        { match: /Iraq|伊拉克|\bIQ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇶" },
        { match: /Ireland|爱尔兰|愛爾蘭|Dublin|都柏林|Cork|科克|\bIE(?![a-zA-Z])\s*\d+/, emoji: "🇮🇪" },
        { match: /Israel|以色列|Jerusalem|耶路撒冷|\bIL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇱" },
        { match: /Italy|意大利|Rome|罗马|羅馬|Milan|米兰|米蘭|\bIT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇮🇹" },
        { match: /Ivory Coast|象牙海岸|科特迪瓦|\bCI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇮" },
        { match: /Jamaica|牙买加|牙買加|\bJM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇯🇲" },
        { match: /Japan|日本|日(?!尔|爾|利)|Tokyo|东京|東京|Osaka|大阪|Kyoto|京都|Saitama|埼玉|\bJP(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇯🇵" },
        { match: /Jordan|约旦|約旦|\bJO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇯🇴" },
        { match: /Kazakhstan|哈萨克斯坦|哈薩克斯坦|\bKZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇿" },
        { match: /Kenya|肯尼亚|肯尼亞|\bKE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇪" },
        { match: /Kiribati|基里巴斯|\bKI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇮" },
        { match: /Kuwait|科威特|\bKW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇼" },
        { match: /Kyrgyzstan|吉尔吉斯斯坦|吉爾吉斯斯坦|\bKG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇬" },
        { match: /Laos|老挝|老撾|Vientiane|万象|萬象|(?<!美国\s*)\bLA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇦" },
        { match: /Latvia|拉脱维亚|拉脫維亞|\bLV(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇻" },
        { match: /Lebanon|黎巴嫩|\bLB(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇧" },
        { match: /Lesotho|莱索托|\bLS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇸" },
        { match: /Liberia|利比里亚|利比里亞|\bLR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇷" },
        { match: /Libya|利比亚|利比亞|\bLY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇾" },
        { match: /Liechtenstein|列支敦士登|列支敦斯登|\bLI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇮" },
        { match: /Lithuania|立陶宛|\bLT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇹" },
        { match: /Luxembourg|卢森堡|盧森堡|\bLU(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇺" },
        { match: /Macao|Macau|澳门|澳門|\bMO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇴" },
        { match: /Madagascar|马达加斯加|馬達加斯加|\bMG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇬" },
        { match: /Malawi|马拉维|馬拉維|\bMW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇼" },
        { match: /Malaysia|马来西亚|馬來西亞|Kuala Lumpur|吉隆坡|Penang|槟城|檳城|\bMY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇾" },
        { match: /Maldives|马尔代夫|馬爾代夫|\bMV(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇻" },
        { match: /Mali|马里|馬里|\bML(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇱" },
        { match: /Malta|马耳他|馬耳他|\bMT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇹" },
        { match: /Marshall Islands|马绍尔群岛|馬紹爾群島|\bMH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇭" },
        { match: /Martinique|马提尼克|\bMQ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇶" },
        { match: /Mauritania|毛里塔尼亚|毛里塔尼亞|\bMR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇷" },
        { match: /Mauritius|毛里求斯|毛里裘斯|\bMU(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇺" },
        { match: /Mexico|墨西哥|墨|\bMX(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇽" },
        { match: /Micronesia|密克罗尼西亚|密克羅尼西亞|\bFM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇫🇲" },
        { match: /Moldova|摩尔多瓦|摩爾多瓦|\bMD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇩" },
        { match: /Monaco|摩纳哥|摩納哥|\bMC(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇨" },
        { match: /Mongolia|蒙古|\bMN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇳" },
        { match: /Montenegro|黑山|\bME(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇪" },
        { match: /Morocco|摩洛哥|\bMA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇦" },
        { match: /Mozambique|莫桑比克|\bMZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇿" },
        { match: /Myanmar|缅甸|緬甸|Naypyidaw|内比都|內比都|Yangon|仰光|\bMM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇲" },
        { match: /Namibia|纳米比亚|納米比亞|\bNA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇦" },
        { match: /Nauru|瑙鲁|瑙魯|\bNR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇷" },
        { match: /Nepal|尼泊尔|尼泊爾|\bNP(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇵" },
        { match: /Netherlands|荷兰|荷蘭|\bNL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇱" },
        { match: /New Caledonia|新喀里多尼亚|\bNC(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇨" },
        { match: /New Zealand|新西兰|新西蘭|\bNZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇿" },
        { match: /Nicaragua|尼加拉瓜|\bNI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇮" },
        { match: /Niger|尼日尔|尼日爾|\bNE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇪" },
        { match: /Nigeria|尼日利亚|尼日利亞|\bNG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇬" },
        { match: /North Korea|朝鲜|朝鮮|Pyongyang|平壤|\bKP(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇵" },
        { match: /North Macedonia|北马其顿|北馬其頓|\bMK(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇲🇰" },
        { match: /Norway|挪威|\bNO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇳🇴" },
        { match: /Oman|阿曼|\bOM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇴🇲" },
        { match: /Pakistan|巴基斯坦|\bPK(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇰" },
        { match: /Palau|帕劳|帛琉|\bPW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇼" },
        { match: /Palestine|巴勒斯坦|Gaza|加沙|\bPS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇸" },
        { match: /Panama|巴拿马|巴拿馬|\bPA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇦" },
        { match: /Papua New Guinea|巴布亚新几内亚|巴布亞新畿內亞|\bPG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇬" },
        { match: /Paraguay|巴拉圭|\bPY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇾" },
        { match: /Peru|秘鲁|秘魯|\bPE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇪" },
        { match: /Philippines|菲律宾|菲律賓|Manila|马尼拉|馬尼拉|Davao|达沃|達沃|\bPH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇭" },
        { match: /Poland|波兰|波蘭|Warsaw|华沙|華沙|\bPL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇱" },
        { match: /Portugal|葡萄牙|\bPT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇵🇹" },
        { match: /Qatar|卡塔尔|卡塔爾|\bQA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇶🇦" },
        { match: /Romania|罗马尼亚|羅馬尼亞|\bRO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇷🇴" },
        { match: /Russia|俄罗斯|俄羅斯|Moscow|莫斯科|Saint Petersburg|圣彼得堡|聖彼得堡|\bRU(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇷🇺" },
        { match: /Rwanda|卢旺达|盧旺達|\bRW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇷🇼" },
        { match: /Saudi Arabia|沙特|\bSA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇦" },
        { match: /Senegal|塞内加尔|塞內加爾|\bSN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇳" },
        { match: /Serbia|塞尔维亚|塞爾維亞|\bRS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇷🇸" },
        { match: /Seychelles|塞舌尔|塞席爾|\bSC(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇨" },
        { match: /Sierra Leone|塞拉利昂|\bSL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇱" },
        { match: /Singapore|新加坡|\bSG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇬" },
        { match: /Slovakia|斯洛伐克|\bSK(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇰" },
        { match: /Slovenia|斯洛文尼亚|斯洛維尼亞|\bSI(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇮" },
        { match: /Solomon Islands|所罗门群岛|所羅門群島|\bSB(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇧" },
        { match: /Somalia|索马里|索馬里|\bSO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇴" },
        { match: /South Africa|南非|Johannesburg|约翰内斯堡|約翰內斯堡|约堡|\bZA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇿🇦" },
        { match: /South Korea|Korea|韩国|韓國|韩|韓|Seoul|首尔|首爾|Busan|釜山|Daegu|大邱|\bKR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇰🇷" },
        { match: /South Sudan|南苏丹|南蘇丹|\bSS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇸" },
        { match: /Spain|西班牙|Madrid|马德里|馬德里|Barcelona|巴塞罗那|巴塞羅那|\bES(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇪🇸" },
        { match: /Sri Lanka|斯里兰卡|斯里蘭卡|\bLK(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇱🇰" },
        { match: /Sudan|苏丹|蘇丹|\bSD(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇩" },
        { match: /Suriname|苏里南|蘇里南|\bSR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇷" },
        { match: /Sweden|瑞典|Stockholm|斯德哥尔摩|斯德哥爾摩|Gothenburg|哥德堡|\bSE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇪" },
        { match: /Switzerland|瑞士|Zurich|苏黎世|蘇黎世|\bCH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇨🇭" },
        { match: /Syria|叙利亚|敘利亞|\bSY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇸🇾" },
        { match: /Taiwan|台湾|台灣|臺灣|Taipei|台北|臺北|Tainan|台南|臺南|Taichung|台中|Kaohsiung|高雄|Hsinchu|新竹|Keelung|基隆|Chiayi|嘉义|嘉義|\bTW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇼" },
        { match: /Tajikistan|塔吉克斯坦|\bTJ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇯" },
        { match: /Tanzania|坦桑尼亚|坦桑尼亞|\bTZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇿" },
        { match: /Thailand|泰国|泰國|Bangkok|曼谷|Chiang Mai|清迈|清邁|\bTH(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇭" },
        { match: /Timor-Leste|东帝汶|東帝汶|\bTL(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇱" },
        { match: /Togo|多哥|\bTG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇬" },
        { match: /Tonga|汤加|湯加|\bTO(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇴" },
        { match: /Trinidad and Tobago|特立尼达和多巴哥|特立尼達和多巴哥|\bTT(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇹" },
        { match: /Tunisia|突尼斯|\bTN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇳" },
        { match: /Turkey|土耳其|Ankara|安卡拉|\bTR(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇷" },
        { match: /Turkmenistan|土库曼斯坦|土庫曼斯坦|\bTM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇲" },
        { match: /Tuvalu|图瓦卢|圖瓦盧|\bTV(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇹🇻" },
        { match: /Uganda|乌干达|烏干達|\bUG(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇺🇬" },
        { match: /Ukraine|乌克兰|烏克蘭|Kyiv|基辅|基輔|\bUA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇺🇦" },
        { match: /United Arab Emirates|阿联酋|阿拉伯联合酋长国|阿拉伯聯合酋長國|Dubai|迪拜|\bAE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇦🇪" },
        { match: /United Kingdom|英国|英國|英格兰|英格蘭|大不列颠|大不列顛|London|伦敦|倫敦|Manchester|曼彻斯特|曼徹斯特|Birmingham|伯明翰|\bGB(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇬🇧" },
        { match: /United States|USA|美国|美國|美(?!尼)|米国|米國|Washington|华盛顿|華盛頓|New York|纽约|紐約|Los Angeles|洛杉矶|洛杉磯|Chicago|芝加哥|Houston|休斯顿|休斯頓|Phoenix|凤凰城|鳳凰城|Philadelphia|费城|費城|San Antonio|圣安东尼奥|聖安東尼奧|San Diego|圣迭戈|聖迭戈|Dallas|达拉斯|達拉斯|San Jose|圣何塞|聖何塞|Austin|奥斯汀|奧斯汀|\bUS(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇺🇸" },
        { match: /Uruguay|乌拉圭|烏拉圭|\bUY(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇺🇾" },
        { match: /Uzbekistan|乌兹别克斯坦|烏茲別克斯坦|\bUZ(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇺🇿" },
        { match: /Vatican City|梵蒂冈|梵蒂岡|\bVA(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇻🇦" },
        { match: /Venezuela|委内瑞拉|委內瑞拉|\bVE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇻🇪" },
        { match: /Vietnam|越南|Hanoi|河内|河內|Ho Chi Minh|胡志明|\bVN(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇻🇳" },
        { match: /Yemen|也门|也門|\bYE(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇾🇪" },
        { match: /Zambia|赞比亚|贊比亞|\bZM(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇿🇲" },
        { match: /Zimbabwe|津巴布韦|津巴布韋|\bZW(?![a-zA-Z])(?:\d|\s|[\u4e00-\u9fa5])*/, emoji: "🇿🇼" }
    ];

    const emojiRegex = /[\u{1F1E6}-\u{1F1FF}]{2}/u;
    const processNameWithEmoji = (name) => {
        let newName = name;
        for (let item of emojiData) {
            if (item.match.test(newName)) {
                if (emojiRegex.test(newName)) {
                    newName = newName.replace(emojiRegex, (match, offset) => {
                        const after = newName.slice(offset + match.length);
                        if (after.length > 0 && after[0] !== ' ') {
                            return item.emoji + ' ';
                        }
                        return item.emoji;
                    });
                } else {
                    if (newName.startsWith(' ')) {
                        newName = newName.trimStart();
                    }
                    newName = `${item.emoji} ${newName}`;
                }
                break;
            }
        }
        return newName;
    };

    if (config.proxies) {
        config.proxies.forEach(p => {
            p.name = processNameWithEmoji(p.name);
        });
    }

    const excludeRegex = /(Official|官网|Data Left|Remain|剩余|流量|Expire|过期|时间|到期|Reset|重置|GB|MB)/i;
    const allProxies = config.proxies.map(p => p.name);
    const filteredProxies = allProxies.filter(name => !excludeRegex.test(name));

    // Routing Rule Generating
    config["proxy-groups"] = [
        // -------------------------------------------------------------------------------------
        {
            name: "🚀 PROXY",
            type: "select",
            proxies: ["⚡ AUTO", ...filteredProxies]
        },
        {
            name: "⚡ AUTO",
            type: "url-test",
            url: "http://www.gstatic.com/generate_204",
            interval: 600,
            hidden: true,
            proxies: filteredProxies
        },
        {
            name: "🏡 DIRECT",
            type: "select",
            hidden: true,
            proxies: ["DIRECT"]
        },
        {
            name: "🚫 REJECT",
            type: "select",
            hidden: true,
            proxies: ["REJECT"]
        },
        {
            name: "🧿 DROP",
            type: "select",
            hidden: true,
            proxies: ["REJECT-DROP"]
        },
        {
            name: "🆗 PASS",
            type: "select",
            hidden: true,
            proxies: ["PASS"]
        },
        // -------------------------------------------------------------------------------------
        {
            name: "🧼 PCDN",
            type: "select",
            proxies: ["🚫 REJECT", "🧿 DROP", "🆗 PASS"]
        },
        {
            name: "🔰 AD & Privacy",
            type: "select",
            proxies: ["🚫 REJECT", "🧿 DROP", "🆗 PASS"]
        },
        {
            name: "🧱 Firewall",
            type: "select",
            proxies: ["🚫 REJECT", "🧿 DROP", "🆗 PASS"]
        }
        // -------------------------------------------------------------------------------------
    ];

    config.rules = [
        // ------------------------------------------------------
        "GEOSITE,private,🏡 DIRECT",
        "RULE-SET,AntiAntiFraud,🚫 REJECT",
        "RULE-SET,AntiPCDNFix,🏡 DIRECT",
        "RULE-SET,AntiPCDN,🧼 PCDN",
        "RULE-SET,217heidaiAdblockFilters,🔰 AD & Privacy",
        "GEOSITE,category-ads-all,🔰 AD & Privacy",
        "RULE-SET,DirectProcess,🏡 DIRECT",
        "GEOSITE,category-games@cn,🏡 DIRECT",
        "GEOSITE,cn,🏡 DIRECT",
        "GEOSITE,!cn,🚀 PROXY",
        // ------------------------------------------------------
        "GEOIP,private,🏡 DIRECT",
        "RULE-SET,firehol_level1,🧱 Firewall",
        "GEOIP,cn,🏡 DIRECT",
        "GEOIP,!cn,🚀 PROXY",
        // ------------------------------------------------------
        "MATCH,🚀 PROXY"
    ];

    return config;
};