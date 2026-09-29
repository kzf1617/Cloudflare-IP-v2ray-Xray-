#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 扫描器 (v2ray / Xray 专用)

本程序解决的核心问题：
    普通 CF 测速工具(如 CloudflareSpeedTest)只会测『TCP 通不通 / HTTP 下载快不快』，
    因此筛出的很多 IP 一放进 v2ray(TLS + WS + CDN 回源) 就全部超时 / 软件内测速 -1。

    其主要原因是：那些 IP 虽然『整体可达』，但对『你的域名 + 443 SNI』这一条真正要用
    的链路并不成立 —— 例如被 CF 针对该 CDN 域分发、证书不匹配、回源被 CF 阻断等。

本程序改进了判定：
    阶段1 TCP 连通     —— 快速踢掉完全连不上的。
    阶段2 TLS 握手     —— 用你 v2ray 的 域名 作 SNI 建立 TLS，并校验返回证书是否匹配该域名。
                           这一步直接对应 v2ray 客户端连接该 IP 时会发生什么。
    阶段3 真实回源探测 —— 视配置对候选 IP 再发一次 HTTP/WS 探测，观察 CF 是否把请求
                           正确回源到你的 server(依据状态码与响应特征判断)。
    阶段4 下载压测     —— 对最终候选做速度抽样(可选)。
    输出 = v2ray 可直接粘贴使用的 『IP:port』 列表。

纯 Python 标准库实现，无任何第三方依赖，Python 3.8+ 即可运行。
平台: Windows / Linux / macOS 通用。

作者备注: 是否最终可用仍需在你的 v2ray 客户端 + 具体网络实测确认，
         因为 Cloudflare 会动态调整对代理/回源流量的处理(见 CloudflareSpeedTest 项目
         明确声明『禁止以代理形式使用』的免责声明)。本工具尽力筛选可建立正确 TLS/回源
         链路的 IP，以显著降低『测速 -1』的概率。
"""
import asyncio
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time

# --------------------------------------------------------------------------- #
# 常量与默认值
# --------------------------------------------------------------------------- #
PROG_NAME = "Cloudflare-优选IP for v2ray"
VERSION = "1.2.0"

# 兼容旧名字(仍指向首选源), 避免外部脚本 import 失效。
CF_IP_RANGES_URL = CF_RANGE_SOURCES[0][1] if "CF_RANGE_SOURCES" in globals() else "https://www.cloudflare.com/ips-v4"
CF_IP_RANGES_URL_V6 = "https://www.cloudflare.com/ips-v6"

# 官方段的本地缓存文件名(放在程序目录下), 联网成功时写入, 断网时优先复用。
RANGE_CACHE_FILE = "cf_ranges.cache"

# 缓存最长可使用天数(超过则视为过期, 但仍会在联网失败时兜底使用)。
RANGE_CACHE_MAX_AGE_DAYS = 30

# 官方 IP 段清单的多个来源(按顺序尝试, 任一成功即用)。
# 之所以给多个 URL: 部分地区/网络无法访问 www.cloudflare.com, 但 api.cloudflare.com
# 或第三方镜像可达; 多一个来源就少一次“回退到内置段”。
CF_RANGE_SOURCES = [
    ("cloudflare-ips-v4", "https://www.cloudflare.com/ips-v4"),
    ("cloudflare-api", "https://api.cloudflare.com/client/v4/ips"),
    ("cloudflare-ips-v4-cdn", "https://cloudflare.com/ips-v4"),
]

# 内置一份常用 CDN 段(在无网络拉取官方列表时兜底使用)。
#
# 说明: 这些是 Cloudflare 长期稳定公布的边缘网段, 覆盖其绝大多数 PoP。
# 由于无法联网时无法校验时效, 这里保留较大粒度(而不是拆成 /24),
# 由 expand_networks_to_ips() 在每个段内随机抽样, 既保证覆盖面又不会爆内存。
# 若你发现官方段已更新, 只需在此处增改即可(或改用 -f 指定本地清单)。
BUILTIN_IPV4 = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# 无法联网时用于提示的“内置段版本”, 便于日后核对是否需要更新 BUILTIN_IPV4。
BUILTIN_IPV4_SNAPSHOT = "2024-01 (CF 官方 ips-v4 快照)"

# Cloudflare 数据中心三字码(IATA 机场码) -> 所在城市/地区。
# CF 会在响应头 `cf-ray: <rayid>-<COLO>` 中回传该连接落到的机房码，
# 我们据此判断每个优选 IP 实际接入的是哪个地区节点(无需任何第三方 GeoIP 库)。
COLO_MAP = {
    "AMS": "Amsterdam", "ARN": "Stockholm", "ATL": "Atlanta", "AKL": "Auckland",
    "BOM": "Mumbai", "BOS": "Boston", "BUD": "Budapest", "BUF": "Buffalo",
    "CAI": "Cairo", "CDG": "Paris", "CGB": "Cuiaba", "CGK": "Jakarta",
    "CLT": "Charlotte", "CLE": "Cleveland", "CMH": "Columbus", "CPH": "Copenhagen",
    "CPT": "Cape Town", "CUR": "Curacao", "DAC": "Dhaka", "DEL": "New Delhi",
    "DEN": "Denver", "DFW": "Dallas", "DME": "Moscow", "DOH": "Doha",
    "DTW": "Detroit", "DUB": "Dublin", "DUS": "Dusseldorf", "DXB": "Dubai",
    "EBB": "Entebbe", "EDI": "Edinburgh", "EVN": "Yerevan", "EZE": "Buenos Aires",
    "FCO": "Rome", "FLL": "Fort Lauderdale", "FRA": "Frankfurt", "GMP": "Seoul",
    "GRU": "Sao Paulo", "GVA": "Geneva", "HEL": "Helsinki", "HKG": "Hong Kong",
    "HNL": "Honolulu", "IAD": "Ashburn", "IAH": "Houston", "ICN": "Seoul",
    "IND": "Indianapolis", "IST": "Istanbul", "JAX": "Jacksonville", "JIB": "Djibouti",
    "JNB": "Johannesburg", "KEF": "Reykjavik", "KIX": "Osaka", "KUL": "Kuala Lumpur",
    "KWI": "Kuwait", "LAD": "Luanda", "LAS": "Las Vegas", "LAX": "Los Angeles",
    "LCA": "Nicosia", "LHR": "London", "LIM": "Lima", "LIS": "Lisbon",
    "LOS": "Lagos", "MAA": "Chennai", "MAD": "Madrid", "MAN": "Manchester",
    "MCI": "Kansas City", "MCO": "Orlando", "MDE": "Medellin", "MEL": "Melbourne",
    "MEM": "Memphis", "MEX": "Mexico City", "MIA": "Miami", "MNL": "Manila",
    "MSP": "Minneapolis", "MSY": "New Orleans", "MUC": "Munich", "MXP": "Milan",
    "NAG": "Nagpur", "NRT": "Tokyo", "OMA": "Omaha", "ORD": "Chicago",
    "ORY": "Paris", "PAT": "Patna", "PDX": "Portland", "PER": "Perth",
    "PHL": "Philadelphia", "PHX": "Phoenix", "PNH": "Phnom Penh", "PRG": "Prague",
    "QRO": "Queretaro", "RDU": "Raleigh", "RIC": "Richmond", "RIX": "Riga",
    "RUH": "Riyadh", "SAN": "San Diego", "SCL": "Santiago", "SEA": "Seattle",
    "SFO": "San Francisco", "SIN": "Singapore", "SJC": "San Jose", "SLC": "Salt Lake City",
    "SOF": "Sofia", "STL": "St. Louis", "SYD": "Sydney", "TLV": "Tel Aviv",
    "TLL": "Tallinn", "TPA": "Tampa", "VIE": "Vienna", "VNO": "Vilnius",
    "WAW": "Warsaw", "YUL": "Montreal", "YVR": "Vancouver", "YYC": "Calgary",
    "YYZ": "Toronto", "ZAG": "Zagreb", "ZRH": "Zurich",
}

DEFAULT_CONFIG = {
    "domain": "",
    "port": 443,
    "ws_path": "/ws",
    "protocol": "ws",
    "use_tls": True,
    "connect_timeout": 5.0,
    "handshake_timeout": 6.0,
    "max_concurrency": 256,
    "max_download_mb": 2,          # >0 才会对候选做下载测速(越小越快)
    "download_url": "https://speed.cloudflare.com/__down?bytes=2097152",
    "verify_cert": True,
    "probe_method": "ws",          # tls | ws
    "speed_top": 10,               # 对延迟最好的前 N 个做下载测速
    "save_best": 15,
    "allow_builtin_ranges": True,  # 联网失败时允许回退到内置段(建议保持 true)
}

# ---- 让控制台/重定向中文不乱码：把标准输出统一为 UTF-8 ----
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# 运行目录适配(源码运行 / 打包成 exe 运行 都正确)
# --------------------------------------------------------------------------- #
def is_frozen():
    """是否运行在 PyInstaller 等打包出来的可执行文件里。"""
    return bool(getattr(sys, "frozen", False))


def app_dir():
    """返回程序"工作根目录"。

    - 打包成 exe 时：返回 exe 文件所在目录(不是临时解压目录 _MEIPASS)，
      这样用户放在 exe 旁边的 config.json / out 目录才会被正确读写。
    - 源码运行时：返回本脚本所在目录。
    """
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def resolve_path(p):
    """把命令行传入的相对路径统一解析到 app_dir() 之下，便于双击 exe 使用。"""
    if not p:
        return p
    if os.path.isabs(p):
        return p
    return os.path.join(app_dir(), p)


CONFIG_NOTES = [
    "domain: 【必填】你解析到 Cloudflare、且 v2ray 实际使用的域名(如 sub.example.com)。",
    "port: v2ray 节点端口，一般 443。",
    "ws_path: WS 协议下你 v2ray 入站配置的路径(如 /ws)；非 WS 协议可留空字符串。",
    "protocol: ws=WebSocket；也可填 vless / trojan。",
    "use_tls: 是否使用 TLS(对应你 v2ray 的 TLS 开关，几乎都要 true)。",
    "connect_timeout / handshake_timeout: 连接与 TLS 握手超时(秒)。",
    "max_concurrency: 并发扫描的 IP 数量(越大越快，但吃网络/CPU)。",
    "max_download_mb: 每个候选下载测速上限(MB)。0=关闭测速(速度列显示 -)。",
    "download_url: 测速用 URL，默认 CF 官方测速接口。",
    "verify_cert: 是否校验服务器证书(通常 true，会校验域名匹配)。",
    "probe_method: ws=额外做一次真实回源探测(推荐)；tls=仅握手(也会补取地区)。",
    "speed_top: 只对延迟最好的前 N 个候选做下载测速，避免整体变慢。",
    "save_best: 结果保留前多少条并写入 out/result.txt|result.csv|result.json",
    "结果里的 Region 是 CF 机房三字码(如 HKG/NRT/LAX)，取自响应头 cf-ray，即该 IP 实际接入的地区。",
]


def ensure_default_config(path):
    """若配置文件不存在则生成一份带注解的默认配置, 返回是否新建。

    打包成 exe 后第一次运行会缺 config.json，这里自动生成一份方便直接编辑。
    """
    if os.path.isfile(path):
        return False
    try:
        data = dict(DEFAULT_CONFIG)
        data["注解"] = CONFIG_NOTES
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        return True
    except Exception:
        return False



# --------------------------------------------------------------------------- #
# 日志与辅助
# --------------------------------------------------------------------------- #
class Logger:
    """简易终端日志。多协程写入加锁保护，保证整行不被其它协程打断。"""
    def __init__(self):
        self._lock = asyncio.Lock()

    async def line(self, msg, level="I"):
        ts = time.strftime("%H:%M:%S")
        async with self._lock:
            sys.stdout.write("[{}] [{}] {}\n".format(ts, level.ljust(3), msg))
            sys.stdout.flush()


def parse_colo(headers_text):
    """从 HTTP 响应头文本中解析 Cloudflare 数据中心三字码。

    CF 会返回形如:  cf-ray: 8a1b2c3d4e5f6a7b-LAX
    末尾的 LAX 即该连接落入的机房。解析失败返回 ""。
    """
    for raw in headers_text.split("\n"):
        ln = raw.strip()
        low = ln.lower()
        if low.startswith("cf-ray:") or low.startswith("cf-ray :"):
            val = ln.split(":", 1)[1].strip()
            if "-" in val:
                colo = val.rsplit("-", 1)[1].strip().upper()
                if 2 <= len(colo) <= 4 and colo.isalpha():
                    return colo
    return ""


def colo_label(colo):
    """把三字码规范成展示用标签。

    找不到映射时原样返回三字码(而不是缩写), 便于用户自行查证未知机房。
    """
    if not colo:
        return "N/A"
    return colo.upper()





# --------------------------------------------------------------------------- #
# 获取 Cloudflare IP 段
# --------------------------------------------------------------------------- #
def fetch_cf_ranges(url=CF_IP_RANGES_URL, timeout=8):
    """从单个来源获取 CF 的 IPv4 段列表；失败返回 None。

    同时兼容两种响应格式:
      - 纯文本(每行一个 CIDR)     -> cloudflare.com/ips-v4
      - JSON(含 ipv4_cidrs 数组) -> api.cloudflare.com/client/v4/ips
    """
    import urllib.request
    req = urllib.request.Request(
        url, headers={"User-Agent": f"cf-ip-scanner/{VERSION}", "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "ignore")
    except Exception:
        return None
    nets = _parse_api_json(text) if text.lstrip().startswith("{") else _parse_range_text(text)
    return nets or None


def load_ip_pool(custom_file=None, allow_builtin=True):
    """汇总待扫描的 IP 段。优先级：自定义文件 > 在线多源 > 本地缓存 > 内置段。

    返回 (ranges, source)；source 取值: custom / online:<来源名> / cache / builtin / none。
    """
    # ---- 1. 用户自定义文件(最高优先级) ----
    if custom_file and os.path.isfile(custom_file):
        ranges = _read_range_file(custom_file)
        if ranges:
            print(f"[i] 使用自定义 IP 文件: {custom_file} (段数={len(ranges)})")
            return ranges, "custom"
        print(f"[!] 自定义 IP 文件 {custom_file} 中没有有效条目, 回退到在线/缓存/内置段。")

    cache_path = os.path.join(app_dir(), RANGE_CACHE_FILE)

    # ---- 2. 在线多来源(逐个尝试, 任一成功即用) ----
    last_url = ""
    for name, url in CF_RANGE_SOURCES:
        online = fetch_cf_ranges(url)
        if online:
            print(f"[i] 已从 {name} 拉取官方 IPv4 段 {len(online)} 个")
            _save_cached_ranges(cache_path, online)
            return online, f"online:{name}"
        last_url = url

    # ---- 3. 本地缓存(上次联网成功时留下的) ----
    cached, ts = _load_cached_ranges(cache_path)
    if cached:
        age = _cache_age_days(ts)
        age_txt = "时间未知" if age is None else f"{age:.1f} 天前"
        warn = ""
        if age is None or age > RANGE_CACHE_MAX_AGE_DAYS:
            warn = f" (已超过 {RANGE_CACHE_MAX_AGE_DAYS} 天, 建议联网后重跑以刷新)"
        print(f"[!] 无法联网获取官方段(最后尝试 {last_url}), 改用本地缓存 "
              f"{os.path.basename(cache_path)}: {len(cached)} 段, 更新于{age_txt}{warn}")
        return cached, "cache"

    # ---- 4. 内置段(最后兜底) ----
    if allow_builtin:
        print(f"[!] 无法从网络获取官方段, 使用内置段 {BUILTIN_IPV4_SNAPSHOT} "
              f"({len(BUILTIN_IPV4)} 段); 内置段可能过期, 建议日后更新代码中 BUILTIN_IPV4")
        return list(BUILTIN_IPV4), "builtin"

    print("[!] 无法获取任何 IP 段(在线失败且 allow_builtin_ranges=false), 无法继续。")
    return [], "none"


def _read_range_file(path):
    """读取用户提供的 IP/CIDR 列表文件, 支持注释/逗号/空格分隔与裸 IP。"""
    ranges = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            # 支持行内注释与逗号/空格分隔
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            for token in line.replace(",", " ").split():
                token = token.strip()
                if not token:
                    continue
                if "/" not in token:
                    # 裸 IP 自动补 /32，便于用户直接粘贴单个 IP
                    try:
                        ipaddress.ip_address(token)
                        token += "/32"
                    except ValueError:
                        print(f"[!] 忽略非法条目: {token}")
                        continue
                else:
                    try:
                        ipaddress.ip_network(token, strict=False)
                    except ValueError:
                        print(f"[!] 忽略非法条目: {token}")
                        continue
                ranges.append(token)
    return ranges


def _parse_range_text(text, expect_v4=True):
    """把一份官方段文本(每行一个 CIDR)解析为合法段列表, 无有效条目时返回 []。"""
    nets = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if expect_v4 and net.version != 4:
            continue
        nets.append(str(net))
    return nets


def _parse_api_json(text):
    """解析 api.cloudflare.com/client/v4/ips 的 JSON 响应, 提取 ipv4_cidrs。"""
    try:
        data = json.loads(text)
    except Exception:
        return []
    result = data.get("result") or {}
    return _parse_range_text("\n".join(result.get("ipv4_cidrs") or []))


def _load_cached_ranges(path):
    """读取本地缓存的段文件, 返回 (段列表, 缓存时间戳|None)。"""
    if not path or not os.path.isfile(path):
        return [], None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        nets = _parse_range_text("\n".join(data.get("ranges") or []))
        return nets, data.get("ts")
    except Exception:
        return [], None


def _save_cached_ranges(path, nets):
    """把成功的段列表写入本地缓存, 便于之后断网时复用。失败静默忽略。"""
    if not path or not nets:
        return
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"ts": time.time(),
                       "saved": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "ranges": list(nets)}, f, indent=2)
        os.replace(tmp, path)      # 原子替换, 避免写一半被中断导致缓存损坏
    except Exception:
        pass


def _cache_age_days(ts):
    """把缓存时间戳换算成"多少天前", 失败返回 None。"""
    try:
        return max(0.0, (time.time() - float(ts)) / 86400.0)
    except Exception:
        return None


def expand_networks_to_ips(networks, max_per_network=None, seed=None):
    """把 CIDR 段展开成具体候选 IP。

    相比旧版的三点改进：
      1. 不再用 rng.sample(range(...)) —— 该写法会先在 [0, N) 上做 range 映射,
         对 104.16.0.0/13 这类 52 万地址的大段会产生大量中间对象。
         现在直接对「偏移量」做随机采样, 成本只与采样数有关。
      2. 小段(<=512 地址)仍然全量枚举, 保证 /24 级别的段不会漏点。
      3. 采样配额按段大小加权分配: 大段多抽、小段少抽, 让覆盖更均匀,
         同时保证总的候选规模可预期(便于快速跑完一轮)。
    """
    rng = random.Random(seed) if seed is not None else random.Random()
    parsed = []
    for net_str in networks:
        try:
            net = ipaddress.ip_network(net_str, strict=False)
        except ValueError:
            print(f"[!] 忽略非法段: {net_str}")
            continue
        if net.version != 4:
            continue
        # 只有 prefixlen<=30 的传统子网才有"网络地址/广播地址"不可用的说法；
        # /31、/32 是特殊用途(点对点/单主机)，首尾都应当保留，
        # 否则像用户直接写单个 IP 的 "1.2.3.4/32" 会被错误地算成 0 个候选。
        if net.prefixlen <= 30:
            first = int(net.network_address) + 1      # 跳过网络地址
            last = int(net.broadcast_address) - 1     # 跳过广播地址
        else:
            first = int(net.network_address)
            last = int(net.broadcast_address)
        total = last - first + 1
        if total <= 0:
            continue
        parsed.append((first, last, total))

    if not parsed:
        return []

    # ---- 先做小段全量枚举, 并统计需要抽样的大段 ----
    ip_list = []
    big = []
    for first, last, total in parsed:
        if total <= 512:
            ip_list.extend(str(ipaddress.IPv4Address(v)) for v in range(first, last + 1))
        else:
            big.append((first, last, total))

    if not big:
        return ip_list

    # ---- 大段按大小加权分配采样配额(至少 8 个/段, 避免小段被饿死) ----
    per = max_per_network if max_per_network and max_per_network > 0 else 300
    total_big = sum(t for _, _, t in big)
    quota = []
    for first, last, t in big:
        share = int(round(per * (t / total_big) * len(big)))
        quota.append(max(8, min(share, per, t)))

    for (first, last, t), n in zip(big, quota):
        # 直接在偏移量上抽样(不走 range 物化), 速度与 n 成正比
        spans = set()
        while len(spans) < n:
            spans.add(rng.randrange(t))
        ip_list.extend(str(ipaddress.IPv4Address(first + off)) for off in spans)

    return ip_list


# --------------------------------------------------------------------------- #
# 单 IP 探测协程(TCP + TLS + 证书校验收 + 可选 WS 回源)
# --------------------------------------------------------------------------- #
RESULT_OK = "ok"
RESULT_TCP_FAIL = "tcp_fail"
RESULT_TLS_FAIL = "tls_fail"
RESULT_CERT_FAIL = "cert_fail"
RESULT_WS_FAIL = "ws_fail"

def _build_tls_context(cfg):
    """构造适用于连接 CF 边缘的 SSLContext。

    关键点：
      - 用系统 CA。verify_cert=True 时开启证书链与 hostname 校验(SNI=你的域名)；
        verify_cert=False 时仅做匿名校验(仍可拿到证书信息用于调试)。
      - 关闭会拖慢握手的老旧/不必要选项。
    """
    if cfg.get("verify_cert", True):
        ctx = ssl.create_default_context()          # CA from 系统库
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx


# SSLContext 创建成本不低(要加载系统根证书), 而整个扫描过程中 verify_cert
# 只有 True/False 两种取值 —— 因此按需缓存两份即可, 避免每个 IP 都重建一次。
_TLS_CONTEXT_CACHE = {}


def get_tls_context(verify):
    """按需构造并缓存 SSLContext(verify 为 bool)。"""
    key = bool(verify)
    ctx = _TLS_CONTEXT_CACHE.get(key)
    if ctx is None:
        ctx = _build_tls_context({"verify_cert": key})
        _TLS_CONTEXT_CACHE[key] = ctx
    return ctx


async def probe_ip(ip, cfg, logger):
    """对单个 IP 执行到 CF 边缘 + 你域名对应的完整链路探测。

    返回: (RESULT_xxx, ip, details_dict)
      details 里含耗时/证书/状态码/机房(colo)等, 便于上层排序与输出说明。
    """
    domain = cfg["domain"]
    port = int(cfg.get("port", 443) or 443)
    probe = cfg.get("probe_method", "ws")

    connect_to = cfg.get("connect_timeout", 5.0)
    t1 = time.perf_counter()

    ctx = get_tls_context(cfg.get("verify_cert", True))
    try:
        if cfg.get("use_tls", True) is False:
            # 纯 TCP(不适合本工具主要场景, 但保留灵活性)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, family=socket.AF_INET),
                    timeout=connect_to)
            except (OSError, asyncio.TimeoutError):
                return RESULT_TCP_FAIL, ip, {"err": "tcp connect fail"}
            t2 = time.perf_counter()
            writer.close()
            return RESULT_OK, ip, {"tcp_ms": round((t2 - t1) * 1000, 1), "colo": ""}
        # ---------------- TLS 连接(含 SNI = 你的域名) ----------------
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, port, ssl=ctx, server_hostname=domain,
                    family=socket.AF_INET),
                timeout=connect_to)
        except (ssl.SSLCertVerificationError,) as e:
            # 能连上 TLS 但证书校验失败 -> 单独分类, 便于用户判断
            return RESULT_CERT_FAIL, ip, {"err": f"cert verify fail: {_abbrev(str(e))}"}
        except (ssl.SSLError, OSError, asyncio.TimeoutError, TimeoutError) as e:
            if isinstance(e, (asyncio.TimeoutError, TimeoutError)):
                return RESULT_TLS_FAIL, ip, {"err": "handshake timeout"}
            return RESULT_TLS_FAIL, ip, {"err": f"{type(e).__name__}: {_abbrev(str(e))}"}
        except Exception as e:
            return RESULT_TLS_FAIL, ip, {"err": f"{type(e).__name__}: {_abbrev(str(e))}"}

        t2 = time.perf_counter()
        tls_ms = round((t2 - t1) * 1000, 1)
        cert_subject = ""
        try:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is not None:
                peer_cert = sslobj.getpeercert()
                if peer_cert:
                    cert_subject = str(peer_cert.get("subject", ""))
        except Exception:
            pass

        # ---------------- WS 回源探测(同时也是取 colo 的时机) ----------------
        if probe == "ws":
            status, reason, headers_text, _head_ms = await _ws_probe(reader, writer, cfg)
            colo = parse_colo(headers_text)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except Exception:
                pass
            total_ms = round((time.perf_counter() - t1) * 1000, 1)
            if status is None:
                return RESULT_WS_FAIL, ip, {"err": f"ws read fail: {reason}",
                                            "tls_ms": tls_ms}
            # 判定: 预期 CF 会回源。返回如下即代表链路已通到你的 server/CF：
            #  101 = 命中 WS Upgrade 且对方确认(通常是 WS 节点自身)
            #  200/404 = 触达了源站但路径/方法不对(仍说明回源链路 OK)
            #  403/503/530 = CF 对该流量拦截或无正确回源 host
            if status in (101, 200, 404):
                note = {101: "WS upgrade ok", 200: "originated ok",
                        404: "origin path miss(链通)"}[status]
                return RESULT_OK, ip, {"kind": "ws+origin", "status": status,
                                       "note": note, "colo": colo,
                                       "tls_ms": tls_ms, "total_ms": total_ms,
                                       "cert": cert_subject}
            return RESULT_WS_FAIL, ip, {"kind": "ws+origin", "status": status,
                                        "note": f"origin response {status} {reason}",
                                        "colo": colo, "tls_ms": tls_ms,
                                        "total_ms": total_ms}

        # ---------------- 仅 TLS 模式：补一次轻量 HEAD 只为取 cf-ray(地区) ----------------
        colo = ""
        try:
            colo, _extra = await _colo_probe(reader, writer, cfg)
        except Exception:
            colo = ""
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass
        total_ms = round((time.perf_counter() - t1) * 1000, 1)
        return RESULT_OK, ip, {"kind": "tls", "tls_ms": tls_ms,
                               "total_ms": total_ms, "cert": cert_subject,
                               "colo": colo}
    except Exception as e:  # 兜底
        return RESULT_TLS_FAIL, ip, {"err": f"{type(e).__name__}: {_abbrev(str(e))}"}



def _abbrev(s, n=120):
    s = (s or "").strip().replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


async def _ws_probe(reader, writer, cfg):
    """在已建立的 TLS 连接上，向 CF(回源到你的 server)发起一次 HTTP/1.1 探测请求。

    用到的技巧：我们并不真的需要完成 WebSocket 双向帧。只要 CF 边缘把你的请求按
    Host/域名 路由并回源，就会在服务器端把请求交给你的 Caddy→v2ray 或直接返回状态码。
    我们依据『收到的 HTTP 首行状态』判断这一整条回源链是否通；同时读取响应头里的
     `cf-ray: xxx-<COLO>`，得到该 IP 实际落到的 Cloudflare 机房(地区)。

    返回值: (status:int|None, reason:str, headers_text:str, 耗时ms)
    """
    domain = cfg["domain"]
    port = int(cfg.get("port", 443) or 443)
    ws_path = (cfg.get("ws_path", "") or "/")
    protocol = (cfg.get("protocol", "ws") or "ws").lower()
    hto = max(1.0, float(cfg.get("handshake_timeout", 6.0) or 6.0))

    # 根据协议决定请求行/头(尽量模拟 v2ray 客户端发出的形态以触发 Caddy 反代)
    if protocol in ("ws", "websocket"):
        request_target = ws_path
        upgrade_headers = (
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        )
    else:
        # vless / trojan 也以 TLS 承载，这里只用标准 GET 探测回源即可。
        request_target = "/"
        upgrade_headers = ""

    hostline = f"Host: {domain}:{port}" if port not in (443, 80) else f"Host: {domain}"
    req = (
        f"GET {request_target} HTTP/1.1\r\n"
        f"{hostline}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36\r\n"
        "Accept: */*\r\n"
        f"{upgrade_headers}"
        "X-Forwarded-Proto: https\r\n"
        "\r\n"
    )
    try:
        writer.write(req.encode("utf-8", "ignore"))
        await asyncio.wait_for(writer.drain(), timeout=hto)
    except Exception:
        return None, "", "", -1

    # ---- 读取响应头(读到 \r\n\r\n 为止, 不等 body) ----
    t0 = time.perf_counter()
    try:
        buf = b""
        max_bytes = 32 * 1024
        while b"\r\n\r\n" not in buf and len(buf) < max_bytes:
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=hto)
            except (asyncio.TimeoutError, TimeoutError):
                return None, "read-timeout", "", round((time.perf_counter() - t0) * 1000)
            if not chunk:
                break
            buf += chunk
        head_bytes = buf.split(b"\r\n\r\n", 1)[0]
        head_str = head_bytes.decode("utf-8", "ignore")
        lines = head_str.split("\r\n")
        if not lines or not lines[0]:
            return None, "no-response", "", round((time.perf_counter() - t0) * 1000)
        m = lines[0].split(" ", 2)
        if len(m) < 2 or not m[0].startswith("HTTP/"):
            return None, lines[0][:60], head_str, round((time.perf_counter() - t0) * 1000)
        try:
            status = int(m[1])
        except ValueError:
            status = 0
        reason = m[2] if len(m) > 2 else ""
        return status, reason, head_str, round((time.perf_counter() - t0) * 1000)
    except (asyncio.TimeoutError, TimeoutError):
        return None, "read-timeout", "", round((time.perf_counter() - t0) * 1000)
    except Exception:
        return None, "io-error", "", round((time.perf_counter() - t0) * 1000)


async def _colo_probe(reader, writer, cfg):
    """仅用于 `probe_method=tls` 时补取所在机房(地区)。

    在已完成 TLS 握手的连接上发一个最小 HEAD 请求，只为从响应头里取 `cf-ray` 的
    colo 后缀。失败不影响主判定结果。
    返回 (colo:str, headers_text:str)
    """
    domain = cfg["domain"]
    port = int(cfg.get("port", 443) or 443)
    hto = max(1.0, float(cfg.get("handshake_timeout", 6.0) or 6.0))
    hostline = f"Host: {domain}:{port}" if port not in (443, 80) else f"Host: {domain}"
    req = (f"HEAD / HTTP/1.1\r\n{hostline}\r\n"
           "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36\r\n"
           "Accept: */*\r\n\r\n").encode("utf-8", "ignore")
    try:
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=hto)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 32 * 1024:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=hto)
            if not chunk:
                break
            buf += chunk
        head_str = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "ignore")
        return parse_colo(head_str), head_str
    except Exception:
        return "", ""



# --------------------------------------------------------------------------- #
# 速度抽样(对延迟最优的前若干候选执行)
# --------------------------------------------------------------------------- #
async def _speed_probe(ip, cfg):
    """对指定 IP(不是域名) 做一次有上限的 HTTP(S) 下载测速。

    修复了旧实现的真实缺陷：
      - 旧版把「测速域名」直接拿去 open_connection，等于测了域名解析到的某个边缘，
        完全没用到待测 IP，测出来的速度与被测 IP 无关；
      - 旧版把可能带端口的 netloc 再拼端口，会构造出非法地址。

    现在：连接【被测 IP】:port，SNI/Host 用测速域名(默认 CF 官方测速端点)，
    下载 max_download_mb 上限即停，返回 MB/s。
    """
    mb = float(cfg.get("max_download_mb", 0) or 0)
    if mb <= 0:
        return None
    need = int(mb * 1048576)
    url = cfg.get("download_url", "") or "https://speed.cloudflare.com/__down"
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or "speed.cloudflare.com"
    path = parsed.path or "/__down"
    if parsed.query:
        path += "?" + parsed.query
    # 让请求的字节数与我们要统计的上限一致(CF 测速端点看 bytes 参数)
    if "__down" in path and "bytes=" not in path:
        path += ("&" if "?" in path else "?") + f"bytes={need}"
    port = int(cfg.get("port", 443) or 443)
    # 测速端点不是你的域名证书，跳过校验
    ctx = get_tls_context(False)
    limit_s = max(3.0, float(cfg.get("speed_time_limit", 6.0) or 6.0))

    t0 = time.perf_counter()
    got = 0
    body_seen = 0
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host),
            timeout=float(cfg.get("connect_timeout", 5.0) or 5.0))
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36\r\n"
               "Accept: */*\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n")
        writer.write(req.encode("utf-8", "ignore"))
        await writer.drain()
        header_done = False
        while got < need and (time.perf_counter() - t0) < limit_s:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=limit_s)
            except (asyncio.TimeoutError, TimeoutError):
                break
            if not chunk:
                break
            if not header_done:
                # 跳过响应头，只统计 body 字节
                if b"\r\n\r\n" in chunk:
                    header_done = True
                    body_seen += len(chunk.split(b"\r\n\r\n", 1)[1])
                continue
            body_seen += len(chunk)
            got += len(chunk)
    except Exception:
        pass
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    dt = time.perf_counter() - t0
    if dt <= 0 or body_seen <= 0:
        return None
    return {"speed_mbps": body_seen / dt / 1048576.0,
            "bytes": body_seen, "sec": dt}


# --------------------------------------------------------------------------- #
# 结果排序 / 写入 + 输出 CLI 摘要
# --------------------------------------------------------------------------- #
def make_v2ray_address_list(ok_list, port):
    """把通过的候选按延迟升序整理成结果行(含地区 colo)。"""
    sortable = []
    for ip, d in ok_list:
        lat = d.get("total_ms") or d.get("tls_ms") or 9999
        sortable.append((lat, ip, d))
    sortable.sort(key=lambda x: x[0])
    rows = []
    for lat, ip, d in sortable:
        rows.append({
            "ip": ip,
            "port": port,
            "region": colo_label(d.get("colo", "")),
            "colo": d.get("colo", ""),
            "delay_ms": lat,
            "speed_mbps": None,          # 由 attach_speed 填入
            "kind": d.get("kind", ""),
            "status": d.get("status", ""),
            "note": d.get("note", ""),
        })
    return rows


async def attach_speed(rows, cfg, logger, logger_pref="I"):
    """对延迟最好的前 speed_top 个候选执行下载测速, 把结果写回 rows。

    只测少量候选，避免拖慢整体扫描；可用 config 的 speed_top / max_download_mb 调整。
    """
    if not rows:
        return
    mb = float(cfg.get("max_download_mb", 0) or 0)
    top = int(cfg.get("speed_top", 0) or 0)
    if mb <= 0 or top <= 0:
        return
    targets = rows[:top]
    await logger.line(f"对延迟最优的 {len(targets)} 个候选做下载测速(每个上限 {mb:g} MB)...")
    sem = asyncio.Semaphore(4)   # 限流，避免测速互相抢带宽导致结果失真

    async def one(r):
        async with sem:
            res = await _speed_probe(r["ip"], cfg)
            if res:
                r["speed_mbps"] = res["speed_mbps"]

    await asyncio.gather(*(one(r) for r in targets))


def save_result(list_rows, dest_dir, domain="", port=443, probe=""):
    """写出 result.txt(可读表格+纯 IP 列表)、result.csv、result.json。"""
    os.makedirs(dest_dir, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # ---- result.txt：上半是可读表格, 下半是可直接粘贴的 IP:端口 ----
    path = os.path.join(dest_dir, "result.txt")
    header = [
        "# Cloudflare 优选IP (可替换 v2ray 节点的 address)",
        f"# 生成时间: {stamp}",
        f"# 目标域名: {domain}   端口: {port}   探测模式: {probe}",
        f"# 共 {len(list_rows)} 条 (按延迟升序)",
        "# Region = Cloudflare 机房三字码(如 HKG/NRT/LAX), 代表该 IP 实际接入的地区",
        "",
    ]
    table_hdr = f"{'#':<4}{'IP':<20}{'Region':<8}{'Delay(ms)':<11}{'Speed(MB/s)':<13}{'Note'}"
    lines = list(header) + [table_hdr, "-" * 78]
    for i, r in enumerate(list_rows, 1):
        spd = f"{r['speed_mbps']:.2f}" if r.get("speed_mbps") else "-"
        lines.append(
            f"{i:<4}{r['ip']:<20}{r['region']:<8}{r['delay_ms']:<11}{spd:<13}"
            f"{r.get('note','')}"
        )
    lines.append("-" * 78)
    lines.append("")
    lines.append("# ===== 以下为可直接复制到 v2ray 的 IP:端口 =====")
    lines.extend(f"{r['ip']}:{r['port']}" for r in list_rows)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    # ---- result.csv：便于表格软件查看/筛选地区与速度 ----
    csv_path = os.path.join(dest_dir, "result.csv")
    try:
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            f.write("ip,port,region,colo,delay_ms,speed_mbps,kind,status,note\n")
            for r in list_rows:
                spd = f"{r['speed_mbps']:.2f}" if r.get("speed_mbps") else ""
                note = (r.get("note", "") or "").replace(",", ";")
                f.write(f"{r['ip']},{r['port']},{r['region']},{r.get('colo','')},"
                        f"{r['delay_ms']},{spd},{r.get('kind','')},"
                        f"{r.get('status','')},{note}\n")
    except Exception:
        csv_path = ""

    # ---- result.json ----
    json_path = os.path.join(dest_dir, "result.json")
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(list_rows, f, ensure_ascii=False, indent=2)
    except Exception:
        json_path = ""

    return path, csv_path, json_path


def display_table(rows):
    """在终端打印含地区/速度的对齐表格。"""
    print()
    print("-" * 82)
    print(f"{'#':<4}{'IP':<20}{'Region':<8}{'Delay(ms)':<11}{'Speed(MB/s)':<13}{'Note'}")
    print("-" * 82)
    for i, r in enumerate(rows, 1):
        spd = f"{r['speed_mbps']:.2f}" if r.get("speed_mbps") else "-"
        print(f"{i:<4}{r['ip']:<20}{r['region']:<8}{r['delay_ms']:<11}{spd:<13}"
              f"{(r.get('note','') or '')[:34]}")
    print("-" * 82)



# --------------------------------------------------------------------------- #
# 扫描调度
# --------------------------------------------------------------------------- #
async def run_scan(ip_pool, cfg, logger):
    """并发对每个候选 IP 探测，返回 (ok_results, fail_stat)。

       ok_results: list[(ip, details)]
       fail_stat: dict{分类->count}，用于向用户解释『为何大量 -1』

    说明: 结果列表与计数都只在事件循环里被协程修改, 无需加锁;
    进度按「时间间隔」节流打印(而不是每批打印), 避免几千个候选刷屏。
    """
    sem = asyncio.Semaphore(int(cfg.get("max_concurrency", 200)))
    fail_stat = {}
    ok_results = []

    async def worker(ip):
        async with sem:
            st, ipx, det = await probe_ip(ip, cfg, logger)
            if st == RESULT_OK:
                ok_results.append((ipx, det))
            else:
                fail_stat[det.get("err", "?")[:60]] = \
                    fail_stat.get(det.get("err", "?")[:60], 0) + 1

    # 分批提交，避免一次创建过多 task
    batch = 400
    total = len(ip_pool)
    done = 0
    t0 = time.perf_counter()
    last_log = 0.0

    for i in range(0, total, batch):
        tasks = [asyncio.create_task(worker(ip)) for ip in ip_pool[i:i + batch]]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        done += len(tasks)

        # 节流: 至少间隔 1.5 秒或最后一批才打印一次进度(避免刷屏)
        now = time.perf_counter()
        if done >= total or (now - last_log) >= 1.5:
            last_log = now
            elapsed = now - t0
            rate = done / elapsed if elapsed > 0 else 0.0
            eta = (total - done) / rate if rate > 0 else 0.0
            await logger.line(
                f"进度 {done}/{total} ({done * 100 // max(1, total)}%)  "
                f"通过 {len(ok_results)}  失败 {sum(fail_stat.values())}  "
                f"{rate:.0f} IP/s  预计剩余 {eta:.0f}s")
    return ok_results, fail_stat


def summarize_failures(fail_stat, top_n=6):
    """把失败原因聚合成更易读的分类统计(供终端与结果文件使用)。

    探测失败信息里往往带具体错误串(含端口/IP/SSL 版本等噪声), 直接按原文计数
    会得到几十条碎条目。这里做一次归类: 证书/超时/连接被拒/DNS/其它。
    """
    buckets = {
        "证书校验失败": 0,
        "TLS 握手超时": 0,
        "TCP 连接失败/超时": 0,
        "连接被重置 / 对端关闭": 0,
        "回源响应异常": 0,
        "其它": 0,
    }
    for reason, cnt in (fail_stat or {}).items():
        low = reason.lower()
        if "cert" in low or "certificate" in low:
            buckets["证书校验失败"] += cnt
        elif "handshake timeout" in low or ("tls" in low and "timeout" in low):
            buckets["TLS 握手超时"] += cnt
        elif "tcp connect fail" in low or ("tcp" in low and "timeout" in low):
            buckets["TCP 连接失败/超时"] += cnt
        elif "reset" in low or "eof" in low or "closed" in low or "aborted" in low:
            buckets["连接被重置 / 对端关闭"] += cnt
        elif "origin response" in low or "ws read fail" in low or "read-timeout" in low:
            buckets["回源响应异常"] += cnt
        else:
            buckets["其它"] += cnt
    # 只保留非零项, 并按数量降序
    items = [(k, v) for k, v in buckets.items() if v > 0]
    items.sort(key=lambda kv: -kv[1])
    return items[:top_n] or [("(无失败记录)", 0)]


def build_arg_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog="cloudflare_speedtest.py",
        description="Cloudflare 优选 IP 扫描(v2ray/Xray ws+tls 专用判定)",
        epilog="示例: python cloudflare_speedtest.py -d 你的域名.com -p 443 -P /ws --threads 128")
    p.add_argument("-c", "--config", default="config.json",
                   help="配置文件(json)。命令行部分参数可覆盖它。")
    p.add_argument("-d", "--domain", default="", help="你 v2ray 实际使用并解析到 CF 的域名")
    p.add_argument("-p", "--port", type=int, default=0, help="端口(默认读配置, 通常 443)")
    p.add_argument("-P", "--ws-path", default="", help="WS path, 如 /ws (用于真实回源探测)")
    p.add_argument("-t", "--threads", type=int, default=0, help="并发线程数")
    p.add_argument("-f", "--ip-file", default="", help="自定义 IP 段/单个IP 文件(每行一个 CIDR 或 IP)")
    p.add_argument("-n", "--num", type=int, default=0,
                   help="最终只随机抽取 N 个候选进行扫描(默认 0=全部; 想快速试跑可设 100)")
    p.add_argument("-N", "--net-samples", type=int, default=0,
                   help="每个大段(/24 以上)抽取的样本数上限, 默认 300")
    p.add_argument("-m", "--probe", default="", choices=["", "tls", "ws"],
                   help="探测模式: tls(仅握手校验证书) / ws(加回源探测)")
    p.add_argument("--no-verify", action="store_true",
                   help="跳过证书 hostname 校验(仅做握手, 不建议)")
    p.add_argument("--save-dir", default="out", help="结果目录")
    p.add_argument("--no-builtin", action="store_true",
                   help="禁止在联网失败时回退到内置段(此时若也无本地缓存则直接报错退出)")
    p.add_argument("--max-download-mb", type=float, default=-1,
                   help="每个候选的下载测速上限(MB)。-1=读配置, 0=关闭测速。注意: 测的是到该边缘的带宽, 不代表能否代理。")
    p.add_argument("--speed-top", type=int, default=-1,
                   help="只对延迟最好的前 N 个候选做下载测速(默认读配置, 10)。")
    p.add_argument("--no-speed", action="store_true",
                   help="完全关闭下载测速(速度列显示 -), 扫描更快。")
    return p


def merge_config(cli):
    """读取 config.json 再用命令行覆盖。

    路径解析规则(保证双击 exe 也能用)：
      - 未显式传 -c 时，使用 exe/脚本所在目录下的 config.json；
      - 显式传了相对路径，也相对 app_dir() 解析；
      - 文件不存在时自动生成一份默认配置，方便用户直接编辑。
    """
    cfg = dict(DEFAULT_CONFIG)
    cfg_path = resolve_path(cli.config or "config.json")
    if cfg_path and os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                fd = json.load(f)
        except Exception as e:
            print(f"[!] 配置文件解析失败({e}), 使用默认配置。")
            fd = {}
        for k, v in fd.items():
            if not k.startswith("_") and not isinstance(v, list):
                cfg[k] = v
    else:
        if ensure_default_config(cfg_path):
            print(f"[i] 未找到配置文件, 已生成默认配置: {cfg_path}")
            print("    请编辑其中的 domain(你的 CF 域名) 后重新运行。")
    if cli.domain:
        cfg["domain"] = cli.domain
    if cli.port:
        cfg["port"] = cli.port
    if cli.ws_path:
        cfg["ws_path"] = cli.ws_path
    if cli.threads:
        cfg["max_concurrency"] = cli.threads
    if cli.probe:
        cfg["probe_method"] = cli.probe
    if cli.no_verify:
        cfg["verify_cert"] = False
    if cli.max_download_mb >= 0:
        cfg["max_download_mb"] = cli.max_download_mb
    if cli.speed_top >= 0:
        cfg["speed_top"] = cli.speed_top
    if cli.no_speed:
        cfg["max_download_mb"] = 0
        cfg["speed_top"] = 0
    # --no-builtin 命令行开关优先级最高; 否则看配置里的 allow_builtin_ranges(默认 true)。
    if cli.no_builtin:
        cfg["allow_builtin_ranges"] = False
    cfg["_config_path"] = cfg_path
    return cfg, cli

def main():
    parser = build_arg_parser()
    cli = parser.parse_args()

    # 统一把用户传的相对路径解析到程序目录(exe 所在目录)，方便双击运行
    cli.ip_file = resolve_path(cli.ip_file) if cli.ip_file else ""
    cli.save_dir = resolve_path(cli.save_dir) if cli.save_dir else "out"

    cfg, _cli = merge_config(cli)
    domain = (cfg.get("domain") or "").strip()
    # ---- 关键约束：必须先有可用域名 ----
    if not domain or domain.startswith("你的域名") or "example.com" == domain:
        print(f"""
{'=' * 62}
  [需要配置] 还没有设置你的 Cloudflare 域名, 无法开始扫描。

  配置文件位置:
      {cfg['_config_path']}

  请这样做:
      1. 用记事本打开上面的 config.json
      2. 把 "domain": ""  改成你 v2ray 里实际使用、
         并且已经解析到 Cloudflare 的那个域名, 例如:
             "domain": "sub.example.com"
      3. 如果你 v2ray 用的是 WebSocket, 确认 "ws_path" 与节点里的路径一致(如 /ws)
      4. 保存后重新运行本程序

  也可以直接用命令行临时指定(不用改配置文件):
      CF优选IP.exe -d sub.example.com -p 443 -P /ws
{'=' * 62}""")
        return
    port = int(cfg["port"] or 443)
    mb = float(cfg.get("max_download_mb", 0) or 0)
    speed_desc = f"开(前 {cfg.get('speed_top')} 个, 每个 {mb:g}MB)" if mb > 0 else "关"

    print(f"\n[程序目录] {app_dir()}")
    banner = f"""
{'=' * 60}
  {PROG_NAME}  v{VERSION}
  目标域名    : {domain}
  目标端口    : {port}
  WS path     : {cfg.get('ws_path') or '(未启用/由协议决定)'}
  探测模式    : {cfg.get('probe_method')}
  校验证书    : {('是(域名匹配)' if cfg.get('verify_cert') else '否(SKIP)')}
  并发        : {cfg.get('max_concurrency')}
  下载测速    : {speed_desc}
  结果地区    : Cloudflare 机房三字码 (取自响应头 cf-ray)
{'=' * 60}"""
    print(banner)

    # ---- 1. 生成扫描候选 ----
    ranges, source = load_ip_pool(cli.ip_file,
                                  allow_builtin=bool(cfg.get("allow_builtin_ranges", True)))
    if not ranges:
        print("[!] 没有可用的 IP 段(可能因为 --no-builtin 且无在线/缓存可用), 结束。")
        return
    net_samples = cli.net_samples if cli.net_samples > 0 else 300
    pool = expand_networks_to_ips(ranges, max_per_network=net_samples,
                                  seed=int(time.time()) % (2**31))
    # -n: 统一语义 = 「最终随机抽取 N 个候选」。与来源(自定义/在线/缓存/内置)无关。
    if cli.num and cli.num > 0 and len(pool) > cli.num:
        pool = random.Random().sample(pool, cli.num)
    print(f"[i] 共准备候选 IP: {len(pool)} 个 (段来源: {source}, 每大段样本上限: {net_samples})")
    if not pool:
        print("[!] 没有可扫描的 IP，结束。")
        return

    logger = Logger()

    async def pipeline():
        t0 = time.perf_counter()
        ok_list, fail_stat = await run_scan(pool, cfg, logger)
        rows = make_v2ray_address_list(ok_list, port)
        # 对延迟最优的前若干个做下载测速(可关闭)
        await attach_speed(rows, cfg, logger)
        return rows, fail_stat, time.perf_counter() - t0

    rows, fail_stat, el = asyncio.run(pipeline())

    # ---- 3. 输出 ----
    print("\n" + "=" * 60)
    print(f"[完成] 扫描 {len(pool)} 个候选, 耗时 {el:.1f}s, "
          f"测试通过(能被你的域名正常 TLS/回源) {len(rows)} 个")

    if fail_stat:
        print("\n最常见的『不可用原因』(这往往就是普通工具筛出后 v2ray -1 的根源):")
        for reason, cnt in summarize_failures(fail_stat):
            print(f"   - [{cnt:>5}]  {reason}")

    if rows:
        print(f"\n注: 以下 IP 对『{domain}』均建立起了正确 TLS 并由 CF 做了回源, "
              f"按延迟排序。Region 为该 IP 实际接入的 CF 机房(地区)。")
        display_table(rows)

        save_best = int(cfg.get("save_best", 15) or 15)
        to_save = rows[:save_best]
        txt_path, csv_path, json_path = save_result(
            to_save, cli.save_dir, domain=domain, port=port,
            probe=cfg.get("probe_method", ""))
        print(f"\n[保存] 前 {len(to_save)} 条 ->")
        print(f"        {txt_path}   (含 Region/延迟/速度 表格 + 纯 IP:port 列表)")
        if csv_path:
            print(f"        {csv_path}")
        if json_path:
            print(f"        {json_path}")

        # 按地区做个小结，便于挑节点
        region_count = {}
        for r in rows:
            region_count[r["region"]] = region_count.get(r["region"], 0) + 1
        if region_count:
            summary = "  ".join(f"{k}×{v}" for k, v in
                                sorted(region_count.items(), key=lambda kv: -kv[1]))
            print(f"\n[地区分布] {summary}")

        print(f"\n[推荐] 直接复制以下 IP(:{port}) 到 v2ray 节点 address 一栏(按延迟升序):")
        for r in to_save:
            spd = f"{r['speed_mbps']:.2f} MB/s" if r.get("speed_mbps") else "未测速"
            print("        " + f"{r['ip']}:{r['port']}".ljust(24)
                  + f" {r['region']:<6} {r['delay_ms']:>7} ms  {spd}")
    else:
        print("\n[提示] 未筛出任何可用 IP。请参照上文『失败原因』以及 README 排查章节调整：")
        print("        1) 确认你输入的域名真实解析到了 Cloudflare 且 v2ray 用的是该域名")
        print("        2) 若失败原因提到证书校验失败, 可尝试 --no-verify 仅看握手, "
              "并检查本地 CA/时间")
        print("        3) Cloudflare 动态风控与区域差异很大; 可换时间段/换运营商再跑")
    print()


def _pause_if_needed():
    """双击 exe 运行结束时暂停，避免窗口一闪而过看不到结果。

    仅在这种情况暂停：打包成 exe 且当前是交互式控制台, 且没有通过管道重定向。
    """
    try:
        if not is_frozen():
            return
        if not sys.stdin or not sys.stdin.isatty():
            return
        if os.environ.get("CFST_NO_PAUSE"):
            return
        input("\n按回车键退出...")
    except Exception:
        pass


def run():
    """统一入口：捕获异常并给出友好提示(exe 场景下尤其重要)。"""
    try:
        main()
    except KeyboardInterrupt:
        print("\n[中断] 用户已取消。")
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n[错误] 程序异常: {type(e).__name__}: {e}")
    finally:
        _pause_if_needed()


if __name__ == "__main__":
    run()

