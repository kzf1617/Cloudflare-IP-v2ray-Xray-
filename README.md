# Cloudflare-IP-v2ray-Xray-
Cloudflare 优选 IP 扫描器 (供 v2ray / Xray 使用)
一个**纯 Python 标准库**（零第三方依赖）实现的 Cloudflare 「自选优选 IP」工具，
但与普通的 SpeedTest 工具（例如 XIU2/CloudflareSpeedTest）最大的不同是：

> **它筛选的不是『哪个 IP 下载或 TCP 通得快』，而是『哪个 IP 能真正被你的域名以
> v2ray 的 TLS/WS 方式连接并正确回源』**，并输出**地区(机房)**与**速度**。

## 〇、直接用 exe（Windows 10 / 11，无需安装 Python）

仓库里已提供打好包的单文件程序：**`CF优选IP.exe`**（约 9 MB，免安装、免 Python 环境）。

**三步使用：**
1. 把 `CF优选IP.exe` 放到任意文件夹（例如 `D:\cfip`）；
2. **双击运行一次** → 会在同目录自动生成 `config.json`，程序会提示你怎么改；
3. 用记事本打开 `config.json`，把 `"domain"` 填成你 v2ray 实际使用、且已解析到 Cloudflare
   的域名（WS 协议再把 `"ws_path"` 改成你节点的路径），保存后**再次双击**即可。

结果自动输出到 **exe 同目录的 `out\`** 文件夹：`result.txt` / `result.csv` / `result.json`。

**命令行方式（同样无需 Python）：**
```bat
CF优选IP.exe -d sub.example.com -p 443 -P /ws
CF优选IP.exe -d sub.example.com -n 100            :: 只随机抽 100 个候选快速试
CF优选IP.exe -d sub.example.com --no-speed        :: 关闭测速，扫描最快
CF优选IP.exe -d sub.example.com --save-dir D:\cfip\out
CF优选IP.exe -h                                   :: 查看全部参数
```

> 程序运行结束时会停在「按回车键退出」，方便你看结果（批处理/脚本中可设环境变量
> `CFST_NO_PAUSE=1` 跳过）。配置文件与输出目录始终以 **exe 所在目录**为基准，
> 因此放到哪里都能正常读写。

### 自己重新打包 exe

需要 Python 3.8+（建议 3.9~3.12）与 PyInstaller：

```bat
build.bat            :: 一键打包，产物在 dist\CF优选IP.exe
```

或手动执行：
```bat
python -m pip install pyinstaller
python -m PyInstaller --onefile --console --name CF优选IP cloudflare_speedtest.py
```

---

## 一、先理解问题：为什么“优选的 IP 拿到 v2ray 里全是 -1 / 连不上”？

Cloudflare CDN 在全球有海量边缘 IP，理论上都共享同一套证书与回源网络。
但现实是：

1. **普通优选工具（CFST 等）测的是「这个 IP 能不能作为一个 CF 节点下载/响应」，**
   它用一个**和自己无关的下载地址**（例如 `speed.cloudflare.com`）做 HTTP 测速，能通不代表
   能把你 v2ray 节点连接时用到的那套链路走通。
2. **真正决定 v2ray 能不能用的是下面这条链：**
   ```
   你(v2ray客户端, 连【优选IP:端口】, SNI+Host=你的域名)
      → CF 边缘节点(根据 SNI / Host 决定路由到哪个网站/回源)
      → 回源到你的源站(Caddy/Nginx → v2ray 的入站)
   ```
   其中任意一段出问题（IP 被 CF 针对该域名屏蔽、证书不匹配、回源被封、区域被风控等），
   就表现为 v2ray 或机场工具内 **测速 -1 / 握手失败 / 无法连接**。
3. 尤其注意：Cloudflare 官方**明文禁止以「代理套 CDN」形式使用**，为此会动态地、按区域
   地对疑似翻墙流量做审查与阻断，这会造成**同一批 IP 在不同时段结果剧烈波动**。

因此「能测速的 IP」≠「能代理的 IP」。本程序用一个更贴合实际的方式去预筛。

## 二、本程序的筛选思路（四阶段判定）

| 阶段 | 做了什么 | 对应到 v2ray 的意义 |
| --- | --- | --- |
| ① TCP 连通 | 用你指定的端口（通常是 443）建立 TCP 连接 | 快速排除完全连不上的 IP |
| ② TLS 握手 | 使用你的**域名**作为 SNI 和目标 Host，建立 TLS，并校验返回证书是否匹配该域名 | 模拟 v2ray 客户端 `TLS + v2ray 域名` 连到该 IP 时会发生什么 |
| ③ WS/回源探测 | 在已建立的 TLS 上发一次针对你 **WS path** 的 HTTP 升级请求，看 CF 是否把请求正确回源（依据返回状态码 101/200/404 等） | 验证“CF → 你的源站”这一跳真实可用 |
| ④ 地区识别 | 从响应头 `cf-ray: xxx-<COLO>` 里取出三字码（如 `HKG`、`NRT`、`LAX`），即该 IP 实际接入的 CF 机房 | 让你一眼看出节点落地区域，便于选择离你近的 |
| ⑤ 延迟 + 速度 | 按握手/回源总耗时排序；再对最快的若干个做一次有上限的下载测速 | 兼顾“连得上”和“跑得快” |

> 也就是说，其余普通工具只做到「这 IP 通」；本程序尽量做到「这 IP 对**你的配置**通」，并附带**地区 + 速度**信息。

### 结果里的「地区」是怎么来的？

不需要任何第三方 GeoIP 库。Cloudflare 在每个边缘节点的响应里都会带上：

```
cf-ray: 8a1b2c3d4e5f6a7b-HKG      ← 末尾的 HKG 就是该连接落到的机房(香港)
```

程序直接解析这个后缀作为地区，**准确且零依赖**。若某个 IP 没有返回 `cf-ray`（例如请求被 CF 拦截/并非 CF 回源），地区显示 `N/A`。

常见三字码：`HKG` 香港、`NRT` 东京、`KIX` 大阪、`SIN` 新加坡、`ICN`/`GMP` 首尔、`LAX` 洛杉矶、`SJC` 圣何塞、`SEA` 西雅图、`FRA` 法兰克福、`LHR` 伦敦、`CDG` 巴黎 …（完整映射见代码中的 `COLO_MAP`）


## 三、用法（三选一）

### A. 用配置文件（推荐，所有参数集中管理）

编辑同目录下 `config.json`，把 `domain` 改成 v2ray 节点实际使用、且已解析到 Cloudflare 的
域名，`ws_path` 改成 v2ray 入站对应的路径（如果协议是 WS）。然后运行：

```
python cloudflare_speedtest.py
```

### B. 全部用命令行参数

```
python cloudflare_speedtest.py ^
    -d 你的域名.com ^
    -p 443 ^
    -P /ws ^
    --probe ws ^
    -t 128
```

### C. 用你自己的 IP/cidr 列表

```
python cloudflare_speedtest.py -d 你的域名.com -p 443 -P /ws -f my_ips.txt
# my_ips.txt 每行一个如:  104.16.0.0/13  或  104.16.0.1
```

### 常用参数速查

```
-d,  --domain      你 v2ray 实际使用并解析到 CF 的域名（必填）
-p,  --port        端口，默认读配置(443)
-P,  --ws-path     WS path，如 /ws
-t,  --threads     并发探测数(默认读配置 256)
-m,  --probe       tls(只握手校验证书) / ws(默认额外回源探测)
-n,  --num         最终只随机抽取 N 个候选来扫（调小可快速验证）
-N,  --net-samples 每个大段抽取的样本数上限(默认 300)
--max-download-mb  每个候选下载测速上限(MB)。-1=读配置, 0=关闭测速
--speed-top        只对最快的 N 个候选测速(默认读配置 10)
--no-speed         彻底关闭测速(速度列显示 -)，扫描最快
--no-verify        关闭证书域名校验(一般不建议)
--no-builtin       联网失败时禁止回退到内置段(无缓存则直接退出)
--save-dir         结果目录名(默认 out)
-c  --config       配置文件路径(默认 config.json)
```

> **IP 段获取顺序**：自定义文件(`-f`) → 在线多来源(`www.cloudflare.com/ips-v4` →
> `api.cloudflare.com/client/v4/ips` → `cloudflare.com/ips-v4`) → 本地缓存
> (`cf_ranges.cache`，程序目录，联网成功时自动写入) → 内置段 `BUILTIN_IPV4`。
> 也就是说，只要**成功联网过一次**，之后断网也能用最近一次的官方段；只有从未联网成功时
> 才会退回内置段（会提示内置段快照时间）。

> 看帮助：`python cloudflare_speedtest.py --help`

运行中会滚动打印**进度**、以及常见的失败分类与原因。结束后：
- 屏幕上打印一张含 `Region / Delay / Speed` 的表格、**地区分布**统计、以及可直接复制的 `IP:端口` 推荐列表；
- 结果写入 `out/`：
  - `result.txt` —— 上半部分是带 `IP / Region / 延迟 / 速度 / 备注` 的表格，下半部分是纯 `IP:端口` 列表；
  - `result.csv` —— 结构化表格（含 `region`、`colo`、`delay_ms`、`speed_mbps` 等列），方便用 Excel 排序筛选；
  - `result.json` —— 完整字段，便于脚本二次处理。

`result.txt` 示例：

```
# Cloudflare 优选IP (可替换 v2ray 节点的 address)
# 生成时间: 2026-09-18 09:27:46
# 目标域名: home.517190.xyz   端口: 443   探测模式: ws
# 共 12 条 (按延迟升序)
# Region = Cloudflare 机房三字码(如 HKG/NRT/LAX), 代表该 IP 实际接入的地区

#   IP                  Region  Delay(ms)  Speed(MB/s)  Note
------------------------------------------------------------------------------
1   104.16.x.x          HKG     45.2       12.31        origin path miss(链通)
2   172.64.x.x          NRT     78.9       8.02         origin path miss(链通)
------------------------------------------------------------------------------

# ===== 以下为可直接复制到 v2ray 的 IP:端口 =====
104.16.x.x:443
172.64.x.x:443
```

## 四、把这些 IP 使用到 v2ray

1. 拿到 `out/result.txt` 里的 `IP:端口` 列表；
2. 在 v2ray / Xray 的客户端（或面板）中，把你原来节点里的服务器地址 `/  address / IP`
   替换成这些优选 IP——**保留原域名作为 Host/SNI 字段不变**，端口仍填你节点的端口；
3. 逐台测试（不同 IP 可能因你本地运营商到达路径不同而在某一时刻不可用，多试几条）；
4. 建议多挑几个写入配置、并做故障自动切换，或定期（例如每天/每次线路异常时）重跑本工具更新。

### 一个典型 WS+TLS 节点的 v2ray 配置片段（示意）

```jsonc
{
  "outbounds": [{
    "protocol": "vmess",
    "settings": { "vnext": [{ "address": "104.16.x.x",       // ← 替换成这里筛出的优选 IP
                             "port": 443,
                             "users": [{ "id": "你的-uuid", "alterId": 0 }] }] },
    "streamSettings": {
      "network": "ws",
      "security": "tls",
      "wsSettings": { "path": "/ws" },                         // 与 config.json 的 ws_path 一致
      "tlsSettings": { "serverName": "你的域名.com",            // 保持你原域名
                       "allowInsecure": false }
    }
  }]
}
```

## 五、跑出来都是 -1 / 一个都不过？怎么排查

程序会列出最常见的失败原因计数，按下面几项逐一对照：

1. **确认域名真的解析到 Cloudflare** —— `nslookup 你的域名` 的 A 记录 IP 应属于 CF
   的公开段。如果你根本没用 CF（例如直连原版服务器），这个工具的前提不成立。
2. **端口/路径/协议要和 v2ray 节点一致** —— 用错端口或 path，即便 IP 通，回源探测也会失败。
3. **证书校验失败（cert verify fail）** —— 多数说明该 IP 返回的证书和你域名不匹配，即该
   边缘确实不服务你的域名；可换其它 IP。也可先 `--no-verify` 一看是否只是本地 CA 问题。
4. **握手超时 / TCP 不通** —— 这些就是那批“看着能测速但在你本地到不了 443”的 IP。
5. **这台机器本身出不了网 / 运营商封锁 443 到海外** …… 请先在浏览器访问一次你的域名确认可用。

> 终极友情提示：**Cloudflare 已明确禁止把 CDN 当作代理/中转使用**，其对代理流量的审查、
> 区域风控、节假日政策都可能让你的优选 IP 时好时坏。若追求稳定长线使用，应考虑合规的
> 服务器/协议而非依赖「协议套 CDN」。本项目仅为连接稳定性预筛工具。

## 六、环境与依赖

- Python 3.8+（本代码在 3.14 下验证）。
- **无第三方依赖**，标准库 only。
- IP 段获取会依次尝试多个官方来源，成功后会缓存到程序目录的 `cf_ranges.cache`；
  仅当在线与缓存都不可用时才回退到内置于代码的常用段（`BUILTIN_IPV4`，快照见
  `BUILTIN_IPV4_SNAPSHOT`）。也可用 `-f` 提供更权威的清单，或用 `--no-builtin` 禁用兜底。

## 许可

同样面向学习/自用目的的开源示例，请遵守 Cloudflare 服务条款与当地法律。
