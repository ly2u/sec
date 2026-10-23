# LY2U SecWatch 架构决策（V0.1）

> 本文件是 V0.1 的**最终架构依据**。`docs/prd-v0.1.md`（原 PRD）作为长期愿景参考；两者冲突时以本文件为准。
> 版本：2026-10-23 · 状态：已定稿，实施中如发现与上游事实不符，先在 Issue 中记录再修改本文件。

---

## 0. 定位与差异化

**不重复造轮子**：漏洞"匹配"本身（尤其发行版回移植）已有成熟数据与工具（OSV、发行版安全追踪、Trivy）。如果我们只是又一个匹配引擎，没有存在价值。

**我们的价值在这四件事上**：

1. **看得见"非包管理"安装**：宝塔 / 1Panel / 源码编译 / 官方二进制 / nvm 安装的 nginx、PHP、Node.js、MySQL。这正是中文 VPS 用户最常见、也是 Trivy 这类通用工具最容易漏掉的地方。
2. **区分"已安装补丁"和"补丁已生效"**：内核未重启、服务进程仍在使用已被替换的旧库。很多人升级完以为安全了，其实没有。
3. **按真实风险排序**：KEV（已在野利用）+ EPSS（利用概率）+ 是否对公网监听，而不是只看 CVSS。
4. **中文、可执行、可验证的修复建议**：修什么、怎么修、修完怎么确认、会不会导致停机。

---

## D1. 情报源：V0.1 只接 4 个

| 来源 | 用途 | 说明 |
|---|---|---|
| **CVEProject/cvelistV5** | 全历史 CVE 索引、站点详情页 | 记录中的 CISA ADP 容器（Vulnrichment）提供 CVSS 3.1、CWE、SSVC、KEV 标记，可覆盖大部分原本要找 NVD 的需求 |
| **CISA KEV** | 已在野利用 | 最高优先级信号；"旧 CVE 新进 KEV"必须生成事件 |
| **EPSS** | 未来 30 天被利用概率 | 每日全量，用于排序。**原 PRD 遗漏了它，必须补上**。下载地址实施时以 FIRST 官方文档为准，不要写死 |
| **OSV 批量导出** | 发行版包状态 + 语言生态 | 覆盖 Debian、Ubuntu、Alpine、Rocky、AlmaLinux，以及 npm/PyPI/Packagist/Go/Maven 等（**已包含 GHSA**） |

**V0.1 明确不接**：

- **NVD API**：限速严格，且 NIST 已缩减补充分析范围；cvelistV5 里的 CISA ADP 数据已覆盖主要字段。V0.2 再作为补充源。
- **GHSA API**：OSV 已包含 GitHub Advisory 数据，重复接入只会带来去重工作。
- **Debian / Ubuntu 直连**：OSV 已转换并发布。只有发现 OSV 存在具体缺口时才写直连适配器。
- **RHEL 本体**：OSV 不含 Red Hat。Rocky / AlmaLinux 已在 OSV 中，覆盖了大部分 RHEL 系 VPS 用户。RHEL 留到 V0.2，接 Red Hat CSAF。

**OSV 使用注意**：

- 按发行版版本前缀的导出（如 `Alpine:v3.17`）**已停止**。应下载基础生态包（如 `Debian/all.zip`），再按 `affected[].package.ecosystem`（如 `Debian:12`）过滤。
- 增量更新使用 `modified_id.csv`。该文件按时间倒序排列，读到已处理过的时间戳即可停止。
- 各数据源许可证不同（例如 Ubuntu 为 CC-BY-SA 4.0，GHSA 为 CC-BY 4.0），需在 `THIRD_PARTY_NOTICES.md` 和站点页脚逐一署名。

---

## D2. 扫描器：数据包下发，本地匹配

**Go 单文件**，linux amd64/arm64，静态编译（`CGO_ENABLED=0`），零运行时依赖。不使用 Python，因为目标 VPS 的 Python 版本不可控。

```text
识别 OS/版本 → 读取已安装包 → 下载该发行版数据包 + 签名 → 校验 → 本地比对 → 输出报告
```

- **不上传任何东西**：兑现隐私承诺，同时满足"用我们自己的数据库"。服务器只知道"有人下载了 debian-12 数据包"。
- **版本比较必须使用发行版原生算法**：dpkg、rpm、apk 各有自己的比较规则（epoch、`~`、`+deb12u1`、`-r0` 等）。使用成熟库（如 Trivy 所用的 `knqyf263/go-deb-version`、`go-rpm-version`、`go-apk-version`），**禁止**自己写字符串或数字比较。
- **源码包 vs 二进制包（高发坑）**：发行版公告按**源码包**发布（如 `openssl`），系统里装的是**二进制包**（如 `libssl3`）。必须做映射：
  - Debian/Ubuntu：`dpkg-query -W -f='${binary:Package}\t${source:Package}\t${source:Version}\t${Version}\n'`
  - RPM：`rpm -qa --qf '%{NAME}\t%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n'`
  - Alpine：`/lib/apk/db/installed` 中的 `o:`（origin）字段
  - 注意 binNMU 等情况下源码版本与二进制版本可能不同，比较时用源码版本。

### 数据包只含事实，不含命令

数据包中**不得出现任何 shell 文本**。修复命令由扫描器二进制根据内置模板生成，例如 `apt-get install --only-upgrade <pkg>`，其中 `<pkg>` 必须通过包名白名单正则校验。

这样即使服务器或数据包被篡改，最坏后果是"结论错误"，而不是"在用户机器上执行了代码"。这是整个信任模型的地基。

### 两把签名密钥分离

| 密钥 | 用途 | 存放位置 |
|---|---|---|
| 数据包签名钥（ed25519 / minisign） | worker 每小时签发数据包 | 服务器 |
| 发布签名钥 | 签名扫描器二进制 Release | 仅 GitHub Actions secret 或离线保存，**永不上服务器** |

服务器被攻破时，攻击者只能伪造数据（由上一条兜底），无法伪造二进制。

### 数据包格式（schema v1）

```json
{
  "schema": 1,
  "distro": "debian",
  "release": "12",
  "generated_at": "2026-10-23T03:00:00Z",
  "sources": { "osv": "2026-10-23T02:41:00Z", "kev": "2026-10-22", "epss": "2026-10-22" },
  "source_packages": {
    "openssl": [
      {
        "id": "CVE-2026-XXXXX",
        "aliases": ["DSA-XXXX-1"],
        "status": "fixed",
        "fixed_version": "3.0.15-1~deb12u1",
        "severity": "HIGH",
        "cvss": 7.5,
        "kev": false,
        "epss": 0.0123,
        "ref": "https://security-tracker.debian.org/tracker/CVE-2026-XXXXX"
      }
    ]
  }
}
```

- `status` 取值：`fixed` | `unfixed`（发行版尚未修复）| `wont_fix`（如 Debian no-dsa / ignored）。
- 文件名带内容哈希：`bundles/debian-12.<sha256前12位>.json.zst` + `.minisig`。`manifest.json` 指向最新文件，并通过 Cloudflare 长期缓存。
- 同时发布到 GitHub Releases 作为镜像。

---

## D3. 四层检测（产品核心）

### L1 发行版包

使用 D2 的数据包，正确处理回移植，可以给出 `CONFIRMED_AFFECTED` / `FIXED` 结论。

`unfixed` / `wont_fix` 状态需要单独说明，例如："已知受影响，发行版暂未修复或不计划修复"，并给出缓解建议。不能简单输出"请升级"，因为根本没有可升级的版本。

### L2 非包管理安装（差异化重点）

规则文件位于 `rules/products/<product>.yaml`，每条规则包含：

- 探测路径
- 版本提取方式
- 上游受影响范围
- 来源链接
- 正例和反例测试用例

| 场景 | 典型路径 |
|---|---|
| 宝塔 | `/www/server/nginx/sbin/nginx`、`/www/server/php/*/bin/php`、`/www/server/mysql/bin/mysqld` |
| 源码编译 / 手动安装 | `/usr/local/nginx/sbin/nginx`、`/usr/local/bin/node`、`/usr/local/php*/bin/php` |
| Node 版本管理器 | `~/.nvm/versions/node/*/bin/node`（仅限 root 及 `/home/*`，可通过开关关闭） |
| 1Panel | `/opt/1panel` 及其应用容器（V0.1 只做识别，深度扫描放在 V0.2） |

**判定规则**：

- 这类安装没有回移植问题，上游版本范围直接适用。版本匹配时可判 `CONFIRMED_AFFECTED`。
- 前提是版本号读取可靠；读取失败时判 `UNKNOWN`。

**安全约束**：

- 只执行规则中写死的绝对路径和只读参数（`-v`、`-V`、`--version`）。
- 设置超时，不经过 shell。
- 提供 `--no-exec` 开关：开启后只读取包数据库和文件元数据，不执行任何二进制。

**V0.1 首批产品**（约 12 个，后续靠社区 PR 扩充）：nginx、Apache httpd、PHP、Node.js、OpenSSL、OpenSSH、MySQL、MariaDB、Redis、PostgreSQL、Docker Engine、sudo。

### L3 补丁是否生效

**内核**：

- 比较 `uname -r` 与已安装的最新内核包。
- Debian/Ubuntu 还要检查 `/var/run/reboot-required`。

**用户态进程**：

- 扫描 `/proc/*/maps` 中带 `(deleted)` 标记的 `.so` 库映射。出现这种情况，说明库文件已升级，但进程还在使用旧版本，原理同 `needrestart`。
- 输出示例："openssl 补丁已安装，但 nginx（pid 1234）仍在使用旧库，需要重启 nginx 才能生效。"

`FIXED` 结论必须标明属于哪一种：`已安装` 或 `已生效`。

### L4 暴露面（只影响排序，不改变判定状态）

- 读取 `/proc/net/tcp*`，建立"监听端口 → 进程 → 包"的映射。
- 在 `0.0.0.0` 或 `::` 上监听的受影响服务排在更前面。
- 不主动探测公网。

### Docker

V0.1 只做三件事：

1. 列出运行中的容器和镜像
2. 标注"容器内未扫描"
3. 推荐使用 `trivy image` 扫描

深度扫描放在 V0.2。

---

## D4. 优先级

| 级别 | 条件（阈值可配置） |
|---|---|
| **P0 立即处理** | 在 KEV 中；或 CVSS ≥ 9.0 且服务对公网监听 |
| **P1 尽快处理** | EPSS ≥ 0.1；或 CVSS ≥ 7.0 且服务对公网监听 |
| **P2 计划处理** | 其余 High/Critical |
| **P3 了解即可** | Medium/Low；默认折叠显示 |

CVSS 只是其中一个维度。不得根据评分推断"可远程提权"之类的结论。

---

## D5. 服务端：沿用 PRD 技术栈，砍掉 V0.1 不需要的部分

**技术栈**：FastAPI + PostgreSQL + Jinja2/HTMX + 独立 worker。

| 保留 | 推迟到 V0.2+ |
|---|---|
| cvelistV5 全历史导入（CVE 详情页是 SEO 长尾流量的主要来源） | NVD、GHSA API、RHEL CSAF |
| KEV、EPSS、OSV 增量采集 | 独立的 notifier 服务、用户订阅 |
| 事件表：新 KEV、修复版本发布、严重度变化 | 网站投稿表单、管理后台 |
| 首页、`/cve/{id}`、搜索、`/scanner`、RSS | 邮件、Webhook |
| 单个 Telegram 频道广播（P0/P1 事件，worker 内直接发送） | AI 生成中文摘要（见下） |
| 数据包生成、签名、manifest | |

**V0.1 服务**：`web`、`worker`、`postgres`。只有当 VPS 上没有现有反向代理时，才增加 `caddy`。

**数据规模**：cvelistV5 约 30 万条记录。数据库体积以实测为准，并记录在 `docs/capacity.md` 中。

**AI 中文摘要（V0.2 候选）**：只对 P0/P1 生成；只能基于来源原文；必须标注"AI 生成，以原文为准"；不得生成修复命令。在安全产品里，幻觉的代价很高。

---

## D6. 部署与 Cloudflare

1. **接入现有 Caddy（阶段 0 实测结论）**。本机 80/443 端口由 `ly-stack` 项目中的 Caddy 容器占用，Caddyfile 位于 `/opt/ly-stack/Caddyfile`。**不另起公网 Caddy。** 由于 Caddy 运行在容器里，它访问不到宿主机的 `127.0.0.1`，因此采用以下网络方案：
   - 新建一个独立的外部网络 `secwatch-edge`（`docker network create secwatch-edge`）。
   - SecWatch 这边**只有 `web` 容器**加入 `secwatch-edge`；`postgres` 和 `worker` 只在 SecWatch 的内部网络中。
   - 在 `ly-stack` 的 compose 文件中，给 caddy 服务追加 `secwatch-edge` 网络（声明为 `external: true`），然后在 Caddyfile 中新增 `sec.ly2u.com` 站点，反代到 `secwatch-web:8000`。
   - **不要**让 SecWatch 直接加入 `ly-stack_default` 网络。那样会让我们的容器和 ly-stack 的其他服务互通，而且两个项目的生命周期会耦合在一起。
   - 修改 ly-stack 的 compose 文件和 Caddyfile 属于生产变更，只在阶段 5 确认后执行。具体步骤：先运行 `caddy validate`，再执行 `caddy reload`（不中断服务）；如果出问题，用备份的 Caddyfile 回滚。
   - 开发阶段（阶段 1–4）完全不接触 Caddy。`web` 只绑定 `127.0.0.1:18080`，站长通过 SSH 隧道访问。
1a. **资源上限**。这台机器还在运行 ly-stack 的线上服务，所以 SecWatch 的每个容器都必须设置 `mem_limit` 和 `cpus`，防止全量导入时抢占资源。建议初始值：
   | 容器 | 内存 | CPU |
   |---|---|---|
   | postgres | 4 GB | 2 |
   | worker | 2 GB | 1.5 |
   | web | 1 GB | 1 |

   全量导入之后，根据实测数据再做调整。
2. **源站 IP 保护（分三层，成本由低到高）**。隐藏 IP 是主要防线，但 IP 可能通过以下途径泄露：全网 443 端口扫描时源站返回的证书、历史 DNS 记录、同一台机器上未开代理的其他子域名、服务器发出的邮件头。
   - **第一层，必做**：反代默认站点拒绝未知域名。nginx 使用 `listen 443 ssl default_server; ssl_reject_handshake on;`（需 nginx ≥ 1.19.4），80 端口默认站点 `return 444;`；Caddy 使用等效配置。目的是让扫描器按 IP 访问时拿不到任何证书，无法反查出域名。注意：这一层只能**防止 IP 被发现**，挡不住已经知道 IP 的攻击者，因为对方可以伪造 Host/SNI，而 SYN 洪泛等 L3/L4 攻击根本到不了 nginx。
   - **第二层，必做**：SSL 模式设为 Full (strict)，并使用 Cloudflare Origin Certificate；检查 `ly2u.com` 各子域名，凡指向本机且未开代理的记录都要处理掉。
   - **第三层，有条件时做**：源站防火墙的 80/443 端口只放行 Cloudflare IP 段。**前提是本机所有对外 443 站点都走 Cloudflare**，因为防火墙无法按域名区分流量。如果本机还有不走代理的站点，这一层就做不了，只能依靠前两层，并在汇报中注明。
   - **站长决定（2026-10-23）**：本机存在不走 Cloudflare 的服务，V0.1 **不实施第三层**，依靠第一、二层。若日后遭到针对源站的攻击，应急方案是更换 VPS IP，或把本站迁到单独 IP 并补上第三层。
3. **缓存策略（防止用户拿到旧数据）**：源站必须对每类路径显式输出 `Cache-Control`，Cloudflare 缓存规则设为"遵循源站"。不要依赖 Cloudflare 的默认行为：它会按扩展名自动缓存 `.zst`、`.gz`、`.zip` 等文件。

   | 路径 | 是否会变 | 源站 `Cache-Control` | 最大陈旧时间 |
   |---|---|---|---|
   | `/bundles/<发行版>.<哈希>.json.zst` 及签名 | 永不变（内容变化即换新文件名） | `public, max-age=31536000, immutable` | 0，不存在陈旧问题 |
   | `/bundles/manifest.json`（唯一可变的入口） | 每次发布都会变 | `public, max-age=60, must-revalidate`，并带 `ETag` | ≤ 60 秒 |
   | `/api/*` | 随数据变化 | `public, max-age=60`；`/api/v1/health` 用 `no-store` | ≤ 60 秒 |
   | `/cve/*` 等页面 | 偶尔变化 | `public, max-age=300` | ≤ 5 分钟 |
   | `/rss.xml` | 随事件变化 | `public, max-age=300` | ≤ 5 分钟 |

   - worker 发布新数据包时的顺序：**先上传新的哈希文件，再更新 manifest**。这样任何时刻 manifest 指向的文件都一定存在。旧哈希文件保留 7 天后再清理，避免正在下载的用户读取失败。
   - 扫描器请求 manifest 时带上 `If-None-Match`。数据没变时返回 304，几乎不消耗流量。
   - `/api/*` 另外配置 Cloudflare 限速规则。
   - 可选：发布后调用 Cloudflare API 清除 manifest 的缓存，把陈旧时间压到接近 0。这需要 API 令牌，V0.1 不做；60 秒的陈旧时间对每小时更新一次的数据来说可以忽略。
4. **数据库与 worker 不暴露任何端口**。

---

## D7. 开发与生产隔离（Codex 运行在生产 VPS 上）

- 开发目录：`/opt/secwatch-dev`
- Compose 项目名：`secwatch-dev`
- 端口只绑定 `127.0.0.1:18xxx`
- **不得**修改、停止或重建任何已有的容器、网络、数据卷、反代配置、防火墙规则
- 涉及以上任何一项的操作，先写出计划和回滚步骤，等待确认后再执行
- GitHub 推送使用**仅授权 `ly2u/sec` 一个仓库**的 fine-grained PAT 或 deploy key，不使用账户全权限 token
- 全量导入前先检查磁盘余量，并且必须先用 `--limit 1000` 跑通一遍

---

## V0.1 验收：可演示的端到端

1. **回移植测试**：在 Debian 12 和 Ubuntu 24.04 容器中运行 `secwatch scan`，输出中文报告。至少包含一个真实的回移植用例被正确判为 `FIXED`。用例从 Debian Security Tracker 中选取，并固化为测试夹具。
2. **宝塔场景**：在模拟的 `/www/server/nginx` 环境中，识别出非包管理安装的 nginx 及其版本。
3. **生效状态**：构造"库已升级、进程未重启"的场景，L3 能正确报出。
4. **站点**：`sec.ly2u.com` 首页显示最近 7 天的 KEV 新增和 P0/P1 事件；任意历史 CVE 都能打开详情页；RSS 可正常订阅。
5. **数据包**：每小时自动更新；签名可校验；篡改后扫描器拒绝使用。

## 分工

| 角色 | 负责 |
|---|---|
| **Claude** | 架构决策、数据包与判定规范、测试用例清单、关键代码审查 |
| **Codex（VPS）** | 实现、本机环境探测、运行测试、部署 |
| **站长（你）** | 建仓库、DNS 和 Cloudflare 设置、确认所有生产操作 |
