# LY2U SecWatch

> 面向 VPS 和自建服务器用户的漏洞情报站与只读安全自检工具。
> Vulnerability intelligence and a read-only self-check scanner for VPS and self-hosted servers.

**站点**：<https://sec.ly2u.com> · **下载**：[Releases](https://github.com/ly2u/sec/releases) · **许可证**：Apache-2.0

## 一条命令检查你的服务器

```sh
curl -fsSL https://sec.ly2u.com/install.sh | sh
sudo secwatch scan
```

安装脚本会先校验发布签名（minisign，或 OpenSSL 3）和 SHA-256，再把单个静态二进制放到 `/usr/local/bin`，不做其他改动。扫描只读、不上传任何数据。

报告是一张“体检清单”：一行结论，逐项说明问题和处理方式，最后是可以照着执行的命令。

```
LY2U SecWatch v0.1.5  my-vps · Debian 12 · 内核 6.1.0-54-amd64 · 只读检查

 ● 状态良好  没有需要立即处理的漏洞，有 2 项建议更新

   系统软件包  ✓ 730 个都是最新
   程序        ! 1 个建议更新，1 个在等作者发布新版
                 caddy          对外服务   14 个漏洞   升级即可，见第 1 步
                 komari-agent              98 个漏洞   等作者发布新版，不急
   容器        ! 1 个建议更新
                 my-api         Debian 13  8 个软件包  重建镜像，见第 3 步
   等待补丁    · glibc、内核各 1 项值得关注  Debian 还没发布修复，无需操作

 建议这样做
   1  sudo apt-get update && sudo apt-get install --only-upgrade caddy
   2  sudo systemctl restart caddy.service
   3  secwatch scan --container my-api
   4  secwatch scan
```

## 能查什么

- **系统软件包**：Debian 11–13、Ubuntu 20.04/22.04/24.04、Rocky Linux 8/9、AlmaLinux 8/9、Alpine 3.22–3.24。按发行版自己的安全数据判定，能识别“版本号没变但已打补丁”的回移植修复，不会误报。
- **不经过系统包管理器安装的软件**：宝塔、LNMP/OneinStack、源码编译、官方二进制、nvm 等装的 nginx、PHP、Node.js、OpenSSL、Redis、MySQL 等；以及来自第三方软件源（nginx.org、Docker、NodeSource、sury 等）的软件包。
- **Go 编译的程序**：Caddy、frp、Xray、Alist、Komari、docker compose / buildx 插件等。读取程序里记录的模块和 Go 版本，对照 Go 官方漏洞库，并给出下载地址、替换和重启的具体步骤。
- **运行中的 Docker 容器**：只读检查容器内的系统软件包（不调用 docker 命令），给出更新镜像的方法；只有一个 Go 程序的精简镜像也能检查。
- **补丁是否生效**：内核更新后没重启、服务还在用升级前的旧库。
- **先修哪个**：已被在野利用（CISA KEV）、被勒索软件利用、被利用概率（FIRST EPSS）、是否对外提供服务，综合成“立即 / 尽快 / 计划”。

不想记命令？直接运行 `sudo secwatch`，按数字选择即可。常用命令：

| 命令 | 作用 |
|---|---|
| `sudo secwatch` | 打开菜单：立即检查、查看详情、开启/修改/关闭定时检查与通知 |
| `sudo secwatch scan` | 体检清单（建议以 root 运行，才能检查容器和对外服务） |
| `secwatch scan --pkg caddy` | 只看一个软件包或程序：漏洞、所需版本和完整修复命令 |
| `secwatch scan --container NAME` | 只看一个容器 |
| `secwatch scan --all` | 完整报告：全部漏洞、验证命令、参考链接 |
| `secwatch scan --format json` | 给脚本和监控用 |
| `secwatch scan --fail-on P2` | 给自己的脚本用：达到该级别时退出码为 3 |
| `sudo secwatch schedule` | 定时检查，有新问题时通知你的 Telegram 或 Webhook（整数小时，最少 1；`--remove` 关闭） |

漏洞数据每次扫描都会自动获取最新版，不需要为了新漏洞更新程序。程序本身有新版本时，报告最后会提示一行；更新就是重新运行安装命令。程序只提示，从不自动更新自己。

## 设计原则

- **只读**：扫描器不修改系统，不执行修复命令，只告诉你该怎么做。
- **不上传**：所有比对在本机完成。服务器只提供签名的漏洞数据包，不接收你的软件清单。开启定时通知后，结论只发到你自己配置的 Telegram/Webhook。
- **数据包只含事实**：数据包里没有任何可执行内容，修复命令由扫描器按内置模板生成，名称要通过白名单校验。
- **不确定就说不确定**：证据不足时标为“可能受影响”或“未检查”，不会把“没查到”说成“安全”。
- **开源可审计**：代码、规则、数据来源全部公开；发布版本由 GitHub Actions 公开构建并签名，构建前用 govulncheck 检查自身依赖。

## 数据来源

[CVE Program](https://github.com/CVEProject/cvelistV5)（含 CISA Vulnrichment）· [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [OSV](https://osv.dev/)（Debian、Ubuntu、Alpine、Rocky Linux、AlmaLinux）· [Go 漏洞库](https://pkg.go.dev/vuln/) · [Node.js 安全工作组](https://github.com/nodejs/security-wg)

各数据源的许可证与署名见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 文档

- [扫描器说明](scanner/README.md)
- [架构决策](docs/ARCHITECTURE.md)
- [生产部署执行清单](docs/DEPLOY.md)
- [开发环境与验证](docs/installation.md)
- [实施计划](docs/CODEX_BRIEF.md) · [产品需求（长期愿景）](docs/prd-v0.1.md)

## 安全问题

请勿在公开 Issue 中报告本项目自身的安全漏洞，详见 [SECURITY.md](SECURITY.md)。

## 许可证

[Apache-2.0](LICENSE)。第三方数据遵循各自的许可证。
