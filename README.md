# LY2U SecWatch

> 面向 VPS 和自建服务器用户的漏洞情报站与只读安全自检工具。
> Vulnerability intelligence and a read-only self-check scanner for VPS and self-hosted servers.

**站点**：<https://sec.ly2u.com>（建设中）

> ⚠️ **项目状态：V0.1 即将发布**。扫描器发布版本出现在 [Releases](https://github.com/ly2u/sec/releases) 之前，请勿在生产环境使用。

## 使用扫描器

```sh
curl -fsSL https://sec.ly2u.com/install.sh | sh
sudo secwatch scan
```

安装脚本会先校验发布签名（minisign，或 OpenSSL 3）和 SHA-256，再把单个静态二进制复制到 `/usr/local/bin`，不做其他改动。扫描器只读、不上传数据。详细说明、手动校验方法和支持范围见 <https://sec.ly2u.com/scanner>。

## 它要解决什么问题

最近 nginx、PHP、Node.js、OpenSSL 等组件的高危漏洞越来越频繁，但对大多数站长来说，问题不在于"不知道有漏洞"，而在于：

- **我的机器到底受不受影响？** 发行版会把安全补丁回移植到旧版本，只看版本号会大量误报。
- **宝塔、1Panel、源码编译装的软件怎么查？** 这些安装不经过系统包管理器，通用扫描工具很容易漏掉。
- **升级了就安全了吗？** 内核没重启、服务没重启的话，补丁其实还没生效。
- **先修哪个？** 已被在野利用的漏洞，比 CVSS 分数高的漏洞更紧急。

## 设计原则

- **只读**：扫描器不修改系统，不执行修复命令，只告诉你该怎么做。
- **不上传**：所有比对在本机完成。服务器只提供签名的漏洞数据包，不接收你的软件清单。
- **数据包只含事实**：数据包里没有任何可执行内容，修复命令由扫描器本身生成。
- **不确定就说不确定**：证据不足时输出 `UNKNOWN`，不会把"没查到"说成"安全"。
- **开源可审计**：代码、规则、数据来源全部公开。

## 数据来源

[CVE Program](https://github.com/CVEProject/cvelistV5)（含 CISA Vulnrichment）· [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [OSV](https://osv.dev/)（含 GitHub Advisory、Debian、Ubuntu、Alpine、Rocky Linux、AlmaLinux 等）

各数据源的许可证与署名见 `THIRD_PARTY_NOTICES.md`（随首个版本提供）。

## 文档

- [阶段 1 开发启动与验证](docs/installation.md)
- [阶段 1 交付报告](docs/phase-1-report.md)
- [实际生成的 PostgreSQL 表结构](docs/database-schema.sql)
- [小样本容量记录](docs/capacity.md)
- [架构决策](docs/ARCHITECTURE.md)
- [生产部署执行清单](docs/DEPLOY.md)
- [实施计划](docs/CODEX_BRIEF.md)
- [产品需求（长期愿景）](docs/prd-v0.1.md)

## 安全问题

请勿在公开 Issue 中报告本项目自身的安全漏洞，详见 [SECURITY.md](SECURITY.md)。

## 许可证

[Apache-2.0](LICENSE)。第三方数据遵循各自的许可证。
