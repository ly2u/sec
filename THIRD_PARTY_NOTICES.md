# 数据来源及第三方声明

本项目代码使用 Apache-2.0；上游数据保留各自的条款和来源署名。LY2U SecWatch 只将公开漏洞事实转换为按发行版拆分的数据包，不主张上游记录的所有权。数据包保留公告编号和 HTTPS 来源链接。

- CVE Program / CVEProject cvelistV5：[使用条款](https://www.cve.org/Legal/TermsOfUse)，包括 CNA 和 CISA ADP 信息。测试夹具为公开记录的最小切片，并保留来源。
- CISA Known Exploited Vulnerabilities Catalog：[官方数据](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)，美国政府公开数据；不隐去原始来源及参考链接。
- FIRST EPSS / Empirical Security：[官方数据说明](https://www.first.org/epss/data.html)。保留 FIRST EPSS 署名、模型版本和评分日期；免费访问不等于本项目可重新许可上游数据。

## OSV 导出及发行版数据

- **OSV.dev 聚合导出**：[数据来源和导出说明](https://google.github.io/osv.dev/data/)。
- **Ubuntu Security data**：Canonical Ltd.；Ubuntu OSV 记录使用 [CC BY-SA 4.0](https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE)。
- **Alpine SecDB**：Alpine Linux；[CC BY-SA 4.0](https://secdb.alpinelinux.org/)。
- **Rocky Linux**：OSV 列出的 Rocky 来源/转换工具使用 BSD 许可证；Rocky Errata API 同时把底层公告材料标为 CC BY 4.0，见 [Rocky Linux Errata](https://errata.rockylinux.org/)。
- **AlmaLinux OSV database**：AlmaLinux OS Foundation；[MIT License](https://github.com/AlmaLinux/osv-database/blob/master/LICENSE)。
- **Debian Security Tracker / Debian Security Advisories**：Debian Security Team，[官方 Tracker](https://security-tracker.debian.org/tracker/)。OSV 把它列为转换数据，但来源页未列独立的数据许可证；公开生产发布前仍需确认适用的再分发声明。

生成的数据包只包含事实性编号、包坐标、版本范围事件、评分和来源链接。Ubuntu Pro、FIPS、Realtime 和 Livepatch 渠道保持可区分；标准 Ubuntu 数据包排除后三种专用渠道。
