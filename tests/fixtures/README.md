# 离线数据来源

采集日期：2026-10-23。保留原始字段值，只裁剪无关的大段内容；非完整上游快照。

- `CVE-2024-3094.json`：[CVEProject 原始记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/3xxx/CVE-2024-3094.json)，包含真实 CISA ADP SSVC；CNA 删除 affected 等无关字段，references 仅保留首项。
- `CVE-2023-5129.json`：[被拒绝的 CVE 原始记录](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2023/5xxx/CVE-2023-5129.json)，保留拒绝原因。
- `kev.json`：[CISA 官方目录](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)中 CVE-2021-44228 的原始条目；为切片将 count 改为 1。
- `epss.csv`：[FIRST 数据说明](https://www.first.org/epss/data.html)指向的日更 CSV 的原始前四行，保留模型版本、评分日期和两个分数。

测试中的 ZIP、gzip、delta 响应由这些夹具在内存中构造。故障、字段变化和 RESERVED 等变体属于明确构造的测试输入，不作为真实漏洞事实发布。
- `golang/GO-2023-2102.json`：按 [Go 漏洞库](https://pkg.go.dev/vuln/GO-2023-2102) 公开记录的 OSV 结构整理（stdlib 与 golang.org/x/net 的修复版本取自公开公告；`toolchain` 一项为构造的输入，用于验证会被跳过）。Go 漏洞库数据使用 CC-BY-4.0。
