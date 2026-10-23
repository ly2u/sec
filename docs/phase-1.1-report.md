# 阶段 1.1 执行报告

## 已完成

- `migrations/versions/0002_baseline_cvss_kev.py`：新增事件 `is_baseline`、采集流永久完成标记 `has_completed`、CVSS 来源字段与 JSONB 全量评分；保留现有数据，把已有样本事件标为基线。
- `collector/ingestion.py`：事件基线标记随事务传递，首次导入跨中断/重启保持基线；后续导入也保留“曾完整完成”的历史。KEV/EPSS 上游 revision 改变时警告并自动从零重启；固定 CVE 基线仍保留显式 restart 约束。
- `collector/adapters/cvelist.py`、`collector/cvss.py`：delta 的错误条目保存在 `cursor.warnings`，剩余记录继续处理；评分按 CNA 3.1 > CISA-ADP 3.1 > CNA 4.0 > CISA-ADP 4.0 > 3.0 > 2.0 选择。保存全部评分、版本、向量和来源，严重度从主评分数值推导。基线批量查询/写入避免逐条数据库往返。
- `collector/store.py`：首页/RSS 查询作用域 `visible_events()` 和后续 Telegram 作用域 `telegram_events()` 均只读非基线事件。实际页面与发送器尚属于阶段 4，未提前实现。
- `kev_entries` 增加 `is_active`、`removed_at`；完整目录中消失的条目保留历史并生成 P2 `removed_from_kev`。官方成员资格使用 JOIN `kev_entries`，原 `cisa_kev` 重命名为参考事实 `adp_kev_flag`，不用于成员资格判断。
- `deploy/compose.yaml`：新增内部 db 网络；postgres 只连 db，worker/web 连 db 与 private；`shared_buffers=1GB`。开发容器已应用配置；未接入线上网络或反向代理。
- 更新架构 D4、安装说明、实库 schema 和全量 [capacity.md](capacity.md)。迁移前已备份开发数据库，备份与监控原始数据在本地忽略目录中。

## 实际验证

46 项测试在 SQLite 和 PostgreSQL 17 两种后端均通过；Ruff 检查、格式检查、Compose 校验及 Alembic 实库漂移检查通过。

| 修正 | 对应测试及结果 |
| --- | --- |
| 基线抑制 | `test_first_full_kev_is_baseline_then_only_new_entry_is_live`：首次完整导入后非基线为 0，第二轮多一条后恰为 1；另测永久完成历史和事件事务上下文 |
| 自动重启 | KEV、EPSS 各自模拟未完成时上游换版本，下一次自动完成且写出日志；固定 CVE 更换版本仍要求显式 restart |
| delta 源端错误 | `test_delta_errors_are_warned_and_persisted_while_valid_records_import`：有效记录成功入库，警告日志及完整错误条目持久化 |
| CVSS | 6 组优先级组合，验证版本/来源/向量、全部评分保存与严重度数值推导；迁移检查确认 JSONB |
| KEV 唯一依据及撤回 | ADP 标记不能冒充目录成员；部分目录不撤回，完整目录撤回保留历史、只生成一个 P2 事件，重放幂等 |
| 内部数据库网络 | `test_compose_resources_and_network_isolation` 校验内部 db、每服务网络、1GB shared_buffers、端口及资源上限；同时用 docker inspect 和 SHOW 实测 |
| 迁移 | 0001 数据升级至 0002 的回填，upgrade/downgrade/upgrade 和模型漂移检查 |

实际命令（工作目录 `/opt/secwatch-dev`）：

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/pytest -q

docker compose --env-file .env -f deploy/compose.yaml config --quiet
docker compose --env-file .env -f deploy/compose.yaml exec -T worker alembic upgrade head
docker compose --env-file .env -f deploy/compose.yaml exec -T worker alembic check
docker compose --env-file .env -f deploy/compose.yaml exec -T -e SECWATCH_TEST_POSTGRES=1 worker pytest -q -p no:cacheprovider

docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli kev --all
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli epss --all
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli cve-baseline --restart --all
# 人为中断后，恢复固定快照：
docker compose --env-file .env -f deploy/compose.yaml stop worker
docker compose --env-file .env -f deploy/compose.yaml start worker
docker compose --env-file .env -f deploy/compose.yaml exec -T worker python -m collector.cli cve-baseline --all
```

测试使用独立 `secwatch_test`，不清空开发数据库。唯一测试警告为 Starlette TestClient 对 httpx 的弃用提示，不影响通过结果。

| 全量数据源 | 最终记录数 | 本轮命令耗时 |
| --- | ---: | ---: |
| KEV | 1,754 | 2.68 秒 |
| EPSS | 394,415 | 154.00 秒 |
| CVE 基线 | 413,350 | 445.52 秒（两段合计） |

KEV/EPSS 从旧样本的 1000 条断点继续，以上时间不包含此前样本导入。CVE 首次运行重放旧样本以回填新增字段，在 59,600 条的已提交断点停止 worker，恢复后处理到 EOF；URL、revision 始终一致，原进程预期退出 137，续传进程退出 0。库内另保留阶段 1 的较新增量 `CVE-2026-115638`，使用保存的原文回填新增 CVSS 字段，并补充对应回归测试；没有用较旧基线覆盖。CVE 总墙钟时间 453.52 秒。三源均 `completed=true`。

数据库实测 1,689,114,291 字节；raw_record 存储值合计 887,753,184 字节，逻辑 JSON 文本 1,638,189,643 字节。前 5 大表与索引、状态分布、测量口径见 [capacity.md](capacity.md)。事件共 1,755 条，其中基线 1,755、非基线 0。

约每 15 秒执行 `docker stats --no-stream` 并检查站点 HTTP，累计 43 个定时样本，并辅以手工点测，HTTP 异常 0 次。线上容器 ID、启动时间、重启次数和配置哈希前后一致，sites 正常返回 200，civilflow 公网返回预期认证 401，直接上游返回 200。

| 服务 | 内存上限 | CPU 上限 | 网络 |
| --- | ---: | ---: | --- |
| postgres | 4 GiB | 2.0 | db（internal） |
| worker | 2 GiB | 1.5 | db、private |
| web | 1 GiB | 1.0 | db、private |

实际生成的完整 DDL 在 [database-schema.sql](database-schema.sql)；仍为 7 张业务表及 alembic_version，没有提前加入阶段 2 表结构。

## 未完成或已知缺陷

本次六项修正和全量导入均完成。首页、RSS 页面及 Telegram 发送器属于阶段 4，本次只建立并测试其公共过滤查询；没有声称已上线这些功能。断点续传是记录级，恢复时需要重读压缩流前缀。delta 的源端错误保留为 warnings 供核查，不会伪造失败记录。

## 需要站长确认的事项

本阶段无新增确认事项；没有修改生产配置，没有执行全局清理或 prune。

## 下一步计划

已停在阶段 1.1，等待审查；未开始阶段 2。
