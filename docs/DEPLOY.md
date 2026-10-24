# 生产部署执行清单（阶段 5）

本清单是阶段 5 的执行依据，已吸收站长对勘察计划（`docs/deploy-plan-private.md`，不入库）的修改意见。主机相关的具体信息（IP、现有站点）只写在私有计划里，不写在这里。

**规则**：每一大步完成后汇报再继续；标注「站长确认」的步骤必须等到确认后才能执行。任何一步结果和预期不符时立即停下，按该步的回滚方法处理，然后汇报。不得使用 `docker system prune` / `docker image prune -a`。

约定：

```sh
P="docker compose --env-file /opt/secwatch/.env -f /opt/secwatch/deploy/compose.prod.yaml"
D="docker compose --env-file /opt/secwatch-dev/.env -f /opt/secwatch-dev/deploy/compose.yaml"
```

## 0. 前提

- 仓库 main 分支 CI 通过；记录要部署的提交号。
- 发布签名密钥已由站长加入（`keys/release-signing.pub` 存在，仓库密钥 `RELEASE_MINISIGN_KEY` 已设置），且至少发布过一个版本（如 `v0.1.0`）。否则 `https://sec.ly2u.com/install.sh` 会下载失败。
- 磁盘余量 ≥ 20 GiB。

## 1. 准备生产目录（不影响任何现有服务）

```sh
git clone https://github.com/ly2u/sec.git /opt/secwatch
cd /opt/secwatch && git checkout <提交号>
umask 077
printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > /opt/secwatch/.env
# 可选：TELEGRAM_BOT_TOKEN=...、TELEGRAM_CHAT_ID=...（不设置则不广播）
chmod 600 /opt/secwatch/.env
```

**数据包签名私钥必须与开发环境相同**（扫描器内置的是它的公钥 D7B7CA69ADC798BC，换钥会让所有已分发的扫描器拒收数据）：

```sh
cp -a /opt/secwatch-dev/secrets /opt/secwatch/secrets
cmp /opt/secwatch-dev/secrets/bundle-signing.key /opt/secwatch/secrets/bundle-signing.key
stat -c '%a %U:%G %n' /opt/secwatch/secrets /opt/secwatch/secrets/*   # 汇报权限，不得输出内容
```

回滚：删除 `/opt/secwatch`（确认里面没有生产数据后）。

## 2. 构建镜像、创建网络

```sh
cd /opt/secwatch && $P build
docker image ls secwatch          # 只应有 secwatch:current
docker network create --internal secwatch-edge
```

`--internal`：Caddy 能连到 web，web 自己不能出网（它不需要）。

回滚：`docker network rm secwatch-edge`（此时没有任何容器使用它）；`docker image rm secwatch:current`。

## 3. 迁移数据并启动

从开发库导出、导入生产库，不在生产重跑全量导入：

```sh
install -d -m 700 /opt/secwatch/backups
$D exec -T postgres pg_dump -U secwatch -d secwatch -Fc > /opt/secwatch/backups/initial-from-dev.dump
$D exec -T postgres pg_restore --list < /opt/secwatch/backups/initial-from-dev.dump > /dev/null && echo dump-ok
$P up -d --wait postgres          # 等健康检查通过；首次启动要先初始化数据库，需要几秒到几十秒
$P exec -T postgres pg_restore -U secwatch -d secwatch --no-owner --no-acl --exit-on-error \
  < /opt/secwatch/backups/initial-from-dev.dump
$P run --rm worker alembic upgrade head
$P up -d --wait worker web
$P exec -T worker python -m collector.cli bundles
$P exec -T web python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health').read())"
```

验证并汇报：

- 生产与开发库关键表行数一致（vulnerabilities、affected_packages、upstream_advisories、kev_entries）。
- `$P ps` 三个容器 healthy / running；`docker stats --no-stream` 内存占用。
- web 容器无法出网：`$P exec -T web python -c "import urllib.request; urllib.request.urlopen('https://github.com', timeout=5)"` 应报错。
- worker 日志里下一轮定时任务正常完成。

回滚：`$P down`（不加 `-v`，保留数据卷）。

## 4. Origin 证书（站长操作）

1. Cloudflare → SSL/TLS → Origin Server → Create Certificate，主机名只填 `sec.ly2u.com`，有效期 15 年。
2. 站长自己登录服务器保存（私钥不要经过任何 AI 工具）：

```sh
install -d -m 700 /opt/ly-stack/secrets/sec-origin
nano /opt/ly-stack/secrets/sec-origin/cert.pem   # 粘贴证书
nano /opt/ly-stack/secrets/sec-origin/key.pem    # 粘贴私钥
chmod 644 /opt/ly-stack/secrets/sec-origin/cert.pem
chmod 600 /opt/ly-stack/secrets/sec-origin/key.pem
```

## 5. 接入 Caddy（站长确认；挑访问量低的时段）

分两步，每步单独回归，降低风险。

**5a. Caddy 加入 edge 网络并挂载证书目录（需要重建 Caddy 容器，现有站点中断几秒）**

```sh
cd /opt/ly-stack
cp -a compose.yaml compose.yaml.bak-$(date -u +%Y%m%dT%H%M%SZ)
cp -a Caddyfile Caddyfile.bak-$(date -u +%Y%m%dT%H%M%SZ)
```

在 `compose.yaml` 的 caddy 服务中：

- `networks` 增加 `secwatch-edge`（保留原有网络），并在文件末尾 `networks:` 中声明 `secwatch-edge: {external: true}`；
- `volumes` 增加 `- /opt/ly-stack/secrets/sec-origin:/etc/caddy/certs:ro`（挂整个目录，以后换证书不受文件 inode 影响）。

```sh
docker compose -f /opt/ly-stack/compose.yaml config -q && echo compose-ok
docker compose -f /opt/ly-stack/compose.yaml up -d caddy
```

立刻回归现有每个站点（HTTPS 200/重定向与之前一致、证书仍是 Let's Encrypt）。

回滚：恢复 `compose.yaml.bak-*`，再 `docker compose -f /opt/ly-stack/compose.yaml up -d caddy`。

**5b. 新增站点**

Caddyfile 是单文件挂载：**只能原地追加**（`cat >>`），不要用 `sed -i` 或会替换文件的编辑器，否则容器看不到新内容。

```sh
cat >> /opt/ly-stack/Caddyfile <<'CADDY'

sec.ly2u.com {
	tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem
	encode zstd gzip
	reverse_proxy secwatch-web:8000
}
CADDY
docker exec ly-stack-caddy-1 caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec ly-stack-caddy-1 caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```

验证并汇报：

- `curl --noproxy '*' -sk --resolve sec.ly2u.com:443:127.0.0.1 https://sec.ly2u.com/api/v1/health` → `{"status":"ok"}`
- `openssl s_client` 三种情况复测：无 SNI、伪造 SNI 仍拿不到证书；SNI 为 `sec.ly2u.com` 时是 Cloudflare Origin 证书。
- 现有站点再回归一次。

回滚：恢复 `Caddyfile.bak-*`（用 `cat 备份 > Caddyfile` 原地写回），再 validate + reload。

**不做**：80 端口兜底规则、防火墙改动（站长决定）。

## 6. Cloudflare（站长操作）

1. DNS：`sec.ly2u.com` 保持代理（橙色云朵）。
2. **只对这个主机名**设 Full (strict)：Rules → Configuration Rules → 主机名等于 `sec.ly2u.com` → SSL 设为 Full (strict)。不要改整个域名的 SSL 模式。
3. 缓存：Rules → Cache Rules → 主机名等于 `sec.ly2u.com` → Eligible for cache，Edge TTL 选「Use cache-control header if present, bypass cache if not」，Browser TTL 选「Respect origin」。
4. 限速（免费版一条规则）：路径以 `/api/` 开头或等于 `/go` → 每 IP 每 10 秒 60 次 → 阻止 10 秒。
5. 验证：`curl -sI https://sec.ly2u.com/` 两次，第二次 `cf-cache-status: HIT`；`/bundles/manifest.json` 的 `cache-control` 是 `max-age=60`。

回滚：删除上述规则；SSL 规则删除后恢复为域名默认模式。

## 7. 端到端验收

```sh
curl -fsSL https://sec.ly2u.com/install.sh | sh
sudo secwatch scan            # 应在线获取数据包，签名 D7B7CA69ADC798BC 校验通过
```

再用手机打开首页、任意 CVE 页、产品页，确认显示正常。

## 8. 每日备份（站长确认）

```sh
install -m 755 /opt/secwatch/deploy/backup.sh /usr/local/sbin/secwatch-backup
install -m 644 /opt/secwatch/deploy/systemd/secwatch-backup.service /etc/systemd/system/
install -m 644 /opt/secwatch/deploy/systemd/secwatch-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl start secwatch-backup.service && journalctl -u secwatch-backup.service -n 20 --no-pager
systemctl enable --now secwatch-backup.timer
```

**恢复演练**（恢复到临时库，不碰正式库）：

```sh
f=$(ls -1 /opt/secwatch/backups/secwatch-*.dump | tail -1)
$P exec -T postgres createdb -U secwatch secwatch_restore_test
$P exec -T postgres pg_restore -U secwatch -d secwatch_restore_test --no-owner --no-acl --exit-on-error < "$f"
$P exec -T postgres psql -U secwatch -d secwatch_restore_test -c "select count(*) from vulnerabilities"
$P exec -T postgres dropdb -U secwatch secwatch_restore_test
```

汇报耗时和行数。回滚：`systemctl disable --now secwatch-backup.timer`，删除三个安装的文件。

## 9. 停掉开发环境（站长确认，生产验收通过后）

```sh
$D stop           # 只停止，不删除容器、数据卷和镜像
```

回滚：`$D start`。

## 日常更新

```sh
cd /opt/secwatch && git pull --ff-only
docker tag secwatch:current secwatch:previous
$P build && $P run --rm worker alembic upgrade head && $P up -d worker web
```

出问题时：`docker tag secwatch:previous secwatch:current && $P up -d worker web`。
