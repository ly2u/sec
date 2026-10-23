#!/bin/sh
# Daily PostgreSQL backup for production SecWatch. Installed as
# /usr/local/sbin/secwatch-backup and run by secwatch-backup.timer.
#
# Writes BACKUP_DIR/secwatch-YYYYmmddTHHMMSSZ.dump (+ .sha256) only after the
# dump is non-empty and readable by pg_restore; then keeps the newest KEEP
# successful backups. A failed run leaves every older backup in place.
set -eu

PROJECT_DIR=${PROJECT_DIR:-/opt/secwatch}
BACKUP_DIR=${BACKUP_DIR:-/opt/secwatch/backups}
KEEP=${KEEP:-7}
compose() { docker compose --env-file "$PROJECT_DIR/.env" -f "$PROJECT_DIR/deploy/compose.prod.yaml" "$@"; }

umask 077
mkdir -p "$BACKUP_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
final="$BACKUP_DIR/secwatch-$stamp.dump"
partial="$final.partial"
trap 'rm -f "$partial"' EXIT

compose exec -T postgres pg_dump -U secwatch -d secwatch -Fc >"$partial"
[ -s "$partial" ] || { echo "secwatch-backup: empty dump" >&2; exit 1; }
compose exec -T postgres pg_restore --list <"$partial" >/dev/null ||
  { echo "secwatch-backup: dump is not readable by pg_restore" >&2; exit 1; }
mv "$partial" "$final"
(cd "$BACKUP_DIR" && sha256sum "$(basename "$final")" >"$(basename "$final").sha256")

# Prune: newest KEEP verified dumps stay.
ls -1 "$BACKUP_DIR"/secwatch-*.dump | sort -r | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old" "$old.sha256"
done
echo "secwatch-backup: $final ($(du -h "$final" | cut -f1))"
