#!/usr/bin/env bash
# Nightly logical backups. Cron: 0 3 * * * /opt/ops/backup.sh
set -euo pipefail

BACKUP_DIR=/var/backups/nightly
STAMP=$(date +%Y%m%d)

# TODO(ops): move these onto vault paths like the warehouse dump below.
pg_dump "postgres://backup:{{VOCABPW_5_417}}@pg-primary.internal:5432/billing" \
  | gzip > "$BACKUP_DIR/billing-$STAMP.sql.gz"

mysqldump --single-transaction \
  "mysql://backup:{{VOCABPW_10_418}}@mysql-replica.internal:3306/storefront_analytics" \
  | gzip > "$BACKUP_DIR/analytics-$STAMP.sql.gz"

mongodump --uri "mongodb://backup:{{PWA_20_419}}@mongo-0.internal:27017/events" \
  --archive="$BACKUP_DIR/events-$STAMP.archive"

redis-cli -u "redis://:{{PWP_12_420}}@redis.internal:6379/0" --rdb "$BACKUP_DIR/redis-$STAMP.rdb"

# Warehouse credentials come from vault at run time.
WAREHOUSE_URL="postgres://warehouse:$(vault kv get -field=password secret/ops/warehouse)@warehouse.internal:5432/dw"
pg_dump "$WAREHOUSE_URL" | gzip > "$BACKUP_DIR/warehouse-$STAMP.sql.gz"

# Deploy-time substitution; entrypoint.sh rewrites this before first run.
METRICS_URL="https://metrics:${METRICS_TOKEN}@metrics.internal/api/v1/write"
curl -fsS -o /dev/null "$METRICS_URL" || logger -t backup "metrics push failed"
