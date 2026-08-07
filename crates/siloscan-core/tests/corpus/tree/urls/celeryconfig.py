"""Celery configuration for the reporting workers.

Broker credentials are inlined; see OPS-2214 for the migration to
environment-provided settings that never landed.
"""

import os

broker_url = "amqp://:{{VOCABPW_8_421}}@rabbit.internal:5672/reporting"
result_backend = "redis://:{{VOCABPW_11_422}}@redis.internal:6379/5"

# Dead-letter broker still uses a generated credential.
dead_letter_broker = "amqp://reporting-dlx:{{B64URL_43_423}}@rabbit-dlx.internal:5672/reporting"

# Local development fallback, overridden in every deployed environment.
if os.environ.get("REPORTING_ENV") == "dev":
    broker_url = "amqp://guest:guest@localhost:5672//"
    result_backend = "redis://localhost:6379/0"

# Overridable at deploy time: celeryconfig.py.tmpl renders this line.
flower_url = "https://flower:{{ flower_password }}@flower.internal:5555"
