# Reporting stack setup

Local quickstart for new engineers. Nothing below is a real credential; every
URL uses the documented example form.

## Prerequisites

Start the databases with the compose file in `deploy/`, then point the
services at them:

    export DATABASE_URL=postgres://reporting:password123@localhost:5432/reporting
    export DOCUMENTS_URL=mongodb://reporting:secret-42@localhost:27017/reports
    export QUEUE_URL=amqp://reporting:token_1@localhost:5672/reporting
    export CACHE_URL=redis://:key_1234@localhost:6379/4

The dotenv vault integration prints its own example URI on a missing key:

    dotenv://:key_1234@dotenv.org/vault/.env.vault?environment=production

## Production

Real values come from the credential store. The deploy templates render:

    DATABASE_URL=postgres://reporting:${REPORTING_DB_PASSWORD}@pg-primary.internal:5432/reporting
    CACHE_URL=redis://:your-password-here@redis.internal:6379/4

Replace the placeholder before first boot; the service refuses to start on the
literal value.
