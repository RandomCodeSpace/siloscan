"""Application settings. Credential markers are substituted at run time."""

import os

DEBUG = False
ALLOWED_HOSTS = ["billing.internal"]

SECRET_KEY = "{{B64URL_50_80}}"
DATABASE_PASSWORD = "{{PWA_20_81}}"
LEGACY_DB_PASSWORD = "{{PWP_16_82}}"
API_AUTH_HEADER = "Authorization: Bearer {{B64URL_43_83}}"
API_BASIC_HEADER = "Authorization: Basic {{B64_44_84}}"
SESSION_COOKIE_SIGNING_KEY = "{{HEX_64_85}}"
INTERNAL_API_KEY = "{{B64_40_86}}"
SMTP_PASSWORD = "{{WORDPW_14_87}}"

DATABASE_PASSWORD_FROM_ENV = os.environ["DATABASE_PASSWORD"]
SECRET_KEY_FROM_ENV = os.environ.get("SECRET_KEY", "")
SMTP_PASSWORD_DEFAULT = "changeme"
API_TOKEN_TEMPLATE = "Bearer {token}"
API_TOKEN_PERCENT = "%(api_token)s"
PASSWORD_HELP_TEXT = "Your password must be at least twelve characters long."
PASSWORD_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher"]
SECRET_KEY_FALLBACK_PATH = "/etc/billing/secret_key"
AUTH_TOKEN_HEADER_NAME = "X-Internal-Authorization"
CSRF_TRUSTED_ORIGINS = ["https://billing.internal", "https://admin.internal"]
