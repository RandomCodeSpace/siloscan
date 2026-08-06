# frozen_string_literal: true

module Billing
  class Client
    GITLAB_TOKEN = "{{GLPAT_0_190}}"
    NPM_TOKEN = "{{NPMTOKEN_0_191}}"
    SERVICE_PASSWORD = "{{PWA_20_192}}"
    SERVICE_TOKEN = "{{B64_40_193}}"
    SESSION_SECRET = "{{HEX_40_194}}"
    AUTHORIZATION = "Bearer {{B64URL_43_195}}"
    BASIC_AUTHORIZATION = "Basic {{B64_44_196}}"
    ADMIN_PASSWORD = "{{PWP_24_197}}"
    DATABASE_URL = "mysql://billing:{{PWA_24_198}}@mysql.internal:3306/billing"

    TOKEN_FROM_ENV = ENV.fetch("GITLAB_TOKEN", nil)
    PASSWORD_PLACEHOLDER = "your_password"
    AUTHORIZATION_HEADER = "Authorization"
    TOKEN_TEMPLATE = "Bearer #{access_token}"
    SCHEMA_VERSION = "20240815120000"
    ERROR_MESSAGE = "the credential supplied for this account was not accepted"
  end
end
