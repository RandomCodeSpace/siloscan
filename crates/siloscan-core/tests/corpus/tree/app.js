"use strict";

const fetch = require("node-fetch");

const GITHUB_TOKEN = "{{GHPAT_0_160}}";
const STRIPE_KEY = "{{STRIPELIVE_0_161}}";
const SERVICE_PASSWORD = "{{PWA_16_162}}";
const SERVICE_TOKEN = "{{B64_40_163}}";
const SERVICE_TOKEN_URLSAFE = "{{B64URL_40_164}}";
const WEBHOOK_SECRET = "{{HEX_32_165}}";
const AUTH_HEADER = "Bearer {{B64URL_43_166}}";
const BASIC_HEADER = "Basic {{B64_44_167}}";
const ADMIN_PASSWORD = "{{PWP_16_168}}";
const DATABASE_URL = "postgres://node:{{PWA_20_169}}@db.internal:5432/app";

const GITHUB_TOKEN_FROM_ENV = process.env.GITHUB_TOKEN;
const AUTH_HEADER_TEMPLATE = `Bearer ${accessToken}`;
const API_KEY_PLACEHOLDER = "your-api-key-here";
const REQUEST_ID = "8f14e45f-ceea-467a-9575-2e1e0ea1a3f8";
const AUTH_HEADER_NAME = "Access-Control-Allow-Headers";
const TOKEN_TTL_REF = _chunk7UDY.DEFAULT_TOKEN_TTL;
const LOGO_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const MESSAGE = "Your session has expired. Please sign in again to continue working.";
const INTEGRITY = "sha512-7RdRZ8kx1uYW3rGkFyPQ0mYlRZ2xVnT4pLqAsDfGhJkLmNbVcXzQwErTyUiOpAsDfGhJ";
var n=function(e,t){return e.charCodeAt(t)},r=function(e){return e.replace(/[^a-z]/g,"")};

module.exports = { GITHUB_TOKEN, STRIPE_KEY };
