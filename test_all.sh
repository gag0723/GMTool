#!/bin/sh
# pytest + jsdom E2E（E2E 需服务已在运行，可用 CB_BASE 指定地址）
set -e
cd "$(dirname "$0")"
echo "== 后端单元/接口测试 =="
.venv/bin/python -m pytest tests -q
echo "== 前端 E2E（jsdom）=="
cd tests
node e2e/all_modules.js
echo "== 自定义页面巡检：编码转换工具 =="
node e2e/encode_check.js
echo "== 自定义页面巡检：量化评估 =="
node e2e/scoring_check.js
echo "== 全站下拉巡检 =="
node e2e/options_check.js
echo "== 全站页面格式校验 =="
node e2e/format_check.js
echo "== 证书格式检查页面（自签证书） =="
node e2e/cert_format_check.js
