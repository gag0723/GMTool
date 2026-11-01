#!/bin/sh
set -e
cd /opt/cipherbox
echo "== 后端单元/接口测试 =="
.venv/bin/python -m pytest tests -q
echo "== 前端 E2E（jsdom）=="
cd tests
node e2e/all_modules.js
