#!/bin/sh
# 密码工具百宝箱 · 本地版 启动脚本
cd "$(dirname "$0")" || exit 1
PORT="${CIPHERBOX_PORT:-18080}"
exec .venv/bin/python -m waitress --host=0.0.0.0 --port="$PORT" --threads=8 --call app.server:create_app
