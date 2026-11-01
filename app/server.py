"""密码工具百宝箱 · 本地版 —— Flask 应用入口。

- 纯本地运行，无任何外部请求、无广告、无授权校验
- 前端静态资源位于 web/，各工具模块按需加载 web/modules/*.js
"""
from __future__ import annotations

import importlib
import os
import traceback

from flask import Flask, jsonify, request, send_from_directory

from .core.common import ToolError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(os.path.dirname(BASE_DIR), "web")

# 蓝图注册表：新增模块时在此追加
BLUEPRINTS = [
    "sym",
    "hash",
    "mac",
    "asym",
    "sm9",
    "cert",
    "proto",
    "sig",
    "ops",
    "other",
    "encoding",
    "randomness",
    "scoring",
]


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
    app.json.ensure_ascii = False

    for name in BLUEPRINTS:
        try:
            mod = importlib.import_module(f"app.api.{name}")
        except ModuleNotFoundError:
            continue
        bp = getattr(mod, "bp", None)
        if bp is not None:
            app.register_blueprint(bp)

    @app.errorhandler(ToolError)
    def _tool_error(err: ToolError):
        return jsonify({"code": 1, "msg": str(err)}), 200

    @app.errorhandler(404)
    def _not_found(err):
        if request.path.startswith("/api/"):
            return jsonify({"code": 1, "msg": "接口不存在"}), 200
        return send_from_directory(WEB_DIR, "index.html")

    @app.errorhandler(500)
    def _server_error(err):
        traceback.print_exc()
        return jsonify({"code": 1, "msg": "服务内部错误"}), 200

    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename: str):
        return send_from_directory(WEB_DIR, filename)

    @app.get("/api/health")
    def health():
        return jsonify({"code": 0, "msg": "ok", "data": {"name": "cipherbox", "version": "1.0.0"}})

    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("CIPHERBOX_PORT", "18080"))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
