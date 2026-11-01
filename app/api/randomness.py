"""随机数检测接口（NIST SP 800-22 常用子集）与随机数生成。

路由：

* ``POST /api/random/detect``       检测随机数序列，字段 ``data`` / ``dataFormat``（HEX / BASE64 / TEXT / BIN）
* ``GET  /api/random/generate``     ``?bits=256&format=HEX`` 生成随机数
* ``POST /api/random/generate``     同上（JSON 提交，便于前端统一调用）
* ``POST /api/random/tests``        返回已实现的检测项清单
* ``POST /api/random/detect/file``  上传文件内容的 Base64（与 detect 等价，字段名更直观）
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import randomness
from ..core.common import ToolError, as_int, ok

bp = Blueprint("randomness", __name__, url_prefix="/api/random")


def _p() -> dict:
    """合并 JSON body 与 query 参数，POST/GET 均可携带 bits、format。"""
    payload = dict(request.args.to_dict())
    body = request.get_json(silent=True)
    if isinstance(body, dict):
        payload.update(body)
    return payload


@bp.post("/detect")
def detect():
    p = _p()
    data = p.get("data") or p.get("message") or p.get("sequence") or ""
    fmt = p.get("dataFormat") or p.get("messageFormat") or p.get("format") or "HEX"
    alpha = p.get("alpha")
    if alpha in (None, ""):
        alpha = randomness.ALPHA
    else:
        try:
            alpha = float(alpha)
        except (TypeError, ValueError):
            raise ToolError("显著水平 alpha 必须为 0~1 之间的小数")
        if not 0 < alpha < 1:
            raise ToolError("显著水平 alpha 必须为 0~1 之间的小数")
    return ok(randomness.detect(data, fmt, alpha))


@bp.post("/detect/file")
def detect_file():
    p = _p()
    data = p.get("b64") or p.get("data") or ""
    return ok(randomness.detect(data, "BASE64", randomness.ALPHA))


@bp.get("/generate")
def generate_get():
    bits = request.args.get("bits") or request.args.get("length") or 256
    fmt = request.args.get("format") or "HEX"
    return ok(randomness.generate(as_int(bits, "随机数位数", 256), fmt))


@bp.post("/generate")
def generate_post():
    p = _p()
    bits = p.get("bits", p.get("length", 256))
    fmt = p.get("format") or p.get("resultFormat") or "HEX"
    return ok(randomness.generate(as_int(bits, "随机数位数", 256), fmt))


@bp.post("/tests")
def tests():
    return ok({
        "tests": randomness.TEST_META,
        "alpha": randomness.ALPHA,
        "minBits": randomness.MIN_BITS,
        "maxBits": randomness.MAX_BITS,
        "dftMaxBits": randomness.DFT_MAX_BITS,
        "standard": "NIST SP 800-22 Rev.1a（常用子集）",
    })
