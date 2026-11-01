"""MAC 计算接口：POST /api/mac/calc

字段与原站 MacView 一致：
    cipherType / mode / message / messageFormat / key / keyFormat /
    spareKey / sparekeyFormat / paddingType / tlen / resultFormat
成功时 data 为按 resultFormat 格式化的 MAC 字符串（与原站一致）。
"""
from flask import Blueprint, request

from ..core import mac as mac_core
from ..core.common import ToolError, format_bytes, ok, parse_bytes

bp = Blueprint("mac", __name__, url_prefix="/api/mac")

MAX_MESSAGE = 100_000


def _payload() -> dict:
    return request.get_json(silent=True) or {}


@bp.post("/calc")
def calc():
    p = _payload()

    algo = mac_core.normalize_algo(p.get("cipherType") or p.get("type"))
    mode = mac_core.normalize_mode(p.get("mode"))

    data = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if len(data) > MAX_MESSAGE:
        raise ToolError(f"消息长度不能大于 {MAX_MESSAGE} 字节")

    key = parse_bytes(p.get("key"), p.get("keyFormat") or "HEX")
    spare_raw = p.get("spareKey")
    key2 = None
    if spare_raw is not None and str(spare_raw).strip() != "":
        key2 = parse_bytes(spare_raw, p.get("sparekeyFormat") or p.get("spareKeyFormat") or "HEX")

    info = mac_core.mac_calc(
        algo=algo,
        mode=mode,
        key=key,
        data=data,
        padding=p.get("paddingType") or "M2",
        key2=key2,
        tlen=p.get("tlen"),
    )
    fmt = (p.get("resultFormat") or "HEX").upper()
    out = format_bytes(info["mac"], fmt)
    if fmt == "HEX":
        out = out.upper()  # 与原站一致：HEX 输出大写
    return ok(out)


@bp.get("/algorithms")
def algorithms():
    """算法、模式、填充的可选值（供前端/联调参考）。"""
    return ok(
        {
            "algorithms": [
                {"value": k, "label": mac_core.ALGO_LABEL[k], "blockSize": v[0], "keySize": v[1]}
                for k, v in mac_core.ALGOS.items()
            ],
            "modes": [{"value": k, "label": mac_core.MODE_LABEL[k]} for k in mac_core.MODES],
            "paddings": list(mac_core.PADDINGS),
            "twoKeyModes": list(mac_core.TWO_KEY_MODES),
        }
    )
