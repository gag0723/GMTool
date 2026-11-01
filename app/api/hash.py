from flask import Blueprint, request

from ..core import hashing
from ..core.common import ToolError, format_bytes, ok, parse_bytes

bp = Blueprint("hash", __name__, url_prefix="/api/hash")


def _payload():
    return request.get_json(silent=True) or {}


@bp.post("/digest")
def digest():
    p = _payload()
    algo = p.get("type") or "SM3"
    data = parse_bytes(p.get("message"), p.get("messageFormat"))
    if len(data) > 5000:
        raise ToolError("消息长度不能大于 5000 字节")
    salt = parse_bytes(p.get("slot") or p.get("salt") or "", p.get("slotFormat") or "HEX")
    out = hashing.digest(algo, data, salt, p.get("slotSite") or "PRE", p.get("times") or 1)
    return ok(format_bytes(out, p.get("resultFormat") or "HEX"))


@bp.post("/digest/all")
def digest_all():
    p = _payload()
    data = parse_bytes(p.get("message"), p.get("messageFormat"))
    if len(data) > 5000:
        raise ToolError("消息长度不能大于 5000 字节")
    salt = parse_bytes(p.get("slot") or p.get("salt") or "", p.get("slotFormat") or "HEX")
    rows = hashing.digest_all(data, salt, p.get("slotSite") or "PRE", p.get("times") or 1)
    origin = (p.get("originDigest") or "").strip().lower()
    if origin:
        matched, others = [], []
        for r in rows:
            (matched if r["value"].lower() == origin else others).append({**r, "match": r["value"].lower() == origin})
        rows = matched + others
    return ok({"rows": rows, "length": len(data)})


@bp.post("/hmac")
def hmac_digest():
    p = _payload()
    algo = p.get("type") or "SM3"
    data = parse_bytes(p.get("message"), p.get("messageFormat"))
    key = parse_bytes(p.get("key"), p.get("keyFormat") or "HEX")
    out = hashing.hmac_digest(algo, data, key)
    return ok(format_bytes(out, p.get("resultFormat") or "HEX"))
