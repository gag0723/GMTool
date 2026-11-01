"""其他常用工具接口：密文长度分析、大数运算、取模运算、逻辑运算、字节逆序。

字段名与原站保持一致（``s1``/``s1Format``/``s2``/``s2Format``/``p1``/``p1Format``/
``resultFormat``/``message``/``messageFormat``），同时兼容更易读的别名
（``a``/``aFormat``/``b``/``p``/``data``/``dataFormat``/``format``）。
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import other_ext
from ..core.common import ok

bp = Blueprint("other", __name__, url_prefix="/api/other")


def _p() -> dict:
    return request.get_json(silent=True) or {}


def _pick(payload: dict, *keys, default=""):
    for key in keys:
        if key in payload and payload[key] not in (None, ""):
            return payload[key]
    return default


def _payload_fields(p: dict) -> dict:
    return {
        "a": _pick(p, "s1", "a", "data", "left"),
        "a_fmt": _pick(p, "s1Format", "aFormat", "dataFormat", "format", default="HEX"),
        "b": _pick(p, "s2", "b", "right"),
        "b_fmt": _pick(p, "s2Format", "bFormat", default="HEX"),
        "p": _pick(p, "p1", "p", "modulus", "mod"),
        "p_fmt": _pick(p, "p1Format", "pFormat", default="HEX"),
        "out": _pick(p, "resultFormat", "outputFormat", default="HEX"),
        "type": _pick(p, "type", "op", default=""),
    }


# --------------------------- 密文长度分析 ---------------------------

@bp.post("/length/analyze")
def length_analyze():
    p = _p()
    data = _pick(p, "message", "s1", "data")
    fmt = _pick(p, "messageFormat", "s1Format", "dataFormat", default="HEX")
    return ok(other_ext.analyze_cipher_length(data, fmt))


@bp.post("/length/table")
def length_table():
    p = _p()
    kind = _pick(p, "type", "group", "kind", default="HASH")
    return ok(other_ext.length_table(kind))


# 与原站路径兼容：GET /api/other/query/cipher/length?type=1
@bp.get("/query/cipher/length")
def query_cipher_length_get():
    kind = request.args.get("type") or request.args.get("group") or "HASH"
    return ok(other_ext.length_table(kind))


@bp.post("/query/cipher/length")
def query_cipher_length():
    return length_table()


@bp.post("/query/cipher")
def query_cipher():
    return length_analyze()


# --------------------------- 大数运算 ---------------------------

@bp.post("/big/number")
def big_number():
    f = _payload_fields(_p())
    return ok(other_ext.big_number(f["type"], f["a"], f["a_fmt"], f["b"], f["b_fmt"], f["out"]))


@bp.post("/math")
def math_alias():
    return big_number()


# --------------------------- 取模运算 ---------------------------

@bp.post("/mod/number")
def mod_number():
    f = _payload_fields(_p())
    return ok(other_ext.mod_number(f["type"], f["a"], f["a_fmt"], f["b"], f["b_fmt"],
                                   f["p"], f["p_fmt"], f["out"]))


@bp.post("/mod")
def mod_alias():
    return mod_number()


# --------------------------- 逻辑运算 ---------------------------

@bp.post("/xor")
def logic():
    p = _p()
    f = _payload_fields(p)
    return ok(other_ext.logic_op(f["type"], f["a"], f["a_fmt"], f["b"], f["b_fmt"], f["out"]))


@bp.post("/logic")
def logic_alias():
    return logic()


# --------------------------- 字节逆序 ---------------------------

@bp.post("/byte/reverse")
def byte_reverse():
    p = _p()
    f = _payload_fields(p)
    mode = _pick(p, "mode", "group", "groupSize", default="all")
    if str(mode).upper() in ("ALL", "FULL", "整段", ""):
        mode = "all"
    return ok(other_ext.byte_reverse(f["a"], f["a_fmt"], mode, f["out"]))


@bp.post("/meta")
def meta():
    """把各工具的运算类型清单暴露给前端（便于按钮/选项动态生成）。"""
    return ok({
        "bigOps": list(other_ext.BIG_OPS),
        "modOps": list(other_ext.MOD_OPS),
        "logicOps": list(other_ext.LOGIC_OPS),
        "reverseModes": [k for k in other_ext.REVERSE_MODES],
        "formats": ["HEX", "BASE64"],
        "lengthGroups": [{"key": k, "title": v[0]} for k, v in other_ext.LENGTH_GROUPS.items()],
    })
