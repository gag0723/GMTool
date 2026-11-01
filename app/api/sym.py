"""对称密码接口：分组密码 / 序列密码（ZUC）/ GCM 模式。

统一约定：POST JSON，成功返回 {"code":0,"data":...}，失败抛出 ToolError。
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import sym
from ..core.common import ToolError, format_bytes, ok, parse_bytes, require

bp = Blueprint("sym", __name__, url_prefix="/api/sym")

MAX_BYTES = 64 * 1024


def _payload() -> dict:
    return request.get_json(silent=True) or {}


def _data(value, fmt, name: str, limit: int = MAX_BYTES) -> bytes:
    out = parse_bytes(value, fmt or "HEX")
    if len(out) > limit:
        raise ToolError(f"{name}长度不能大于 {limit} 字节")
    return out


def _check_algo(algo: str) -> str:
    algo = (algo or "SM4").upper()
    if algo not in sym.ALGOS:
        raise ToolError(f"不支持的算法：{algo}")
    return algo


# ---------------------------------------------------------------------------
# 分组密码（ECB / CBC / CTR / OFB / CFB，含填充）
# ---------------------------------------------------------------------------


@bp.post("/encrypt")
def encrypt():
    p = _payload()
    algo = _check_algo(p.get("type"))
    mode = (p.get("mode") or "CBC").upper()
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    message = _data(p.get("message"), p.get("messageFormat") or "TEXT", "明文")
    iv = parse_bytes(p.get("iv"), p.get("ivFormat") or "HEX") if (p.get("iv") or "").strip() else b""
    if mode == "XTS":
        tweak = _data(p.get("tweak"), p.get("tweakFormat") or "HEX", "Tweak")
        out = sym.block_crypt(algo, key, mode, "NOPADDING", message, b"",
                              encrypt=True, tweak=tweak, is_gb=bool(p.get("isGB", True)))
    else:
        out = sym.block_crypt(algo, key, mode, p.get("padding") or "PKCS7", message, iv, encrypt=True)
    return ok(format_bytes(out, p.get("cipherFormat") or "HEX"))


@bp.post("/decrypt")
def decrypt():
    p = _payload()
    algo = _check_algo(p.get("type"))
    mode = (p.get("mode") or "CBC").upper()
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    cipher = _data(p.get("cipher"), p.get("cipherFormat") or "HEX", "密文")
    iv = parse_bytes(p.get("iv"), p.get("ivFormat") or "HEX") if (p.get("iv") or "").strip() else b""
    if mode == "XTS":
        tweak = _data(p.get("tweak"), p.get("tweakFormat") or "HEX", "Tweak")
        out = sym.block_crypt(algo, key, mode, "NOPADDING", cipher, b"",
                              encrypt=False, tweak=tweak, is_gb=bool(p.get("isGB", True)))
    else:
        try:
            out = sym.block_crypt(algo, key, mode, p.get("padding") or "PKCS7", cipher, iv, encrypt=False)
        except ToolError as err:
            raise ToolError(f"解密失败：{err}")
    return ok(format_bytes(out, p.get("messageFormat") or "TEXT"))


# ---------------------------------------------------------------------------
# XTS 专用入口（与原站 /api/cipher/xts/* 参数一致）
# ---------------------------------------------------------------------------


@bp.post("/xts/encrypt")
def xts_encrypt():
    p = _payload()
    algo = _check_algo(p.get("type"))
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    message = _data(p.get("message"), p.get("messageFormat") or "HEX", "明文")
    tweak = _data(p.get("tweak"), p.get("tweakFormat") or "HEX", "Tweak")
    out = sym.block_crypt(algo, key, "XTS", "NOPADDING", message, b"", encrypt=True,
                          tweak=tweak, is_gb=bool(p.get("isGB", True)))
    return ok(format_bytes(out, p.get("cipherFormat") or "HEX"))


@bp.post("/xts/decrypt")
def xts_decrypt():
    p = _payload()
    algo = _check_algo(p.get("type"))
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    cipher = _data(p.get("cipher"), p.get("cipherFormat") or "HEX", "密文")
    tweak = _data(p.get("tweak"), p.get("tweakFormat") or "HEX", "Tweak")
    out = sym.block_crypt(algo, key, "XTS", "NOPADDING", cipher, b"", encrypt=False,
                          tweak=tweak, is_gb=bool(p.get("isGB", True)))
    return ok(format_bytes(out, p.get("messageFormat") or "HEX"))


# ---------------------------------------------------------------------------
# 序列密码 ZUC
# ---------------------------------------------------------------------------


def _zuc_params(p: dict) -> tuple[str, bytes, bytes]:
    algo = (p.get("type") or "ZUC128").upper()
    if algo not in ("ZUC128", "ZUC256"):
        raise ToolError(f"不支持的 ZUC 算法：{algo}")
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    iv = _data(p.get("iv"), p.get("ivFormat") or "HEX", "IV")
    if algo == "ZUC128":
        if len(key) != 16 or len(iv) != 16:
            raise ToolError("ZUC-128 需要 16 字节密钥与 16 字节 IV")
    else:
        if len(key) != 32 or len(iv) != 25:
            raise ToolError("ZUC-256 需要 32 字节密钥与 25 字节 IV")
    return algo, key, iv


@bp.post("/zuc/encrypt")
def zuc_encrypt():
    p = _payload()
    _, key, iv = _zuc_params(p)
    message = _data(p.get("message"), p.get("messageFormat") or "TEXT", "明文")
    return ok(format_bytes(sym.zuc_crypt(key, iv, message), p.get("resultFormat") or "HEX"))


@bp.post("/zuc/decrypt")
def zuc_decrypt():
    p = _payload()
    _, key, iv = _zuc_params(p)
    cipher = _data(require(p.get("result") if p.get("result") is not None else p.get("cipher"), "密文"),
                   p.get("resultFormat") or "HEX", "密文")
    return ok(format_bytes(sym.zuc_crypt(key, iv, cipher), p.get("messageFormat") or "HEX"))


@bp.post("/zuc/mac")
def zuc_mac():
    p = _payload()
    algo, key, iv = _zuc_params(p)
    message = _data(p.get("message"), p.get("messageFormat") or "TEXT", "消息")
    try:
        bits = int(p.get("macLength") or 4) * 8
    except (TypeError, ValueError):
        raise ToolError("MAC 长度必须为整数")
    if algo == "ZUC128":
        if bits not in (32,):
            # 与原站一致：ZUC-128 固定输出 4 字节
            bits = 32
    elif bits not in (32, 64, 128):
        raise ToolError("ZUC-256 的 MAC 长度只支持 4 / 8 / 16 字节")
    return ok(format_bytes(sym.zuc_mac(key, iv, message, bits), p.get("resultFormat") or "HEX"))


# ---------------------------------------------------------------------------
# GCM
# ---------------------------------------------------------------------------


@bp.post("/gcm/encrypt")
def gcm_encrypt():
    p = _payload()
    algo = (p.get("type") or "SM4").upper()
    if algo not in sym.GCM_ALGOS:
        raise ToolError(f"GCM 模式不支持算法：{algo}")
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    message = _data(p.get("message"), p.get("messageFormat") or "TEXT", "明文")
    iv = _data(p.get("iv"), p.get("ivFormat") or "HEX", "IV")
    aad = parse_bytes(p.get("aad") or "", p.get("aadFormat") or "TEXT")
    try:
        tag_len = int(p.get("tagLength") or 16)
    except (TypeError, ValueError):
        raise ToolError("Tag 长度必须为整数")
    if tag_len not in (4, 8, 16):
        raise ToolError("Tag 长度只支持 4 / 8 / 16 字节")
    if len(iv) < 1 or len(iv) > 64:
        raise ToolError("GCM 模式的 IV 长度必须为 1 ~ 64 字节")
    gcm = sym.GCM(algo, key)
    cipher, tag = gcm.encrypt(iv, message, aad, tag_len)
    return ok({
        "cipher": format_bytes(cipher, p.get("resultFormat") or "HEX"),
        "tag": format_bytes(tag, p.get("tagFormat") or "HEX"),
        "tagLength": tag_len,
        "length": len(cipher),
    })


@bp.post("/gcm/decrypt")
def gcm_decrypt():
    p = _payload()
    algo = (p.get("type") or "SM4").upper()
    if algo not in sym.GCM_ALGOS:
        raise ToolError(f"GCM 模式不支持算法：{algo}")
    key = _data(p.get("key"), p.get("keyFormat") or "HEX", "密钥")
    cipher = _data(require(p.get("result") if p.get("result") is not None else p.get("cipher"), "密文"),
                   p.get("resultFormat") or "HEX", "密文")
    iv = _data(p.get("iv"), p.get("ivFormat") or "HEX", "IV")
    aad = parse_bytes(p.get("aad") or "", p.get("aadFormat") or "TEXT")
    tag = _data(p.get("tag") or "", p.get("tagFormat") or "HEX", "认证标签", 64)
    try:
        tag_len = int(p.get("tagLength") or (len(tag) * 8 if tag else 16))
    except (TypeError, ValueError):
        raise ToolError("Tag 长度必须为整数")
    if tag_len not in (4, 8, 16):
        raise ToolError("Tag 长度只支持 4 / 8 / 16 字节")
    gcm = sym.GCM(algo, key)
    plain = gcm.decrypt(iv, cipher, aad, tag, tag_len)
    return ok(format_bytes(plain, p.get("messageFormat") or "TEXT"))
