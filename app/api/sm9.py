"""SM9 接口（前缀 /api/sm9）。

接口与原站一一对应：

    POST /api/sm9/generate/master/keypair   生成签名/加密主密钥对
    POST /api/sm9/generate/user/Key         生成用户私钥
    POST /api/sm9/sign                      签名
    POST /api/sm9/verify                    验签
    POST /api/sm9/encrypt                   加密
    POST /api/sm9/decrypt                   解密
    POST /api/sm9/key/enc                   密钥封装
    POST /api/sm9/key/dec                   密钥解封装
    POST /api/sm9/signature/convert         签名值 h||s 与 DER 互转
    POST /api/sm9/params                    曲线参数展示
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import sm9
from ..core.common import ToolError, format_bytes, ok, parse_bytes

bp = Blueprint("sm9", __name__, url_prefix="/api/sm9")

MAX_MESSAGE = 4096


def _payload() -> dict:
    return request.get_json(silent=True) or {}


def _text(value, name: str) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ToolError(f"请输入{name}")
    return value


def _hx(data: bytes) -> str:
    """HEX 输出统一大写，与原站保持一致。"""
    return data.hex().upper()


def _out(data: bytes, fmt: str | None) -> str:
    fmt = (fmt or "HEX").upper()
    if fmt == "HEX":
        return _hx(data)
    return format_bytes(data, fmt)


def _scalar(value, fmt, name: str) -> int:
    raw = parse_bytes(_text(value, name), fmt or "HEX")
    if len(raw) > 32:
        raise ToolError(f"{name}长度不能超过 32 字节")
    k = int.from_bytes(raw, "big")
    if k <= 0 or k >= sm9.N_ORDER:
        raise ToolError(f"{name}必须为 1 到 N-1 之间的整数")
    return k


def _g1(value, fmt, name: str):
    raw = parse_bytes(_text(value, name), fmt or "HEX")
    try:
        return sm9.g1_from_bytes(raw)
    except ToolError as exc:
        raise ToolError(f"{name}非法：{exc}")


def _g2(value, fmt, name: str):
    raw = parse_bytes(_text(value, name), fmt or "HEX")
    try:
        return sm9.g2_from_bytes(raw)
    except ToolError as exc:
        raise ToolError(f"{name}非法：{exc}")


def _user_id(p: dict) -> bytes:
    uid = parse_bytes(_text(p.get("userId"), " 用户标识ID ").strip(), p.get("userIdFormat") or "TEXT")
    if not uid:
        raise ToolError("用户标识ID不能为空")
    if len(uid) > 128:
        raise ToolError("用户标识ID长度不能超过 128 字节")
    return uid


def _message(p: dict) -> bytes:
    data = parse_bytes(p.get("message") or "", p.get("messageFormat") or "TEXT")
    if len(data) > MAX_MESSAGE:
        raise ToolError(f"消息长度不能超过 {MAX_MESSAGE} 字节")
    return data


def _enc_type(p: dict) -> str:
    t = (p.get("encType") or "STREAM").upper()
    if t not in ("BLOCK", "STREAM"):
        raise ToolError("加密模式只能为 BLOCK（分组）或 STREAM（流）")
    return t


@bp.post("/params")
def params():
    return ok({
        "curve": sm9.CURVE_INFO,
        "q": f"{sm9.P_MOD:064X}",
        "n": f"{sm9.N_ORDER:064X}",
        "t": f"{sm9.T_TRACE:016X}",
        "embeddingDegree": 12,
        "b": sm9.CURVE_B,
    })


@bp.post("/generate/master/keypair")
def generate_master_keypair():
    p = _payload()
    pub_fmt = p.get("publicKeyFormat") or "HEX"
    pri_fmt = p.get("privateKeyFormat") or "HEX"
    res = sm9.generate_master_keypair(p.get("type") or "SIGN")
    pub = bytes.fromhex(res["publicKey"])
    pri = bytes.fromhex(res["privateKey"])
    return ok({
        "type": res["type"],
        "pubKey": _out(pub, pub_fmt),
        "priKey": _out(pri, pri_fmt),
    })


@bp.post("/generate/user/Key")
def generate_user_key():
    p = _payload()
    master = _scalar(p.get("privateKey"), p.get("privateKeyFormat") or "HEX", "主私钥")
    uid = _user_id(p)
    key = sm9.generate_user_key(master, uid, p.get("userKeyType") or 1)
    return ok(_out(key, p.get("userPrivateKeyFormat") or "HEX"))


@bp.post("/sign")
def sign():
    p = _payload()
    pub = _g2(p.get("publicKey"), p.get("publicKeyFormat") or "HEX", "签名主公钥")
    uid = _user_id(p)
    priv = _g1(p.get("userPrivateKey"), p.get("userPrivateKeyFormat") or "HEX", "用户签名私钥")
    msg = _message(p)
    sig = sm9.sign(pub, priv, uid, msg)
    return ok(_out(sig, p.get("signatureFormat") or "HEX"))


@bp.post("/verify")
def verify():
    p = _payload()
    pub = _g2(p.get("publicKey"), p.get("publicKeyFormat") or "HEX", "签名主公钥")
    uid = _user_id(p)
    msg = _message(p)
    sig = parse_bytes(_text(p.get("signature"), "签名值"), p.get("signatureFormat") or "HEX")
    if len(sig) not in (96, 97):
        if sig[:1] == b"\x30":
            sig = sm9.sig_from_der(sig)
        else:
            raise ToolError("签名值格式错误，请输入 h||s（96/97 字节）或 DER 编码")
    if not sm9.verify(pub, uid, msg, sig):
        raise ToolError("验证不通过")
    return ok("验证通过")


@bp.post("/encrypt")
def encrypt():
    p = _payload()
    pub = _g1(p.get("publicKey"), p.get("publicKeyFormat") or "HEX", "加密主公钥")
    uid = _user_id(p)
    msg = _message(p)
    ct = sm9.encrypt(pub, uid, msg, _enc_type(p))
    return ok(_out(ct, p.get("cipherFormat") or "HEX"))


@bp.post("/decrypt")
def decrypt():
    p = _payload()
    priv = _g2(p.get("userPrivateKey"), p.get("userPrivateKeyFormat") or "HEX", "用户加密私钥")
    uid = _user_id(p)
    ct = parse_bytes(_text(p.get("cipher"), "密文"), p.get("cipherFormat") or "HEX")
    plain = sm9.decrypt(priv, uid, ct, _enc_type(p))
    return ok(_out(plain, p.get("messageFormat") or "TEXT"))


@bp.post("/key/enc")
def key_encaps():
    p = _payload()
    pub = _g1(p.get("publicKey"), p.get("publicKeyFormat") or "HEX", "加密主公钥")
    uid = _user_id(p)
    try:
        klen = int(p.get("klen") or 16)
    except (TypeError, ValueError):
        raise ToolError("密钥长度必须为整数")
    if klen < 1 or klen > 1024:
        raise ToolError("密钥长度必须为 1 到 1024 字节")
    key, cipher = sm9.kem_encaps(pub, uid, klen)
    return ok({
        "cipher": _out(cipher, p.get("cipherFormat") or "HEX"),
        "key": _out(key, p.get("keyFormat") or "HEX"),
    })


@bp.post("/key/dec")
def key_decaps():
    p = _payload()
    priv = _g2(p.get("userPrivateKey"), p.get("userPrivateKeyFormat") or "HEX", "用户加密私钥")
    uid = _user_id(p)
    ct = parse_bytes(_text(p.get("cipher"), "密文"), p.get("cipherFormat") or "HEX")
    try:
        klen = int(p.get("klen") or 16)
    except (TypeError, ValueError):
        raise ToolError("密钥长度必须为整数")
    if klen < 1 or klen > 1024:
        raise ToolError("密钥长度必须为 1 到 1024 字节")
    key = sm9.kem_decaps(priv, uid, ct, klen)
    return ok(_out(key, p.get("keyFormat") or "HEX"))


@bp.post("/signature/convert")
def signature_convert():
    p = _payload()
    raw = parse_bytes(_text(p.get("signature"), "签名值"), p.get("signatureFormat") or "HEX")
    target = (p.get("targetFormat") or "DER").upper()
    if target == "DER":
        if raw[:1] == b"\x30" and len(raw) not in (96, 97):
            raise ToolError("当前签名已经是 DER 格式")
        out = sm9.sig_to_der(raw)
    elif target in ("RAW", "HS", "H||S"):
        if raw[:1] != b"\x30" and len(raw) in (96, 97):
            out = raw
        else:
            out = sm9.sig_from_der(raw)
    else:
        raise ToolError("目标格式只能为 DER 或 RAW")
    return ok(_out(out, "HEX"))
