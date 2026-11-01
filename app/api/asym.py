"""非对称算法接口：SM2 / RSA / ECDSA / 附件 / 点压缩（全部本地真算）。

路径与原站一致（前缀替换为 /api/asym）：
    /api/asym/sm2/...  /api/asym/rsa/...  /api/asym/ecdsa/...
    /api/asym/attach/...  /api/asym/compress/parse
"""
from __future__ import annotations

import base64

from flask import Blueprint, request

from ..core import asym
from ..core.common import ToolError, format_bytes, ok, parse_bytes

bp = Blueprint("asym", __name__, url_prefix="/api/asym")

DEFAULT_USER_ID = "31323334353637383132333435363738"  # "1234567812345678"


def _payload():
    return request.get_json(silent=True) or {}


def _text(p, name, default=""):
    value = p.get(name)
    return default if value is None else str(value)


def _hex(data: bytes) -> str:
    return data.hex().upper()


def _fmt_out(data: bytes, fmt, label="PUBLIC KEY") -> str:
    return asym.dump_blob(data, fmt, label)


def _user_id(p):
    raw = p.get("userId")
    if raw in (None, ""):
        raw = DEFAULT_USER_ID
        fmt = "HEX"
    else:
        fmt = p.get("userIdFormat") or "HEX"
    uid = parse_bytes(raw, fmt)
    if not uid:
        raise ToolError("用户标识不能为空")
    if len(uid) > 8192:
        raise ToolError("用户标识过长")
    return uid


# ---------------------------------------------------------------------------
# SM2
# ---------------------------------------------------------------------------


@bp.post("/sm2/keypair")
def sm2_keypair():
    p = _payload()
    pub_fmt = p.get("publicKeyFormat") or "HEX"
    priv_fmt = p.get("privateKeyFormat") or "HEX"
    d, pub = asym.sm2_keypair()
    return ok({
        "publicKey": asym.sm2_public_str(pub, pub_fmt),
        "privateKey": asym.sm2_private_str(d, priv_fmt),
        "publicKeyPem": asym.sm2_public_str(pub, "PEM"),
        "privateKeyPem": asym.sm2_private_str(d, "PEM"),
    })


@bp.post("/sm2/pubkey/calculate")
def sm2_pubkey_calculate():
    p = _payload()
    d = asym.parse_sm2_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    pub = asym.point_mul(asym.SM2_CURVE, d, asym.SM2_CURVE.g)
    if pub is None:
        raise ToolError("私钥非法：计算结果为无穷远点")
    fmt = p.get("publicKeyFormat") or "HEX"
    return ok(asym.sm2_public_str(pub, fmt))


@bp.post("/sm2/publickey/verify")
def sm2_publickey_verify():
    p = _payload()
    pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    return ok({
        "onCurve": True,
        "x": _hex(asym._int_bytes(pub[0], 32)),
        "y": _hex(asym._int_bytes(pub[1], 32)),
        "message": "公钥在曲线上",
    })


@bp.post("/sm2/encrypt")
def sm2_encrypt():
    p = _payload()
    pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待加密消息")
    if len(message) > 8192:
        raise ToolError("消息过长：SM2 单次加密建议不超过 8192 字节")
    mode = p.get("encryptMode") or "C1C3C2"
    cipher = asym.sm2_encrypt(pub, message, mode)
    # 与原站一致：裸密文 C1 不带 04 前缀
    if cipher[:1] == b"\x04" and len(cipher) > 96:
        cipher = cipher[1:]
    return ok(_fmt_out(cipher, p.get("cipherFormat") or "HEX"))


@bp.post("/sm2/decrypt")
def sm2_decrypt():
    p = _payload()
    d = asym.parse_sm2_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    cipher = parse_bytes(p.get("cipher"), p.get("cipherFormat") or "HEX")
    if not cipher:
        raise ToolError("请输入密文")
    message = asym.sm2_decrypt(d, cipher, p.get("encryptMode") or "C1C3C2")
    return ok(format_bytes(message, p.get("messageFormat") or "TEXT"))


@bp.post("/sm2/calculate/evalue")
def sm2_evalue():
    p = _payload()
    pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入消息")
    uid = _user_id(p)
    z, e = asym.sm2_e(pub, message, uid)
    z_fmt = p.get("zzFormat") or p.get("zFormat") or "HEX"
    e_fmt = p.get("resultFormat") or "HEX"
    return ok({
        "zHash": _fmt_out(z, z_fmt),
        "eHash": _fmt_out(e, e_fmt),
        "userId": uid.hex().upper(),
        "entl": "%04X" % (len(uid) * 8),
    })


@bp.post("/sm2/sign")
def sm2_sign():
    p = _payload()
    d = asym.parse_sm2_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    pub = asym.point_mul(asym.SM2_CURVE, d, asym.SM2_CURVE.g)
    if pub is None:
        raise ToolError("私钥非法：无法计算公钥")
    if str(p.get("hashMode") or "noHash") == "withHash":
        e = parse_bytes(p.get("hash"), p.get("hashFormat") or "HEX")
        if len(e) != 32:
            raise ToolError("e 值必须是 32 字节")
        z = b""
    else:
        message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
        if not message:
            raise ToolError("请输入待签名消息")
        uid = _user_id(p)
        z, e = asym.sm2_e(pub, message, uid)
    r, s = asym.sm2_sign_digest(d, e)
    sig = asym._int_bytes(r, 32) + asym._int_bytes(s, 32)
    return ok({
        "signature": _fmt_out(sig, p.get("signatureFormat") or "HEX"),
        "signatureDER": _fmt_out(asym.rs_to_der(r, s), p.get("signatureFormat") or "HEX"),
        "z": _hex(z) if z else "",
        "e": _hex(e),
        "publicKey": asym.sm2_public_str(pub, "HEX"),
    })


@bp.post("/sm2/verify")
def sm2_verify():
    p = _payload()
    pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    if str(p.get("hashMode") or "noHash") == "withHash":
        e = parse_bytes(p.get("hash"), p.get("hashFormat") or "HEX")
        if len(e) != 32:
            raise ToolError("e 值必须是 32 字节")
    else:
        message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
        if not message:
            raise ToolError("请输入待验签消息")
        uid = _user_id(p)
        _z, e = asym.sm2_e(pub, message, uid)
    sig = parse_bytes(p.get("signature"), p.get("signatureFormat") or "HEX")
    r, s = asym.parse_signature(sig)
    if not asym.sm2_verify_digest(pub, e, r, s):
        raise ToolError("验签失败")
    return ok({"valid": True, "e": _hex(e)}, "验签通过")


@bp.post("/sm2/verifyAndAttack")
def sm2_verify_and_attack():
    p = _payload()
    pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    mode = str(p.get("hashMode") or "noHash")
    if mode == "withHash":
        e1 = parse_bytes(p.get("hash"), p.get("hashFormat") or "HEX")
        e2 = parse_bytes(p.get("hashTwo"), p.get("hashTwoFormat") or "HEX")
        if len(e1) != 32 or len(e2) != 32:
            raise ToolError("e 值必须是 32 字节")
    else:
        uid = _user_id(p)
        m1 = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
        m2 = parse_bytes(p.get("messageTwo"), p.get("messageTwoFormat") or "TEXT")
        if not m1 or not m2:
            raise ToolError("请提供两组待签名消息")
        _z1, e1 = asym.sm2_e(pub, m1, uid)
        _z2, e2 = asym.sm2_e(pub, m2, uid)
    sig1 = asym.parse_signature(parse_bytes(p.get("signature"), p.get("signatureFormat") or "HEX"))
    sig2 = asym.parse_signature(parse_bytes(p.get("signatureTwo"), p.get("signatureTwoFormat") or "HEX"))
    if not asym.sm2_verify_digest(pub, e1, *sig1):
        raise ToolError("第一组签名验证不通过，无法进行攻击分析")
    if not asym.sm2_verify_digest(pub, e2, *sig2):
        raise ToolError("第二组签名验证不通过，无法进行攻击分析")
    d, k = asym.sm2_recover_private_key(e1, sig1, e2, sig2)
    if asym.point_mul(asym.SM2_CURVE, d, asym.SM2_CURVE.g) != pub:
        raise ToolError("反推私钥与公钥不匹配：两条签名并未使用同一随机数 k")
    priv_fmt = p.get("privateKeyFormat") or "HEX"
    return ok({
        "privateKey": asym.sm2_private_str(d, priv_fmt),
        "privateKeyHex": format(d, "064X"),
        "k": format(k, "064X"),
        "message": "两组签名均验证通过，且使用了相同的随机数 k，私钥已被反推",
    }, "攻击成功：已通过重复随机数 k 反推出私钥")


@bp.post("/sm2/signature/convert")
def sm2_signature_convert():
    p = _payload()
    sig = parse_bytes(p.get("signature"), p.get("signatureFormat") or "HEX")
    if not sig:
        raise ToolError("请输入签名值")
    target = str(p.get("targetFormat") or "DER").upper()
    r, s = asym.parse_signature(sig)
    if target in ("DER", "ASN1", "ASN.1"):
        out = asym.rs_to_der(r, s)
    elif target in ("RAW", "RS", "R||S", "R|S"):
        out = asym._int_bytes(r, 32) + asym._int_bytes(s, 32)
    else:
        raise ToolError(f"不支持的目标格式：{target}")
    return ok(_hex(out))


@bp.post("/sm2/cipher/convert")
def sm2_cipher_convert():
    p = _payload()
    cipher = parse_bytes(p.get("cipher"), p.get("cipherFormat") or "HEX")
    if not cipher:
        raise ToolError("请输入密文")
    mode = p.get("encryptMode") or "C1C3C2"
    target = str(p.get("targetFormat") or "DER").upper()
    if target in ("DER", "ASN1", "ASN.1"):
        out = asym.sm2_cipher_to_der(cipher, mode)
    elif target in ("RAW", "PLAIN", "裸密文"):
        out = asym.sm2_cipher_from_der(cipher, mode) if cipher[:1] == b"\x30" else cipher
    else:
        raise ToolError(f"不支持的目标格式：{target}")
    return ok(_hex(out))


@bp.post("/sm2/cert/extract-pubkey")
def sm2_cert_extract_pubkey():
    p = _payload()
    data = asym.load_blob(p.get("cert"), p.get("certFormat") or "TEXT")
    if not data:
        raise ToolError("请提供证书数据")
    kind, blob = asym.extract_public_key_der(data)
    if kind != "SM2":
        raise ToolError(f"该证书中的公钥不是 SM2（识别为 {kind}）")
    pub = asym._decode_point_bytes((b"\x04" + blob) if len(blob) == 64 else blob, asym.SM2_CURVE)
    return ok(asym.sm2_public_str(pub, p.get("publicKeyFormat") or "HEX"))


@bp.post("/sm2/private/pem/parse")
def sm2_private_pem_parse():
    p = _payload()
    text = _text(p, "privateKeyPem")
    if not text.strip():
        raise ToolError("请输入私钥 PEM")
    if "-----BEGIN" not in text:
        raise ToolError("无法解析私钥 PEM 格式")
    label, der = asym.pem_decode(text)
    if "PRIVATE KEY" not in label:
        raise ToolError(f"PEM 类型不支持：{label}")
    d = asym._parse_ec_private(der)
    pub = asym.point_mul(asym.SM2_CURVE, d, asym.SM2_CURVE.g)
    return ok({
        "privateKey": asym.sm2_private_str(d, p.get("privateKeyFormat") or "HEX"),
        "publicKey": asym.sm2_public_str(pub, p.get("publicKeyFormat") or "HEX"),
        "privateKeyPem": asym.sm2_private_str(d, "PEM"),
        "publicKeyPem": asym.sm2_public_str(pub, "PEM"),
    })


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------


@bp.post("/rsa/keypair")
def rsa_keypair():
    p = _payload()
    key = asym.rsa_keypair(p.get("keySize") or 2048)
    return ok({
        "publicKey": _fmt_out(asym.rsa_public_der(key), p.get("publicKeyFormat") or "HEX",
                              "PUBLIC KEY"),
        "privateKey": _fmt_out(asym.rsa_private_der(key), p.get("privateKeyFormat") or "HEX",
                               "PRIVATE KEY"),
        "bits": key.size_in_bits(),
        "e": key.e,
    })


@bp.post("/rsa/pubkey/calculate")
def rsa_pubkey_calculate():
    p = _payload()
    key = asym.parse_rsa_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    return ok(_fmt_out(asym.rsa_public_der(key), p.get("publicKeyFormat") or "HEX"))


@bp.post("/rsa/encrypt")
def rsa_encrypt():
    p = _payload()
    pub = asym.parse_rsa_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待加密消息")
    cipher = asym.rsa_encrypt(pub, message, p.get("fillMethod"))
    return ok(_fmt_out(cipher, p.get("cipherFormat") or "HEX"))


@bp.post("/rsa/decrypt")
def rsa_decrypt():
    p = _payload()
    priv = asym.parse_rsa_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    cipher = parse_bytes(p.get("cipher"), p.get("cipherFormat") or "HEX")
    if not cipher:
        raise ToolError("请输入密文")
    message = asym.rsa_decrypt(priv, cipher, p.get("fillMethod"))
    return ok(format_bytes(message, p.get("messageFormat") or "TEXT"))


@bp.post("/rsa/sign")
def rsa_sign():
    p = _payload()
    priv = asym.parse_rsa_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待签名消息")
    sig = asym.rsa_sign(priv, message, p.get("signHash"))
    return ok(_fmt_out(sig, p.get("signatureFormat") or "HEX"))


@bp.post("/rsa/verify")
def rsa_verify():
    p = _payload()
    pub = asym.parse_rsa_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    sig = parse_bytes(p.get("signature"), p.get("signatureFormat") or "HEX")
    if not message:
        raise ToolError("请输入待验签消息")
    if not sig:
        raise ToolError("请输入签名值")
    if not asym.rsa_verify(pub, message, sig, p.get("signHash")):
        raise ToolError("验签失败")
    return ok({"valid": True}, "验签通过")


@bp.post("/rsa/extract/publicKey")
def rsa_extract_public_key():
    p = _payload()
    data = asym.load_blob(p.get("cert"), p.get("certFormat") or "TEXT")
    if not data:
        raise ToolError("请提供证书或公钥数据")
    kind, blob = asym.extract_public_key_der(data)
    if kind != "RSA":
        raise ToolError(f"该数据中的公钥不是 RSA（识别为 {kind}）")
    return ok(_fmt_out(blob, p.get("publicKeyFormat") or "HEX"))


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------


@bp.post("/ecdsa/keypair")
def ecdsa_keypair():
    p = _payload()
    curve, priv, pub = asym.ecdsa_keypair(p.get("curveType"))
    priv_fmt = p.get("privateKeyFormat") or "HEX"
    pub_fmt = p.get("publicKeyFormat") or "HEX"
    return ok({
        "curveType": curve,
        "publicKey": asym.ec_public_str(pub, curve, pub_fmt),
        "privateKey": asym.ec_private_str(priv, curve, priv_fmt),
        "publicKeyPem": asym.dump_blob(asym.ecdsa_public_der(pub), "PEM", "PUBLIC KEY"),
        "privateKeyPem": asym.dump_blob(asym.ecdsa_private_der(priv), "PEM", "PRIVATE KEY"),
    })


@bp.post("/ecdsa/sign")
def ecdsa_sign():
    p = _payload()
    curve = asym.resolve_ec_curve(p.get("curveType"))
    priv = asym.parse_ecdsa_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX", curve)
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待签名消息")
    sig = asym.ecdsa_sign(priv, message, curve, p.get("signHash"))
    return ok(_fmt_out(sig, p.get("signatureFormat") or "HEX"))


@bp.post("/ecdsa/verify")
def ecdsa_verify():
    p = _payload()
    curve = asym.resolve_ec_curve(p.get("curveType"))
    pub = asym.parse_ecdsa_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX", curve)
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    sig = parse_bytes(p.get("signature"), p.get("signatureFormat") or "HEX")
    if not message:
        raise ToolError("请输入待验签消息")
    if not sig:
        raise ToolError("请输入签名值")
    if not asym.ecdsa_verify(pub, message, sig, curve, p.get("signHash")):
        raise ToolError("验签失败")
    return ok({"valid": True}, "验签通过")


@bp.post("/ecdsa/encrypt")
def ecdsa_encrypt():
    p = _payload()
    curve = asym.resolve_ec_curve(p.get("curveType"))
    pub = asym.parse_ecdsa_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX", curve)
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待加密消息")
    cipher = asym.ecdsa_encrypt(pub, message, curve)
    return ok(_fmt_out(cipher, p.get("cipherFormat") or "HEX"))


@bp.post("/ecdsa/decrypt")
def ecdsa_decrypt():
    p = _payload()
    curve = asym.resolve_ec_curve(p.get("curveType"))
    priv = asym.parse_ecdsa_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX", curve)
    cipher = parse_bytes(p.get("cipher"), p.get("cipherFormat") or "HEX")
    if not cipher:
        raise ToolError("请输入密文")
    message = asym.ecdsa_decrypt(priv, cipher, curve)
    return ok(format_bytes(message, p.get("messageFormat") or "TEXT"))


# ---------------------------------------------------------------------------
# Attach & Detach
# ---------------------------------------------------------------------------


@bp.post("/attach/attach")
def attach_attach():
    p = _payload()
    pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
    uid = _user_id(p)
    blob = asym.attach_build(pub, uid)
    return ok({
        "attachment": _hex(blob),
        "publicKey": asym.sm2_public_str(pub, "HEX"),
        "userId": uid.hex().upper(),
        "userIdText": uid.decode("utf-8", "replace"),
        "size": len(blob),
        "layout": "04||X||Y(65B) + 用户标识(%dB)" % len(uid),
    })


@bp.post("/attach/detach")
def attach_detach():
    p = _payload()
    blob = parse_bytes(p.get("attachData") or p.get("attachment"), p.get("attachFormat") or "HEX")
    if not blob:
        raise ToolError("请输入附件数据")
    pub, uid = asym.attach_parse(blob)
    return ok({
        "publicKey": asym.sm2_public_str(pub, p.get("publicKeyFormat") or "HEX"),
        "publicKeyFull": _hex(asym.encode_point(pub)),
        "userId": uid.hex().upper(),
        "userIdText": uid.decode("utf-8", "replace"),
        "size": len(blob),
    })


@bp.post("/attach/sign")
def attach_sign():
    p = _payload()
    d = asym.parse_sm2_private(p.get("privateKey"), p.get("privateKeyFormat") or "HEX")
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待签名消息")
    uid = _user_id(p)
    result = asym.attach_sign(d, message, uid)
    sig_fmt = p.get("signatureFormat") or "HEX"
    result["signature"] = _fmt_out(bytes.fromhex(result["signature"]), sig_fmt)
    result["package"] = _fmt_out(bytes.fromhex(result["package"]), sig_fmt)
    result["attachment"] = _fmt_out(bytes.fromhex(result["attachment"]), sig_fmt)
    for key in ("publicKey", "userKey", "z", "e", "signatureDER"):
        result[key] = result[key].upper()
    return ok(result)


@bp.post("/attach/verify")
def attach_verify():
    p = _payload()
    sig_fmt = p.get("signatureFormat") or "HEX"
    message = parse_bytes(p.get("message"), p.get("messageFormat") or "TEXT")
    if not message:
        raise ToolError("请输入待验签消息")
    package = parse_bytes(p.get("package") or p.get("attachData"), sig_fmt) if (p.get("package") or p.get("attachData")) else b""
    if package:
        point, uid, signature = asym.attach_split_package(package)
        pub = point
    else:
        pub = asym.parse_sm2_public(p.get("publicKey"), p.get("publicKeyFormat") or "HEX")
        uid = _user_id(p)
        signature = parse_bytes(p.get("signature"), sig_fmt)
        if not signature:
            raise ToolError("请输入签名值或附件包")
    if not asym.attach_verify(pub, message, uid, signature):
        raise ToolError("验签失败")
    return ok({
        "valid": True,
        "publicKey": asym.sm2_public_str(pub, "HEX"),
        "userId": uid.hex().upper(),
    }, "验签通过")


# ---------------------------------------------------------------------------
# 点压缩 / 解压
# ---------------------------------------------------------------------------


@bp.post("/compress/parse")
def compress_parse():
    p = _payload()
    curve_type = str(p.get("type") or "SM2").upper()
    if curve_type in ("SM2", "SM2P256V1"):
        curve = asym.SM2_CURVE
    elif curve_type == "SM9":
        if not asym.SM9_AVAILABLE:
            raise ToolError("SM9 曲线参数自检未通过，暂不支持 SM9 点压缩")
        curve = asym.SM9_CURVE
    else:
        raise ToolError(f"不支持的曲线类型：{curve_type}")
    action = str(p.get("compressType") or "compress").lower()
    if action in ("compress", "压缩"):
        raw = parse_bytes(p.get("decompressPubkey"), "HEX")
        if not raw:
            raise ToolError("请输入待压缩的未压缩公钥")
        out = asym.compress_point(curve, raw)
        return ok(_hex(out))
    if action in ("decompress", "解压"):
        raw = parse_bytes(p.get("compressPubkey"), "HEX")
        if not raw:
            raise ToolError("请输入待解压的压缩公钥")
        point = asym.decompress_point(curve, raw)
        # 与原站一致：解压输出 X||Y（不带 04 前缀），本地解析两种形式都接受
        return ok(_hex(asym.encode_point(point)[1:]))
    raise ToolError(f"不支持的操作类型：{p.get('compressType')}")
