"""能力验证必备模块接口：PRF / KDF / TLCP / SM2K / 签名攻击 / 点运算 / PBKDF2 / 工作模式检测。

统一前缀 /api/ops，全部为本地纯计算。
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import ops
from ..core.common import ToolError, format_bytes, ok, parse_bytes

bp = Blueprint("ops", __name__, url_prefix="/api/ops")

MAX_INPUT = 5000


def _payload() -> dict:
    return request.get_json(silent=True) or {}


def _data(p: dict, name: str, fmt: str | None = None, default_fmt: str = "HEX") -> bytes:
    value = p.get(name)
    if value is None:
        value = ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return parse_bytes(value, fmt or p.get(name + "Format") or default_fmt)


def _require_bytes(data: bytes, label: str) -> bytes:
    if not data:
        raise ToolError(f"请输入{label}")
    if len(data) > MAX_INPUT:
        raise ToolError(f"{label}长度不能超过 {MAX_INPUT} 字节")
    return data


def _int_field(value, name: str, default=None, minimum=1, maximum=None) -> int:
    if value in (None, ""):
        if default is None:
            raise ToolError(f"请输入{name}")
        return default
    try:
        num = int(value)
    except (TypeError, ValueError):
        raise ToolError(f"{name}必须为整数")
    if minimum is not None and num < minimum:
        raise ToolError(f"{name}必须大于等于 {minimum}")
    if maximum is not None and num > maximum:
        raise ToolError(f"{name}不能超过 {maximum}")
    return num


# ---------------------------------------------------------------- PRF

@bp.post("/prf")
def prf():
    """PRF：HMAC 迭代伪随机函数，输出长度 = 轮数 × 摘要长度。"""
    p = _payload()
    algo = p.get("type") or "SM3"
    key = _require_bytes(_data(p, "key", default_fmt="HEX"), "Key")
    seed = _require_bytes(_data(p, "seed", default_fmt="TEXT"), "Seed")
    label = p.get("lable")
    if label is None:
        label = p.get("label") or ""
    label_bytes = str(label).encode("utf-8")
    rounds = _int_field(p.get("rounds"), "迭代轮数", 4, 1, ops.MAX_ROUNDS)
    site = (p.get("labelSite") or p.get("lableSite") or "POST").upper()
    mode = p.get("prfMode") or "HMAC"
    out = ops.prf_run(algo, key, seed, label_bytes, rounds,
                      label_after=(site in ("POST", "AFTER", "后置")), mode=mode)
    fmt = p.get("resultFormat") or "HEX"
    result = format_bytes(out, fmt)
    return ok(result)


# ---------------------------------------------------------------- KDF

@bp.post("/kdf")
def kdf():
    """KDF：SM3-KDF / SHA-256 迭代 KDF / HKDF-SHA256 / X9.63-KDF。"""
    p = _payload()
    kind = p.get("type") or "SM3"
    z = _require_bytes(_data(p, "message", default_fmt="HEX"), "共享比特串 Z")
    klen = _int_field(p.get("length"), "输出长度", None, 1, ops.MAX_KDF)
    info = _data(p, "sharedInfo", default_fmt="HEX") if p.get("sharedInfo") else b""
    salt = _data(p, "salt", default_fmt="HEX") if p.get("salt") else b""
    out = ops.kdf(kind, z, klen, info, salt)
    return ok(format_bytes(out, p.get("resultFormat") or "HEX"))


# ---------------------------------------------------------------- TLCP

@bp.post("/tlcp/master")
def tlcp_master():
    p = _payload()
    pms = _require_bytes(_data(p, "preMasterKey", default_fmt="HEX"), "预主密钥")
    cr = _require_bytes(_data(p, "clientRandom", default_fmt="HEX"), "客户端随机数")
    sr = _require_bytes(_data(p, "serverRandom", default_fmt="HEX"), "服务端随机数")
    label = (p.get("str1") or "master secret")
    out = ops.tlcp_master_secret(pms, cr, sr, str(label).encode("utf-8"), p.get("type") or "SM3")
    return ok(out.hex())


@bp.post("/tlcp/keys")
def tlcp_keys():
    p = _payload()
    master = _require_bytes(_data(p, "masterKey", default_fmt="HEX"), "主密钥")
    cr = _require_bytes(_data(p, "clientRandom", default_fmt="HEX"), "客户端随机数")
    sr = _require_bytes(_data(p, "serverRandom", default_fmt="HEX"), "服务端随机数")
    label = (p.get("str2") or "key expansion")
    suite = p.get("cipherSuiteType") or 1
    data = ops.tlcp_key_block(master, cr, sr, str(label).encode("utf-8"),
                              p.get("type") or "SM3", suite,
                              p.get("keyLen"), p.get("ivLen"), p.get("macLen"))
    return ok(data)


# ---------------------------------------------------------------- 椭圆曲线点运算

@bp.post("/point")
def point():
    p = _payload()
    op = p.get("type") or 1
    curve = p.get("curveName") or "sm2p256v1"
    one = _require_bytes(_data(p, "pointOne", default_fmt="HEX"), "第一个点")
    two = b""
    if p.get("pointTwo"):
        two = _data(p, "pointTwo", default_fmt="HEX")
    compressed = bool(p.get("compressed"))
    out = ops.point_operation(op, curve, one, two, True, compressed)
    return ok(format_bytes(out, p.get("resultFormat") or "HEX"))


# ---------------------------------------------------------------- SM2 加密 K

@bp.post("/sm2k/collision")
def sm2k_collision():
    """碰撞随机数 k（仅需 C1）。"""
    p = _payload()
    cipher = _require_bytes(_data(p, "cipher", default_fmt="HEX"), "密文或 C1 部分")
    pub = _data(p, "publicKey", default_fmt="HEX") if p.get("publicKey") else None
    res = ops.sm2_enc_k_analyze(cipher, pub, p.get("maxK"), recover=False)
    res["c1Point"] = None
    res.pop("plain", None)
    return ok(res)


@bp.post("/sm2k/recover")
def sm2k_recover():
    """碰撞 k 并恢复明文（需要完整密文与公钥）。"""
    p = _payload()
    cipher = _require_bytes(_data(p, "cipher", default_fmt="HEX"), "密文")
    pub = _require_bytes(_data(p, "publicKey", default_fmt="HEX"), "加密公钥")
    res = ops.sm2_enc_k_analyze(cipher, pub, p.get("maxK"), recover=True)
    res.pop("c1Point", None)
    plain = res.get("plain")
    fmt = p.get("resultFormat") or "TEXT"
    if plain is None:
        res["result"] = ""
    else:
        res["result"] = format_bytes(plain, fmt) if fmt != "HEX" else plain.hex()
        res["plainHex"] = plain.hex()
    res.pop("plain", None)
    return ok(res)


@bp.post("/sm2k/reuse")
def sm2k_reuse():
    """检测两组密文是否复用同一随机数 k（C1 相同）。"""
    p = _payload()
    a = _require_bytes(_data(p, "cipher", default_fmt="HEX"), "密文 1")
    b = _require_bytes(_data(p, "cipher2", default_fmt="HEX"), "密文 2")
    pub = _data(p, "publicKey", default_fmt="HEX") if p.get("publicKey") else None
    return ok(ops.sm2_k_reuse_compare(a, b, pub))


# ---------------------------------------------------------------- SM2 签名攻击

def _sig_bytes(p: dict, name: str) -> bytes:
    return _require_bytes(_data(p, name, default_fmt="HEX"), "签名值")


def _e_bytes(p: dict, name: str) -> int:
    raw = _data(p, name, default_fmt="HEX")
    if not raw:
        raise ToolError("请输入 e 值")
    return int.from_bytes(raw, "big")


@bp.post("/unravel/rrss")
def unravel_rrss():
    """rrss → d：两组同 k 签名反推私钥。"""
    p = _payload()
    s1 = _sig_bytes(p, "signOne")
    s2 = _sig_bytes(p, "signTwo")
    e1 = _e_bytes(p, "macOne")
    e2 = _e_bytes(p, "macTwo")
    return ok(ops.unravel_rrss(s1, s2, e1, e2))


@bp.post("/unravel/eess")
def unravel_eess():
    """eess（R||S||E）→ d。"""
    p = _payload()
    s1 = _sig_bytes(p, "signOne")
    s2 = _sig_bytes(p, "signTwo")
    e1 = _data(p, "macOne", default_fmt="HEX") or None
    e2 = _data(p, "macTwo", default_fmt="HEX") or None
    return ok(ops.unravel_eess(s1, s2, e1, e2))


@bp.post("/unravel/rsk")
def unravel_rsk():
    """rsk → d：一组签名 + k 反推私钥。"""
    p = _payload()
    r, s = ops.split_rs(_sig_bytes(p, "signOne"), "签名值")
    k = int.from_bytes(_require_bytes(_data(p, "random", default_fmt="HEX"), "随机数 k"), "big")
    d = ops.d_from_rsk(r, s, k)
    pub = ops.sm2_pubkey_from_priv(d)
    # 交叉校验：(k-s)/(r+s) 反推的 d 必然满足 s*(1+d)+r*d ≡ k
    checked = ops.k_from_rsd(r, s, d) == k % ops.get_curve("sm2p256v1").n
    return ok({
        "d": f"{d:064x}",
        "k": f"{k:064x}",
        "verified": checked,
        "publicKey": ops.point_encode(ops.get_curve("sm2p256v1"), pub).hex(),
    })


@bp.post("/unravel/rsd")
def unravel_rsd():
    """rsd → k：一组签名 + 私钥反推随机数 k。"""
    p = _payload()
    r, s = ops.split_rs(_sig_bytes(p, "signOne"), "签名值")
    d = int.from_bytes(_require_bytes(_data(p, "key", default_fmt="HEX"), "私钥 d"), "big")
    k = ops.k_from_rsd(r, s, d)
    return ok({"k": f"{k:064x}", "r": f"{r:064x}", "s": f"{s:064x}"})


@bp.post("/unravel/rsd1")
def unravel_rsd1():
    """rsd1 → d2：第一组签名 + d1 + 第二组签名推出 d2。"""
    p = _payload()
    r1, s1 = ops._split_rs(_sig_bytes(p, "signOne"), "第一组签名值")
    r2, s2 = ops._split_rs(_sig_bytes(p, "signTwo"), "第二组签名值")
    d1 = int.from_bytes(_require_bytes(_data(p, "key", default_fmt="HEX"), "私钥 d1"), "big")
    d2 = ops.d2_from_rsd1(r1, s1, d1, r2, s2)
    k = ops.k_from_rsd(r1, s1, d1)
    return ok({"d2": f"{d2:064x}", "d": f"{d2:064x}", "k": f"{k:064x}"})


@bp.post("/unravel/rs2der")
def unravel_rs2der():
    """R||S → DER。"""
    p = _payload()
    r, s = ops._split_rs(_sig_bytes(p, "signOne"), "签名值")
    der = ops.rs_to_der(r, s)
    return ok(format_bytes(der, p.get("resultFormat") or "HEX"))


@bp.post("/unravel/der2rs")
def unravel_der2rs():
    """DER → R||S。"""
    p = _payload()
    der = _require_bytes(_data(p, "signOne", default_fmt="HEX"), "DER 签名")
    r, s = ops.der_to_rs(der)
    return ok({"rs": f"{r:064x}{s:064x}", "r": f"{r:064x}", "s": f"{s:064x}"})


@bp.post("/unravel/eess2der")
def unravel_eess2der():
    """EESS（R||S||E）→ DER。"""
    p = _payload()
    raw = _sig_bytes(p, "signOne")
    _, r, s = ops.parse_eess(raw)
    der = ops.rs_to_der(r, s)
    return ok(format_bytes(der, p.get("resultFormat") or "HEX"))


@bp.post("/unravel/der2eess")
def unravel_der2eess():
    """DER → EESS（R||S||E）。"""
    p = _payload()
    der = _require_bytes(_data(p, "signOne", default_fmt="HEX"), "DER 签名")
    r, s = ops.der_to_rs(der)
    e_raw = _data(p, "macOne", default_fmt="HEX")
    e = int.from_bytes(e_raw, "big") if e_raw else 0
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big") + (e % (1 << 256)).to_bytes(32, "big")
    return ok(format_bytes(raw, p.get("resultFormat") or "HEX"))


@bp.post("/unravel/verify")
def unravel_verify():
    """用公钥校验一组 SM2 签名（辅助确认反推结果的正确性）。"""
    p = _payload()
    r, s = ops._split_rs(_sig_bytes(p, "signOne"), "签名值")
    e = _e_bytes(p, "macOne")
    pub = _require_bytes(_data(p, "publicKey", default_fmt="HEX"), "公钥")
    point = ops.point_decode(ops.get_curve("sm2p256v1"), pub)
    passed = ops.sm2_verify(point, e, r, s)
    return ok({"valid": passed, "detail": "签名验证通过" if passed else "签名验证失败"})


# ---------------------------------------------------------------- PBKDF2

@bp.post("/pbkdf2")
def pbkdf2():
    p = _payload()
    password = _require_bytes(_data(p, "password", default_fmt="TEXT"), "口令 Password")
    salt = _require_bytes(_data(p, "salt", default_fmt="TEXT"), "盐值 Salt")
    times = _int_field(p.get("times"), "迭代次数", 1024, 1, ops.PBKDF2_MAX_TIMES)
    klen = _int_field(p.get("length"), "密钥长度", 32, 1, ops.MAX_KDF)
    out = ops.pbkdf2(password, salt, times, klen, p.get("type") or "SM3")
    return ok(format_bytes(out, p.get("resultFormat") or "HEX"))


# ---------------------------------------------------------------- 工作模式检测

@bp.post("/mode/detect")
def mode_detect():
    p = _payload()
    ct1 = _require_bytes(_data(p, "ciphertext1", default_fmt="HEX"), "密文 1")
    ct2 = _require_bytes(_data(p, "ciphertext2", default_fmt="HEX"), "密文 2")
    if len(ct1) != len(ct2):
        raise ToolError("两组密文长度必须一致")
    return ok(ops.detect_mode(ct1, ct2))
