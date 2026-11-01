"""非对称算法核心：SM2 / RSA / ECDSA / 公钥附件（Attach&Detach） / 曲线点压缩。

全部为本地真实计算，不访问网络、不落盘：

* SM2 —— GB/T 32918（曲线运算、KDF、C1C3C2 与 C1C2C3 加解密、Z 值与 e 值、
  签名/验签、R||S 与 DER 互转、同 k 签名反推私钥）
* RSA —— RFC 8017（PKCS#1 v1.5 / NoPadding / OAEP），密钥长度 1024~4096
* ECDSA —— SEC1 / ANSI X9.62（DER 签名），P-256/P-384/P-521/secp256k1 使用
  cryptography，SM2 曲线使用本文件的通用椭圆曲线运算
* Attach —— 把 SM2 公钥（04||X||Y）与用户标识拼成附件包，并支持 SM2 签名/验签
* Compress —— SEC1 2.3.3 点压缩/解压；SM9 曲线参数取自 GM/T 0044
  （模块加载时已自检：G1 生成元在曲线上、n·G1 = O）
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass

from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Hash import SHA1 as _SHA1
from Crypto.Hash import SHA224 as _SHA224
from Crypto.Hash import SHA256 as _SHA256
from Crypto.Hash import SHA384 as _SHA384
from Crypto.Hash import SHA512 as _SHA512
from Crypto.PublicKey import RSA as _RSAKey
from Crypto.Signature import pkcs1_15 as _pkcs1_15
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import rsa as _cryptorsa
from gmssl import func as _func
from gmssl import sm3 as _sm3

from .common import ToolError, parse_bytes

# ---------------------------------------------------------------------------
# SM3
# ---------------------------------------------------------------------------


def sm3_hash(data: bytes) -> bytes:
    """SM3 摘要（GB/T 32905），返回 32 字节。"""
    return bytes.fromhex(_sm3.sm3_hash(_func.bytes_to_list(data)))


# ---------------------------------------------------------------------------
# 通用椭圆曲线运算（仿射坐标，点用 (x, y) 元组表示，None 表示无穷远点 O）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    n: int
    gx: int
    gy: int
    size: int  # 坐标字节长度

    @property
    def g(self):
        return (self.gx, self.gy)


SM2_CURVE = Curve(
    name="sm2p256v1",
    p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
    gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
    size=32,
)

# GM/T 0044 SM9 曲线：y^2 = x^3 + 5
SM9_CURVE = Curve(
    name="SM9",
    p=int("B6400000" "02A3A6F1" "D603AB4F" "F58EC745" "21F2934B" "1A7AEEDB" "E56F9B27" "E351457D", 16),
    a=0,
    b=5,
    n=int("B6400000" "02A3A6F1" "D603AB4F" "F58EC744" "49F2934B" "18EA8BEE" "E56EE19C" "D69ECF25", 16),
    gx=int("93DE051D" "62BF718F" "F5ED0704" "487D01D6" "E1E40869" "09DC3280" "E8C4E481" "7C66DDDD", 16),
    gy=int("21FE8DDA" "4F21E607" "63106512" "5C395BBC" "1C1C00CB" "FA602435" "0C464CD7" "0A3EA616", 16),
    size=32,
)


def on_curve(curve: Curve, point) -> bool:
    if point is None:
        return False
    x, y = point
    if not (0 <= x < curve.p and 0 <= y < curve.p):
        return False
    return (y * y - (pow(x, 3, curve.p) + curve.a * x + curve.b)) % curve.p == 0


def point_add(curve: Curve, p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % curve.p == 0:
            return None
        lam = (3 * x1 * x1 + curve.a) % curve.p
        lam = lam * pow(2 * y1, -1, curve.p) % curve.p
    else:
        lam = (y2 - y1) % curve.p
        lam = lam * pow((x2 - x1) % curve.p, -1, curve.p) % curve.p
    x3 = (lam * lam - x1 - x2) % curve.p
    y3 = (lam * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def point_mul(curve: Curve, k: int, point):
    if point is None:
        return None
    k %= curve.n
    if k == 0:
        return None
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1
    return result


def random_scalar(n: int) -> int:
    return secrets.randbelow(n - 1) + 1


def _int_bytes(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def encode_point(point, compressed: bool = False) -> bytes:
    """SEC1 2.3.3 点编码。"""
    x, y = point
    if compressed:
        return bytes([2 + (y & 1)]) + _int_bytes(x, 32)
    return b"\x04" + _int_bytes(x, 32) + _int_bytes(y, 32)


# ---------------------------------------------------------------------------
# DER / PEM 基础编码
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def der_int(value: int) -> bytes:
    body = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return der_tlv(0x02, body)


def der_seq(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_octet(body: bytes) -> bytes:
    return der_tlv(0x04, body)


def der_bitstring(body: bytes) -> bytes:
    return der_tlv(0x03, b"\x00" + body)


def der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(chunk))
    return der_tlv(0x06, body)


OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_SM2 = "1.2.156.10197.1.301"


def read_tlv(data: bytes, off: int = 0):
    """读取一个 TLV，返回 (tag, body, next_offset)。"""
    if off + 2 > len(data):
        raise ToolError("ASN.1 数据不完整")
    tag = data[off]
    idx = off + 1
    first = data[idx]
    idx += 1
    if first == 0x80:
        raise ToolError("不支持 BER 不定长编码")
    if first & 0x80:
        cnt = first & 0x7F
        if cnt > 4 or idx + cnt > len(data):
            raise ToolError("ASN.1 长度字段非法")
        length = int.from_bytes(data[idx:idx + cnt], "big")
        idx += cnt
    else:
        length = first
    if idx + length > len(data):
        raise ToolError("ASN.1 数据长度不足")
    return tag, data[idx:idx + length], idx + length


def read_children(body: bytes):
    items = []
    off = 0
    while off < len(body):
        tag, val, off = read_tlv(body, off)
        items.append((tag, val))
    return items


def pem_encode(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (label, "\n".join(lines), label)


_PEM_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----(?P<body>[A-Za-z0-9+/=\s]+)-----END (?P=label)-----"
)


def pem_decode(text: str):
    m = _PEM_RE.search(text or "")
    if not m:
        raise ToolError("不是合法的 PEM 数据")
    body = re.sub(r"\s+", "", m.group("body"))
    try:
        return m.group("label"), base64.b64decode(body)
    except Exception:
        raise ToolError("PEM 内容解码失败")


def load_blob(value, fmt: str | None) -> bytes:
    """把 PEM / HEX / BASE64 文本转换成 DER 字节。"""
    text = "" if value is None else str(value)
    if "-----BEGIN" in text:
        return pem_decode(text)[1]
    fmt = (fmt or "HEX").upper()
    if fmt == "PEM":
        raise ToolError("PEM 格式内容缺少 -----BEGIN----- 头")
    return parse_bytes(text, fmt)


def dump_blob(der: bytes, fmt: str | None, label: str = "") -> str:
    fmt = (fmt or "HEX").upper()
    if fmt == "PEM":
        return pem_encode(label or "PUBLIC KEY", der)
    if fmt == "BASE64":
        return base64.b64encode(der).decode()
    if fmt in ("TEXT", "STR"):
        return pem_encode(label or "PUBLIC KEY", der)
    return der.hex().upper()


# ---------------------------------------------------------------------------
# SM2 密钥编解码（PKCS#8 私钥 / SubjectPublicKeyInfo 公钥）
# ---------------------------------------------------------------------------


def sm2_private_der(d: int, pub) -> bytes:
    ec_priv = der_seq(
        der_int(1),
        der_octet(_int_bytes(d, 32)),
        der_tlv(0xA0, der_oid(OID_SM2)),
        der_tlv(0xA1, der_bitstring(encode_point(pub))),
    )
    alg = der_seq(der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_SM2))
    return der_seq(der_int(0), alg, der_octet(ec_priv))


def sm2_public_der(pub) -> bytes:
    alg = der_seq(der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_SM2))
    return der_seq(alg, der_bitstring(encode_point(pub)))


def _parse_ec_private(der: bytes) -> int:
    tag, body, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ToolError("私钥 DER 结构非法（缺少 SEQUENCE）")
    items = read_children(body)
    if not items:
        raise ToolError("私钥 DER 结构为空")
    # PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING }
    if items[0][0] == 0x02 and len(items) >= 3 and items[2][0] == 0x04:
        inner = items[2][1]
        tag2, body2, _ = read_tlv(inner, 0)
        if tag2 != 0x30:
            raise ToolError("PKCS#8 内部私钥结构非法")
        items = read_children(body2)
    if len(items) < 2 or items[1][0] != 0x04:
        raise ToolError("私钥 DER 中未找到私钥值")
    raw = items[1][1]
    if not 1 <= len(raw) <= 32:
        raise ToolError("SM2 私钥长度非法")
    d = int.from_bytes(raw, "big")
    if not 1 <= d < SM2_CURVE.n:
        raise ToolError("SM2 私钥不在 [1, n-1] 范围内")
    return d


def _scan_spki(der: bytes):
    """在任意 DER（证书 / SPKI）中查找 SM2 或 EC 公钥比特串。"""
    out = []

    def walk(tag: int, body: bytes, depth: int):
        if depth > 12 or len(out) > 4:
            return
        if tag == 0x30:
            try:
                items = read_children(body)
            except ToolError:
                return
            if len(items) == 2 and items[0][0] == 0x30 and items[1][0] == 0x03:
                oids = []
                try:
                    for t2, v2 in read_children(items[0][1]):
                        if t2 == 0x06:
                            oids.append(_oid_to_str(v2))
                except ToolError:
                    oids = []
                if any(o in (OID_SM2, OID_EC_PUBLIC_KEY) for o in oids):
                    out.append((oids, items[1][1]))
            for t2, v2 in items:
                walk(t2, v2, depth + 1)

    walk(0x30, read_tlv(der, 0)[1] if der else b"", 0)
    return out


def _oid_to_str(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def parse_sm2_public(value, fmt: str | None = "HEX"):
    """解析 SM2 公钥：04||X||Y / X||Y / 02|03||X / PEM / DER。"""
    text = "" if value is None else str(value)
    if not text.strip():
        raise ToolError("请输入 SM2 公钥")
    if "-----BEGIN" in text:
        der = load_blob(text, "PEM")
        tag, body, _ = read_tlv(der, 0)
        if tag == 0x30:
            found = _scan_spki(der)
            if found:
                raw = found[0][1]
                raw = raw[1:] if raw[:1] == b"\x00" else raw
                return _decode_point_bytes(raw, SM2_CURVE)
            items = read_children(body)
            if len(items) == 2 and items[1][0] == 0x03:
                raw = items[1][1]
                raw = raw[1:] if raw[:1] == b"\x00" else raw
                return _decode_point_bytes(raw, SM2_CURVE)
        raise ToolError("DER 中未找到 SM2 公钥")
    raw = parse_bytes(text, fmt)
    return _decode_point_bytes(raw, SM2_CURVE)


def _decode_point_bytes(raw: bytes, curve: Curve):
    size = curve.size
    if len(raw) == 1 + 2 * size and raw[0] == 4:
        point = (int.from_bytes(raw[1:1 + size], "big"), int.from_bytes(raw[1 + size:], "big"))
    elif len(raw) == 2 * size:
        point = (int.from_bytes(raw[:size], "big"), int.from_bytes(raw[size:], "big"))
    elif len(raw) == 1 + size and raw[0] in (2, 3):
        point = decompress_point(curve, raw)
    else:
        raise ToolError(
            "公钥长度非法：应为 04||X||Y（65 字节）、X||Y（64 字节）或 02/03||X（33 字节）"
        )
    if not on_curve(curve, point):
        raise ToolError("公钥不在曲线上，请检查数据")
    return point


def parse_sm2_private(value, fmt: str | None = "HEX") -> int:
    text = "" if value is None else str(value)
    if not text.strip():
        raise ToolError("请输入 SM2 私钥")
    if "-----BEGIN" in text or (fmt or "").upper() == "PEM":
        der = load_blob(text, fmt)
        return _parse_ec_private(der)
    raw = parse_bytes(text, fmt)
    if len(raw) == 32:
        d = int.from_bytes(raw, "big")
    elif raw[:1] == b"\x30":
        return _parse_ec_private(raw)
    else:
        raise ToolError("SM2 私钥长度非法：应为 32 字节")
    if not 1 <= d < SM2_CURVE.n:
        raise ToolError("SM2 私钥不在 [1, n-1] 范围内")
    return d


def sm2_keypair():
    d = random_scalar(SM2_CURVE.n)
    pub = point_mul(SM2_CURVE, d, SM2_CURVE.g)
    return d, pub


# --- 密钥文本表示（与原站一致：HEX 为大写、公钥不带 04 前缀） ---------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def sm2_public_str(pub, fmt: str | None = "HEX") -> str:
    fmt = (fmt or "HEX").upper()
    if fmt == "PEM":
        return pem_encode("PUBLIC KEY", sm2_public_der(pub))
    if fmt == "BASE64":
        return _b64(encode_point(pub)[1:])
    return encode_point(pub)[1:].hex().upper()


def sm2_private_str(d: int, fmt: str | None = "HEX") -> str:
    fmt = (fmt or "HEX").upper()
    pub = point_mul(SM2_CURVE, d, SM2_CURVE.g)
    if fmt == "PEM":
        return pem_encode("PRIVATE KEY", sm2_private_der(d, pub))
    if fmt == "BASE64":
        return _b64(_int_bytes(d, 32))
    return _int_bytes(d, 32).hex().upper()


# ---------------------------------------------------------------------------
# SM2 加解密（GB/T 32918.4）
# ---------------------------------------------------------------------------


def _kdf(z: bytes, klen: int) -> bytes:
    out = b""
    ct = 1
    while len(out) < klen:
        out += sm3_hash(z + ct.to_bytes(4, "big"))
        ct += 1
    return out[:klen]


def _normalize_cipher_mode(mode: str | None) -> str:
    mode = (mode or "C1C3C2").upper().replace("||", "").replace("-", "").replace("_", "")
    if mode in ("C1C3C2", "C1C3C2MODE", "C1C3C2ORDER"):
        return "C1C3C2"
    if mode in ("C1C2C3", "C1C2C3MODE"):
        return "C1C2C3"
    raise ToolError(f"不支持的密文次序：{mode}，仅支持 C1C3C2 / C1C2C3")


def sm2_encrypt(pub, message: bytes, mode: str = "C1C3C2") -> bytes:
    mode = _normalize_cipher_mode(mode)
    if not on_curve(SM2_CURVE, pub):
        raise ToolError("公钥不在曲线上，无法加密")
    klen = len(message)
    if klen == 0:
        raise ToolError("待加密消息不能为空")
    for _ in range(64):
        k = random_scalar(SM2_CURVE.n)
        c1 = point_mul(SM2_CURVE, k, SM2_CURVE.g)
        shared = point_mul(SM2_CURVE, k, pub)
        if shared is None:
            continue
        x2 = _int_bytes(shared[0], 32)
        y2 = _int_bytes(shared[1], 32)
        t = _kdf(x2 + y2, klen)
        if not any(t):
            continue
        c2 = bytes(a ^ b for a, b in zip(message, t))
        c3 = sm3_hash(x2 + message + y2)
        c1_bytes = encode_point(c1)
        if mode == "C1C3C2":
            return c1_bytes + c3 + c2
        return c1_bytes + c2 + c3
    raise ToolError("SM2 加密失败：KDF 输出全零，请重试")


def _try_sm2_decrypt(d: int, body: bytes, mode: str, c1_len: int):
    if len(body) < c1_len + 32:
        return None
    c1_bytes = body[:c1_len]
    point = _decode_point_bytes(c1_bytes, SM2_CURVE)
    rest = body[c1_len:]
    if mode == "C1C3C2":
        c3, c2 = rest[:32], rest[32:]
    else:
        c2, c3 = rest[:-32], rest[-32:]
    shared = point_mul(SM2_CURVE, d, point)
    if shared is None:
        return None
    x2 = _int_bytes(shared[0], 32)
    y2 = _int_bytes(shared[1], 32)
    t = _kdf(x2 + y2, len(c2))
    if not any(t):
        return None
    message = bytes(a ^ b for a, b in zip(c2, t))
    if sm3_hash(x2 + message + y2) != c3:
        return None
    return message


def sm2_decrypt(d: int, cipher: bytes, mode: str = "C1C3C2") -> bytes:
    mode = _normalize_cipher_mode(mode)
    if not 1 <= d < SM2_CURVE.n:
        raise ToolError("SM2 私钥不在 [1, n-1] 范围内")
    data = cipher
    if len(data) < 96:
        raise ToolError("SM2 密文长度不足（至少 96 字节）")
    if data[:1] == b"\x30":
        data = sm2_cipher_from_der(data, mode)
    for c1_len in (65, 64):
        if data[:1] == b"\x04" and c1_len == 64:
            continue
        try:
            out = _try_sm2_decrypt(d, data, mode, c1_len)
        except ToolError:
            out = None
        if out is not None:
            return out
    raise ToolError("SM2 解密失败：密文次序/密钥不匹配，或密文已被篡改")


def sm2_cipher_to_der(raw: bytes, mode: str = "C1C3C2") -> bytes:
    mode = _normalize_cipher_mode(mode)
    if raw[:1] == b"\x30":
        return raw
    # 裸密文 C1 可能带 04 前缀（65 字节）也可能不带（64 字节）
    head = 65 if (len(raw) >= 65 and raw[0] == 0x04) else 64
    point = _decode_point_bytes(raw[:head], SM2_CURVE)
    rest = raw[head:]
    if mode == "C1C3C2":
        c3, c2 = rest[:32], rest[32:]
        parts = (c3, c2)
    else:
        c2, c3 = rest[:-32], rest[-32:]
        parts = (c2, c3)
    return der_seq(der_int(point[0]), der_int(point[1]),
                   der_octet(parts[0]), der_octet(parts[1]))


def sm2_cipher_from_der(der: bytes, mode: str = "C1C3C2") -> bytes:
    mode = _normalize_cipher_mode(mode)
    tag, body, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ToolError("密文 DER 结构非法")
    items = read_children(body)
    if len(items) < 4 or items[0][0] != 0x02 or items[1][0] != 0x02:
        raise ToolError("密文 DER 结构非法（缺少 C1 坐标）")
    x = int.from_bytes(items[0][1], "big")
    y = int.from_bytes(items[1][1], "big")
    # DER 中第三/第四段与裸密文顺序一致
    if mode == "C1C3C2":
        c3, c2 = items[2][1], items[3][1]
    else:
        c2, c3 = items[2][1], items[3][1]
    if not on_curve(SM2_CURVE, (x, y)):
        raise ToolError("密文 C1 点不在曲线上")
    if len(c3) != 32:
        raise ToolError("密文 C3 长度必须为 32 字节")
    c1 = encode_point((x, y))[1:]
    return c1 + (c3 + c2 if mode == "C1C3C2" else c2 + c3)


# ---------------------------------------------------------------------------
# SM2 Z 值 / e 值 / 签名验签
# ---------------------------------------------------------------------------


def sm2_z(pub, user_id: bytes = b"1234567812345678") -> bytes:
    if len(user_id) * 8 > 0xFFFF:
        raise ToolError("用户标识过长")
    entl = (len(user_id) * 8).to_bytes(2, "big")
    curve = SM2_CURVE
    buf = (
        entl
        + user_id
        + _int_bytes(curve.a, 32)
        + _int_bytes(curve.b, 32)
        + _int_bytes(curve.gx, 32)
        + _int_bytes(curve.gy, 32)
        + _int_bytes(pub[0], 32)
        + _int_bytes(pub[1], 32)
    )
    return sm3_hash(buf)


def sm2_e(pub, message: bytes, user_id: bytes = b"1234567812345678") -> tuple[bytes, bytes]:
    z = sm2_z(pub, user_id)
    return z, sm3_hash(z + message)


def _to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")


def sm2_sign_digest(d: int, e: bytes, k: int | None = None):
    if len(e) != 32:
        raise ToolError("e 值长度必须为 32 字节")
    if not 1 <= d < SM2_CURVE.n:
        raise ToolError("SM2 私钥不在 [1, n-1] 范围内")
    e_int = _to_int(e)
    for _ in range(64):
        kk = k or random_scalar(SM2_CURVE.n)
        point = point_mul(SM2_CURVE, kk, SM2_CURVE.g)
        r = (e_int + point[0]) % SM2_CURVE.n
        if r == 0 or r + kk == SM2_CURVE.n:
            if k:
                raise ToolError("该随机数 k 不适用于当前消息，请更换")
            continue
        s = (pow(1 + d, -1, SM2_CURVE.n) * (kk - r * d)) % SM2_CURVE.n
        if s == 0:
            if k:
                raise ToolError("该随机数 k 不适用于当前消息，请更换")
            continue
        return r, s
    raise ToolError("SM2 签名失败，请重试")


def sm2_verify_digest(pub, e: bytes, r: int, s: int) -> bool:
    n = SM2_CURVE.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    if not on_curve(SM2_CURVE, pub):
        raise ToolError("公钥不在曲线上")
    t = (r + s) % n
    if t == 0:
        return False
    p1 = point_mul(SM2_CURVE, s, SM2_CURVE.g)
    p2 = point_mul(SM2_CURVE, t, pub)
    point = point_add(SM2_CURVE, p1, p2)
    if point is None:
        return False
    return (_to_int(e) + point[0]) % n == r


def rs_to_der(r: int, s: int) -> bytes:
    return der_seq(der_int(r), der_int(s))


def der_to_rs(der: bytes) -> tuple[int, int]:
    tag, body, _ = read_tlv(der, 0)
    if tag != 0x30:
        raise ToolError("签名 DER 结构非法")
    items = read_children(body)
    if len(items) != 2 or items[0][0] != 0x02 or items[1][0] != 0x02:
        raise ToolError("签名 DER 结构非法（应为 SEQUENCE { INTEGER r, INTEGER s }）")
    return int.from_bytes(items[0][1], "big"), int.from_bytes(items[1][1], "big")


def parse_signature(raw: bytes) -> tuple[int, int]:
    """R||S（64 字节）或 DER SEQUENCE 签名 → (r, s)。"""
    if not raw:
        raise ToolError("请输入签名值")
    if raw[:1] == b"\x30":
        r, s = der_to_rs(raw)
    elif len(raw) == 64:
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
    else:
        raise ToolError("签名值格式非法：应为 64 字节 R||S 或 DER 编码")
    return r, s


def sm2_recover_private_key(e1: bytes, sig1, e2: bytes, sig2):
    """同一随机数 k 生成两条签名时反推私钥。

    SM2 签名：r = (e + x1) mod n，s = (1+d)^-1 (k - r d) mod n。
    当两条签名使用同一个 k 时，x1 相同，因此 r1 - r2 = e1 - e2，
    由 (1+d)(s1-s2) = -d(e1-e2) 可得：
        d = -(s1-s2) / ((e1-e2) + (s1-s2)) mod n
    再回代求 k = s1 (1+d) + r1 d mod n。
    """
    r1, s1 = sig1
    r2, s2 = sig2
    n = SM2_CURVE.n
    num = (s2 - s1) % n
    den = ((_to_int(e1) - _to_int(e2)) + (s1 - s2)) % n
    if den == 0:
        raise ToolError("两条签名不满足同一随机数的关系式（分母为 0），无法反推私钥")
    if num == 0:
        raise ToolError("两条签名的 s 相同，说明使用了不同的随机数 k，无法反推私钥")
    d = num * pow(den, -1, n) % n
    if not 1 <= d < n:
        raise ToolError("反推得到的私钥不在合法范围，签名数据可能不匹配")
    k = (s1 * (1 + d) + r1 * d) % n
    if k == 0:
        raise ToolError("无法反推随机数 k")
    return d, k


# ---------------------------------------------------------------------------
# 曲线点压缩 / 解压（SEC1 2.3.3）
# ---------------------------------------------------------------------------


def _tonelli_shanks(value: int, p: int) -> int | None:
    """求解 y^2 = value (mod p)。"""
    value %= p
    if value == 0:
        return 0
    if pow(value, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(value, (p + 1) // 4, p)
    # p - 1 = q * 2^s
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(value, q, p)
    r = pow(value, (q + 1) // 2, p)
    while t != 1:
        i = 0
        t2 = t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = b * b % p
        t = t * c % p
        r = r * b % p
    return r


def sqrt_mod(value: int, p: int) -> int | None:
    return _tonelli_shanks(value, p)


def compress_point(curve: Curve, raw: bytes) -> bytes:
    size = curve.size
    if len(raw) == 1 + 2 * size and raw[0] == 0x04:
        point = (int.from_bytes(raw[1:1 + size], "big"), int.from_bytes(raw[1 + size:], "big"))
    elif len(raw) == 2 * size:
        point = (int.from_bytes(raw[:size], "big"), int.from_bytes(raw[size:], "big"))
    elif len(raw) == 1 + size and raw[0] in (0x02, 0x03):
        raise ToolError("输入已经是压缩公钥（02/03 开头），请使用解压功能")
    else:
        raise ToolError(
            f"未压缩公钥长度非法：应为 04||X||Y（{1 + 2 * size} 字节），当前 {len(raw)} 字节"
        )
    if not on_curve(curve, point):
        raise ToolError("公钥不在曲线上，无法压缩")
    return bytes([0x02 + (point[1] & 1)]) + _int_bytes(point[0], size)


def decompress_point(curve: Curve, raw: bytes) -> tuple[int, int]:
    size = curve.size
    if len(raw) == 1 + 2 * size and raw[0] == 0x04:
        raise ToolError("输入已经是未压缩公钥（04 开头），请使用压缩功能")
    if len(raw) != 1 + size or raw[0] not in (0x02, 0x03):
        raise ToolError(
            f"压缩公钥长度非法：应为 02/03||X（{1 + size} 字节），当前 {len(raw)} 字节"
        )
    x = int.from_bytes(raw[1:], "big")
    if not 0 <= x < curve.p:
        raise ToolError("压缩公钥的 X 坐标超出域范围")
    rhs = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
    y = sqrt_mod(rhs, curve.p)
    if y is None:
        raise ToolError("该 X 坐标在曲线上无对应点（不是合法压缩公钥）")
    if (y & 1) != (raw[0] & 1):
        y = curve.p - y
    point = (x, y)
    if not on_curve(curve, point):
        raise ToolError("解压结果不在曲线上，请检查输入")
    return point


# ---------------------------------------------------------------------------
# RSA（RFC 8017）
# ---------------------------------------------------------------------------

_RSA_HASHES = {
    "SHA1": (_SHA1, _hashes.SHA1),
    "SHA224": (_SHA224, _hashes.SHA224),
    "SHA256": (_SHA256, _hashes.SHA256),
    "SHA384": (_SHA384, _hashes.SHA384),
    "SHA512": (_SHA512, _hashes.SHA512),
}

_RSA_SIGN_ALIAS = {
    "SHA1WITHRSA": "SHA1",
    "SHA224WITHRSA": "SHA224",
    "SHA256WITHRSA": "SHA256",
    "SHA384WITHRSA": "SHA384",
    "SHA512WITHRSA": "SHA512",
    "SHA1": "SHA1",
    "SHA224": "SHA224",
    "SHA256": "SHA256",
    "SHA384": "SHA384",
    "SHA512": "SHA512",
}

_RSA_FILL_ALIAS = {
    "RSA/ECB/PKCS1PADDING": "PKCS1",
    "PKCS1": "PKCS1",
    "PKCS1PADDING": "PKCS1",
    "PKCS1V15": "PKCS1",
    "PKCS1_V1_5": "PKCS1",
    "RSA/ECB/NOPADDING": "NONE",
    "NOPADDING": "NONE",
    "RAW": "NONE",
    "RSA/ECB/OAEPPADDING": "OAEP-SHA1",
    "RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING": "OAEP-SHA1",
    "OAEP-SHA1": "OAEP-SHA1",
    "OAEP": "OAEP-SHA1",
    "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING": "OAEP-SHA256",
    "OAEP-SHA256": "OAEP-SHA256",
    "RSA/ECB/OAEPWITHSHA-384ANDMGF1PADDING": "OAEP-SHA384",
    "OAEP-SHA384": "OAEP-SHA384",
    "RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING": "OAEP-SHA512",
    "OAEP-SHA512": "OAEP-SHA512",
}

_OAEP_HASH = {
    "OAEP-SHA1": _SHA1,
    "OAEP-SHA256": _SHA256,
    "OAEP-SHA384": _SHA384,
    "OAEP-SHA512": _SHA512,
}


def _norm_token(value: str | None) -> str:
    return re.sub(r"[\s]", "", (value or "")).upper()


def resolve_rsa_fill(fill: str | None) -> str:
    key = _norm_token(fill)
    if not key:
        return "PKCS1"
    if "ISO9796" in key:
        raise ToolError("暂不支持 ISO9796-1 填充方式")
    if "OAEPWITHMD5" in key:
        raise ToolError("暂不支持 OAEP-MD5 填充方式")
    if "PSS" in key:
        raise ToolError("暂不支持 PSS 填充方式，请使用 PKCS#1 v1.5")
    for alias, target in _RSA_FILL_ALIAS.items():
        if _norm_token(alias) == key:
            return target
    raise ToolError(f"不支持的 RSA 填充方式：{fill}")


def resolve_rsa_hash(name: str | None) -> str:
    key = _norm_token(name)
    if not key:
        return "SHA256"
    if "PSS" in key:
        raise ToolError("暂不支持 RSASSA-PSS，请使用 PKCS#1 v1.5 签名")
    if key.startswith("MD2") or key.startswith("MD5"):
        raise ToolError("暂不支持 MD2/MD5 签名算法")
    if "SHA3-" in key or "SHA3_" in key:
        raise ToolError("暂不支持 SHA3 系列 RSA 签名算法")
    for alias, target in _RSA_SIGN_ALIAS.items():
        if alias == key:
            return target
    raise ToolError(f"不支持的签名算法：{name}")


def rsa_keypair(bits: int = 2048):
    try:
        bits = int(bits)
    except (TypeError, ValueError):
        raise ToolError("密钥长度必须为整数")
    if bits not in (1024, 2048, 3072, 4096):
        raise ToolError("密钥长度仅支持 1024 / 2048 / 3072 / 4096 位")
    key = _RSAKey.generate(bits, e=65537)
    return key


def rsa_private_der(key) -> bytes:
    return key.export_key(format="DER", pkcs=8)


def rsa_public_der(key) -> bytes:
    pub = key.public_key()
    return pub.export_key(format="DER")


def parse_rsa_private(value, fmt: str | None = "HEX"):
    data = load_blob(value, fmt)
    try:
        return _RSAKey.import_key(data)
    except (ValueError, IndexError, TypeError):
        raise ToolError("RSA 私钥解析失败：请确认数据为 PKCS#1 或 PKCS#8 的 DER/PEM")


def parse_rsa_public(value, fmt: str | None = "HEX"):
    data = load_blob(value, fmt)
    try:
        key = _RSAKey.import_key(data)
    except (ValueError, IndexError, TypeError):
        raise ToolError("RSA 公钥解析失败：请确认数据为 X.509/PKCS#1 的 DER/PEM")
    if key.has_private():
        raise ToolError("该数据是私钥，请提供公钥")
    return key


def rsa_encrypt(pub, message: bytes, fill: str | None) -> bytes:
    mode = resolve_rsa_fill(fill)
    size = pub.size_in_bytes()
    if not message:
        raise ToolError("待加密消息不能为空")
    if mode == "PKCS1":
        if len(message) > size - 11:
            raise ToolError(f"消息过长：PKCS#1 v1.5 最多 {size - 11} 字节，当前 {len(message)} 字节")
        return PKCS1_v1_5.new(pub).encrypt(message)
    if mode.startswith("OAEP"):
        h = _OAEP_HASH[mode]
        limit = size - 2 * h.digest_size - 2
        if len(message) > limit:
            raise ToolError(f"消息过长：{mode} 最多 {limit} 字节，当前 {len(message)} 字节")
        return PKCS1_OAEP.new(pub, hashAlgo=h).encrypt(message)
    if len(message) > size:
        raise ToolError(f"消息过长：NoPadding 最多 {size} 字节，当前 {len(message)} 字节")
    m = int.from_bytes(message.rjust(size, b"\x00"), "big")
    return pow(m, pub.e, pub.n).to_bytes(size, "big")


def rsa_decrypt(priv, cipher: bytes, fill: str | None) -> bytes:
    mode = resolve_rsa_fill(fill)
    size = priv.size_in_bytes()
    if len(cipher) != size:
        raise ToolError(f"密文长度必须等于密钥模长 {size} 字节，当前 {len(cipher)} 字节")
    if mode == "PKCS1":
        sentinel = b"\x00INVALID\x00"
        out = PKCS1_v1_5.new(priv).decrypt(cipher, sentinel)
        if out == sentinel or out is None:
            raise ToolError("解密失败：填充校验不通过（私钥不匹配或密文损坏）")
        return out
    if mode.startswith("OAEP"):
        h = _OAEP_HASH[mode]
        try:
            return PKCS1_OAEP.new(priv, hashAlgo=h).decrypt(cipher)
        except ValueError:
            raise ToolError("解密失败：OAEP 填充校验不通过（私钥不匹配或密文损坏）")
    m = pow(int.from_bytes(cipher, "big"), priv.d, priv.n)
    return m.to_bytes(size, "big").lstrip(b"\x00")


def rsa_sign(priv, message: bytes, sign_hash: str | None) -> bytes:
    name = resolve_rsa_hash(sign_hash)
    digest_mod, _ = _RSA_HASHES[name]
    h = digest_mod.new(message)
    try:
        return _pkcs1_15.new(priv).sign(h)
    except (ValueError, TypeError):
        raise ToolError("RSA 签名失败")


def rsa_verify(pub, message: bytes, signature: bytes, sign_hash: str | None) -> bool:
    name = resolve_rsa_hash(sign_hash)
    digest_mod, _ = _RSA_HASHES[name]
    h = digest_mod.new(message)
    try:
        _pkcs1_15.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


# ---------------------------------------------------------------------------
# 公钥提取（证书 / SPKI / 私钥）
# ---------------------------------------------------------------------------


def extract_public_key_der(data: bytes) -> tuple[str, bytes | None]:
    """从证书或公钥/私钥数据中提取公钥，返回 (类型, DER 或 SM2 点字节)。"""
    # 1) 标准 X.509 证书（RSA / NIST 曲线）
    try:
        cert = x509.load_der_x509_certificate(data)
        pub = cert.public_key()
        return _classify_public_key(pub)
    except Exception:
        pass
    # 2) 公钥/私钥 DER
    try:
        key = _RSAKey.import_key(data)
        return "RSA", key.public_key().export_key(format="DER")
    except Exception:
        pass
    try:
        pub = _serialization.load_der_public_key(data)
        return _classify_public_key(pub)
    except Exception:
        pass
    try:
        priv = _serialization.load_der_private_key(data, password=None)
        return _classify_public_key(priv.public_key())
    except Exception:
        pass
    # 3) 自建 ASN.1 扫描（SM2 证书 / SPKI）
    try:
        found = _scan_spki(data)
    except ToolError:
        found = []
    for oids, bit in found:
        raw = bit[1:] if bit[:1] == b"\x00" else bit
        if any(o == OID_SM2 for o in oids) and len(raw) == 65 and raw[0] == 4:
            if on_curve(SM2_CURVE, (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big"))):
                return "SM2", raw
    raise ToolError("未能从该数据中提取公钥：请提供 X.509 证书、SPKI 公钥或 RSA 私钥")


def _classify_public_key(pub) -> tuple[str, bytes]:
    if isinstance(pub, _RSAKey.RsaKey):
        return "RSA", pub.export_key(format="DER")
    if isinstance(pub, _cryptorsa.RSAPublicKey):
        return "RSA", pub.public_bytes(
            _serialization.Encoding.DER, _serialization.PublicFormat.SubjectPublicKeyInfo)
    der = pub.public_bytes(_serialization.Encoding.DER, _serialization.PublicFormat.SubjectPublicKeyInfo)
    return "EC", der


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------

_EC_CURVES = {
    "secp256r1": _ec.SECP256R1,
    "secp384r1": _ec.SECP384R1,
    "secp521r1": _ec.SECP521R1,
    "secp256k1": _ec.SECP256K1,
}

_ECDSA_HASH_ALIAS = {
    "SHA1": "SHA1",
    "SHA-1": "SHA1",
    "SHA224": "SHA224",
    "SHA-224": "SHA224",
    "SHA256": "SHA256",
    "SHA-256": "SHA256",
    "SHA384": "SHA384",
    "SHA-384": "SHA384",
    "SHA512": "SHA512",
    "SHA-512": "SHA512",
}

_ECDSA_HASH_OBJ = {
    "SHA1": (_hashes.SHA1, _SHA1),
    "SHA224": (_hashes.SHA224, _SHA224),
    "SHA256": (_hashes.SHA256, _SHA256),
    "SHA384": (_hashes.SHA384, _SHA384),
    "SHA512": (_hashes.SHA512, _SHA512),
}

EC_CURVE_LABEL = {
    "secp256r1": "secp256r1 (P-256)",
    "secp384r1": "secp384r1 (P-384)",
    "secp521r1": "secp521r1 (P-521)",
    "secp256k1": "secp256k1",
    "SM2": "SM2（sm2p256v1）",
}


def resolve_ec_curve(name: str | None) -> str:
    key = (name or "secp256r1").strip()
    lowered = key.lower()
    if lowered in _EC_CURVES:
        return lowered
    if lowered in ("sm2", "sm2p256v1"):
        return "SM2"
    if lowered in ("p-256", "prime256v1", "secp256r1"):
        return "secp256r1"
    if lowered in ("p-384", "secp384r1"):
        return "secp384r1"
    if lowered in ("p-521", "secp521r1"):
        return "secp521r1"
    raise ToolError(f"不支持的椭圆曲线：{name}")


def resolve_ec_hash(name: str | None) -> str:
    key = (name or "SHA256").strip()
    for alias, target in _ECDSA_HASH_ALIAS.items():
        if alias.upper() == key.upper():
            return target
    raise ToolError(f"不支持的哈希算法：{name}")


def ecdsa_keypair(curve_name: str):
    curve_name = resolve_ec_curve(curve_name)
    if curve_name == "SM2":
        d, pub = sm2_keypair()
        return "SM2", d, pub
    priv = _ec.generate_private_key(_EC_CURVES[curve_name]())
    return curve_name, priv, priv.public_key()


def ecdsa_private_der(obj) -> bytes:
    if isinstance(obj, int):
        pub = point_mul(SM2_CURVE, obj, SM2_CURVE.g)
        return sm2_private_der(obj, pub)
    return obj.private_bytes(
        _serialization.Encoding.DER,
        _serialization.PrivateFormat.PKCS8,
        _serialization.NoEncryption(),
    )


def ecdsa_public_der(obj) -> bytes:
    if isinstance(obj, int):
        obj = point_mul(SM2_CURVE, obj, SM2_CURVE.g)
    if isinstance(obj, (tuple, list)):
        return sm2_public_der(tuple(obj))
    return obj.public_bytes(_serialization.Encoding.DER, _serialization.PublicFormat.SubjectPublicKeyInfo)


def parse_ecdsa_private(value, fmt: str | None, curve_name: str):
    curve_name = resolve_ec_curve(curve_name)
    data = load_blob(value, fmt)
    if curve_name == "SM2":
        if len(data) == 32:
            d = int.from_bytes(data, "big")
            if not 1 <= d < SM2_CURVE.n:
                raise ToolError("SM2 私钥不在 [1, n-1] 范围内")
            return d
        return _parse_ec_private(data)
    priv = None
    if data[:1] == b"\x30":
        try:
            priv = _serialization.load_der_private_key(data, password=None)
        except Exception:
            priv = None
    if priv is None:
        d = int.from_bytes(data, "big")
        priv = _priv_from_scalar(curve_name, d)
    if not isinstance(priv, _ec.EllipticCurvePrivateKey):
        raise ToolError("该私钥不是椭圆曲线私钥")
    return priv


_EC_SIZE = {"secp256r1": 32, "secp384r1": 48, "secp521r1": 66, "secp256k1": 32}


def _priv_from_scalar(curve_name: str, d: int):
    size = _EC_SIZE[curve_name]
    if d <= 0 or d.bit_length() > size * 8:
        raise ToolError("ECDSA 私钥数值超出曲线范围")
    try:
        return _ec.derive_private_key(d, _EC_CURVES[curve_name]())
    except ValueError:
        raise ToolError("ECDSA 私钥不在曲线阶范围内")


def ec_public_str(pub, curve_name: str, fmt: str | None = "HEX") -> str:
    fmt = (fmt or "HEX").upper()
    if isinstance(pub, (tuple, list)):
        raw = encode_point(tuple(pub))[1:]
    else:
        raw = pub.public_bytes(
            _serialization.Encoding.X962, _serialization.PublicFormat.UncompressedPoint
        )[1:]
    if fmt == "PEM":
        return pem_encode("PUBLIC KEY", ecdsa_public_der(pub))
    if fmt == "BASE64":
        return _b64(raw)
    return raw.hex().upper()


def ec_private_str(priv, curve_name: str, fmt: str | None = "HEX") -> str:
    fmt = (fmt or "HEX").upper()
    if isinstance(priv, int):
        d, size = priv, 32
    else:
        d = priv.private_numbers().private_value
        size = (priv.curve.key_size + 7) // 8
    if fmt == "PEM":
        return pem_encode("PRIVATE KEY", ecdsa_private_der(priv))
    if fmt == "BASE64":
        return _b64(_int_bytes(d, size))
    return _int_bytes(d, size).hex().upper()


def parse_ecdsa_public(value, fmt: str | None, curve_name: str):
    curve_name = resolve_ec_curve(curve_name)
    text = "" if value is None else str(value)
    if curve_name == "SM2":
        return parse_sm2_public(text, fmt)
    if "-----BEGIN" in text:
        data = load_blob(text, "PEM")
    else:
        data = parse_bytes(text, fmt)
    # 1) DER SPKI / 证书
    try:
        pub = _serialization.load_der_public_key(data)
        if isinstance(pub, _ec.EllipticCurvePublicKey):
            return pub
    except Exception:
        pass
    # 2) 裸点（04||X||Y 或 X||Y）
    size = _EC_SIZE[curve_name]
    raw = None
    if len(data) == 1 + 2 * size and data[0] == 0x04:
        raw = data
    elif len(data) == 2 * size:
        raw = b"\x04" + data
    elif len(data) == 1 + size and data[0] in (2, 3):
        raw = data
    if raw is None:
        raise ToolError("ECDSA 公钥格式非法：应为 04||X||Y、X||Y、PEM 或 SPKI DER")
    der = der_seq(
        der_seq(der_oid(OID_EC_PUBLIC_KEY), der_oid(_curve_oid(curve_name))),
        der_bitstring(raw),
    )
    try:
        pub = _serialization.load_der_public_key(der)
    except Exception:
        raise ToolError("ECDSA 公钥解析失败：请确认公钥与所选曲线一致")
    return pub


def _curve_oid(curve_name: str) -> str:
    return {
        "secp256r1": "1.2.840.10045.3.1.7",
        "secp384r1": "1.3.132.0.34",
        "secp521r1": "1.3.132.0.35",
        "secp256k1": "1.3.132.0.10",
        "SM2": OID_SM2,
    }[curve_name]


def _sm2_ecdsa_sign(d: int, digest: bytes):
    """在 SM2 曲线上做标准 ECDSA（不含 Z 值），哈希直接作为 e。"""
    n = SM2_CURVE.n
    h = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:
        h >>= excess
    for _ in range(64):
        k = random_scalar(n)
        point = point_mul(SM2_CURVE, k, SM2_CURVE.g)
        r = point[0] % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (h + r * d)) % n
        if s == 0:
            continue
        return r, s
    raise ToolError("ECDSA 签名失败，请重试")


def _sm2_ecdsa_verify(pub, digest: bytes, r: int, s: int) -> bool:
    n = SM2_CURVE.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    h = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - n.bit_length()
    if excess > 0:
        h >>= excess
    w = pow(s, -1, n)
    u1 = h * w % n
    u2 = r * w % n
    point = point_add(SM2_CURVE, point_mul(SM2_CURVE, u1, SM2_CURVE.g),
                      point_mul(SM2_CURVE, u2, pub))
    if point is None:
        return False
    return point[0] % n == r


def ecdsa_sign(priv, message: bytes, curve_name: str, hash_name: str) -> bytes:
    curve_name = resolve_ec_curve(curve_name)
    hash_name = resolve_ec_hash(hash_name)
    digest = hashlib.new(hash_name.lower(), message).digest()
    if curve_name == "SM2":
        d = priv if isinstance(priv, int) else None
        if d is None:
            raise ToolError("SM2 曲线私钥无效")
        r, s = _sm2_ecdsa_sign(d, digest)
        return rs_to_der(r, s)
    try:
        return priv.sign(message, _ec.ECDSA(_ECDSA_HASH_OBJ[hash_name][0]()))
    except Exception:
        raise ToolError("ECDSA 签名失败")


def ecdsa_verify(pub, message: bytes, signature: bytes, curve_name: str, hash_name: str) -> bool:
    curve_name = resolve_ec_curve(curve_name)
    hash_name = resolve_ec_hash(hash_name)
    if curve_name == "SM2":
        digest = hashlib.new(hash_name.lower(), message).digest()
        try:
            r, s = der_to_rs(signature)
        except ToolError:
            return False
        return _sm2_ecdsa_verify(pub, digest, r, s)
    try:
        pub.verify(signature, message, _ec.ECDSA(_ECDSA_HASH_OBJ[hash_name][0]()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def ecdsa_encrypt(pub, message: bytes, curve_name: str) -> bytes:
    curve_name = resolve_ec_curve(curve_name)
    if curve_name != "SM2":
        raise ToolError(
            f"{EC_CURVE_LABEL[curve_name]} 不支持加密：ECDSA 曲线没有内置 ECIES 实现，仅 SM2 曲线支持加密"
        )
    return sm2_encrypt(pub, message, "C1C3C2")


def ecdsa_decrypt(priv, cipher: bytes, curve_name: str) -> bytes:
    curve_name = resolve_ec_curve(curve_name)
    if curve_name != "SM2":
        raise ToolError(
            f"{EC_CURVE_LABEL[curve_name]} 不支持解密：ECDSA 曲线没有内置 ECIES 实现，仅 SM2 曲线支持解密"
        )
    if not isinstance(priv, int):
        raise ToolError("SM2 曲线私钥无效")
    return sm2_decrypt(priv, cipher, "C1C3C2")


# ---------------------------------------------------------------------------
# Attach & Detach（SM2 公钥 + 用户标识 附件包）
# ---------------------------------------------------------------------------

ATTACH_POINT_LEN = 65


def attach_build(pub, user_id: bytes = b"1234567812345678") -> bytes:
    if len(user_id) == 0:
        raise ToolError("用户标识不能为空")
    if len(user_id) > 8192:
        raise ToolError("用户标识过长")
    if not on_curve(SM2_CURVE, pub):
        raise ToolError("公钥不在曲线上，无法生成附件")
    return encode_point(pub) + user_id


def attach_parse(blob: bytes, curve: Curve = SM2_CURVE):
    if len(blob) <= ATTACH_POINT_LEN:
        raise ToolError("附件数据过短：至少需要 65 字节公钥 + 用户标识")
    raw = blob[:ATTACH_POINT_LEN]
    point = _decode_point_bytes(raw, curve)
    user_id = blob[ATTACH_POINT_LEN:]
    return point, user_id


def attach_sign(d: int, message: bytes, user_id: bytes) -> dict:
    pub = point_mul(SM2_CURVE, d, SM2_CURVE.g)
    z, e = sm2_e(pub, message, user_id)
    r, s = sm2_sign_digest(d, e)
    sig = _int_bytes(r, 32) + _int_bytes(s, 32)
    attachment = attach_build(pub, user_id)
    package = attachment + sig
    return {
        "publicKey": encode_point(pub).hex(),
        "userKey": user_id.hex(),
        "userId": user_id.decode("utf-8", "replace"),
        "attachment": attachment.hex(),
        "signature": sig.hex(),
        "signatureDER": rs_to_der(r, s).hex(),
        "package": package.hex(),
        "z": z.hex(),
        "e": e.hex(),
        "size": len(package),
    }


def attach_verify(blob_or_pub, message: bytes, user_id: bytes, signature: bytes,
                  public_key=None) -> bool:
    if blob_or_pub is not None:
        pub = blob_or_pub
    else:
        pub = public_key
    if pub is None:
        raise ToolError("请提供 SM2 公钥或附件包")
    z, e = sm2_e(pub, message, user_id)
    r, s = parse_signature(signature)
    return sm2_verify_digest(pub, e, r, s)


def attach_split_package(package: bytes):
    """附件包 = 65 字节公钥 || 用户标识 || 64 字节签名。"""
    if len(package) <= ATTACH_POINT_LEN + 64:
        raise ToolError("附件包长度非法：应为 公钥(65B) || 用户标识 || 签名(64B)")
    point = _decode_point_bytes(package[:ATTACH_POINT_LEN], SM2_CURVE)
    user_id = package[ATTACH_POINT_LEN:-64]
    if not user_id:
        raise ToolError("附件包中缺少用户标识")
    signature = package[-64:]
    return point, user_id, signature


def sm9_self_check() -> bool:
    """自检 SM9 曲线参数：生成元在曲线上且 n·G1 = O。"""
    if not on_curve(SM9_CURVE, SM9_CURVE.g):
        return False
    return point_mul(SM9_CURVE, SM9_CURVE.n, SM9_CURVE.g) is None


SM9_AVAILABLE = sm9_self_check()
