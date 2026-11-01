"""能力验证必备运算核心：PRF / KDF / TLCP 密钥生成 / SM2 攻击 / 椭圆曲线点运算 / PBKDF2 / 工作模式检测。

全部为本地纯计算实现：不访问网络、不写盘、不返回固定假数据。
标准依据：
- GB/T 32905-2016 SM3 杂凑算法
- GB/T 32918.2-2016 SM2 数字签名算法
- GB/T 32918.4-2016 SM2 公钥加密算法（KDF、加解密）
- GM/T 0024-2014 TLCP 协议（PRF、主密钥、密钥块）
- GM/T 0044-2016 SM9 标识密码算法（G1 / G2 曲线参数）
- RFC 2104 HMAC、RFC 5869 HKDF、ANSI X9.63 KDF、RFC 8018 PBKDF2
"""
from __future__ import annotations

import hashlib
import hmac as _hmac_mod

from .common import ToolError
from .hashing import HASH_ALGOS, _hash_once, hmac_digest

# ---------------------------------------------------------------------------
# 杂凑 / HMAC 小工具
# ---------------------------------------------------------------------------

HASH_LEN = {name: size for name, (_, size) in HASH_ALGOS.items()}

SUPPORTED_PRF = ("SM3", "SHA256", "SHA384", "SHA512", "SHA", "SHA224")


def _algo_name(algo: str) -> str:
    algo = (algo or "SM3").upper().replace("-", "").replace("_", "")
    alias = {
        "SM3": "SM3", "SHA": "SHA", "SHA1": "SHA", "SHA256": "SHA256", "SHA224": "SHA224",
        "SHA384": "SHA384", "SHA512": "SHA512", "MD5": "MD5",
        "SHA3224": "SHA3_224", "SHA3256": "SHA3_256", "SHA3384": "SHA3_384", "SHA3512": "SHA3_512",
    }
    if algo not in alias:
        raise ToolError(f"不支持的杂凑算法：{algo}")
    return alias[algo]


def _check_algo(algo: str) -> str:
    name = _algo_name(algo)
    if name not in SUPPORTED_PRF:
        raise ToolError(f"该运算不支持 {algo}，请选择 SM3 / SHA-256 等算法")
    return name


def _hash(algo: str, data: bytes) -> bytes:
    return _hash_once(algo, data)


def _hmac(algo: str, key: bytes, data: bytes) -> bytes:
    if not key:
        raise ToolError("请输入 Key（HMAC 密钥不能为空）")
    return hmac_digest(algo, data, key)


# ---------------------------------------------------------------------------
# 1. PRF（GB/T 32918 / GM/T 0024：HMAC 迭代伪随机函数）
# ---------------------------------------------------------------------------

MAX_ROUNDS = 64


def prf(algo: str, key: bytes, seed: bytes, label: bytes = b"", rounds: int = 4,
        label_after: bool = False) -> bytes:
    """HMAC 迭代 PRF（TLS / TLCP 的 P_hash 结构）。

    label_after=False（标准 TLCP / TLS 写法，Label 前置）：
        A(1) = HMAC(K, Label||Seed)，out_i = HMAC(K, A(i)||Label||Seed)
    label_after=True（与原站 /operation/prf 对齐，Label 后置）：
        A(1) = HMAC(K, Seed||Label)，out_i = HMAC(K, A(i)||Seed||Label)
    A(i) = HMAC(K, A(i-1))
    """
    name = _check_algo(algo)
    if not key:
        raise ToolError("请输入 Key")
    if not seed:
        raise ToolError("请输入 Seed")
    try:
        rounds = int(rounds)
    except (TypeError, ValueError):
        raise ToolError("迭代轮数必须为整数")
    if rounds < 1:
        raise ToolError("迭代轮数必须大于 0")
    if rounds > MAX_ROUNDS:
        raise ToolError(f"迭代轮数不能超过 {MAX_ROUNDS}")

    lab = label or b""
    msg = (seed + lab) if label_after else (lab + seed)
    a = _hmac(name, key, msg)
    out = bytearray()
    for _ in range(rounds):
        out += _hmac(name, key, a + msg)
        a = _hmac(name, key, a)
    return bytes(out)


def prf_sm3_hmac(key: bytes, seed: bytes, label: bytes = b"", rounds: int = 4) -> bytes:
    """HMAC-SM3 迭代 PRF（GM/T 0024 TLCP 默认构造）。"""
    return prf("SM3", key, seed, label, rounds)


def prf_run(algo: str, key: bytes, seed: bytes, label: bytes = b"", rounds: int = 4,
            label_after: bool = True, mode: str = "HMAC") -> bytes:
    """统一入口：HMAC 迭代 PRF / 直接 SM3 迭代 PRF。"""
    kind = (mode or "HMAC").upper()
    if kind in ("ITER", "SM3ITER", "DIRECT", "迭代"):
        return prf_sm3_direct(key, seed, label, rounds)
    return prf(algo, key, seed, label, rounds, label_after=label_after)


def prf_sm3_direct(key: bytes, seed: bytes, label: bytes = b"", rounds: int = 4) -> bytes:
    """SM3 迭代 PRF 变体：直接用 SM3(K||Z||i) 逐轮扩展（非 HMAC 结构）。"""
    if not key or not seed:
        raise ToolError("请输入 Key 与 Seed")
    rounds = int(rounds or 1)
    if rounds < 1 or rounds > MAX_ROUNDS:
        raise ToolError(f"迭代轮数必须在 1~{MAX_ROUNDS} 之间")
    out = bytearray()
    prev = b""
    for i in range(1, rounds + 1):
        prev = _hash("SM3", key + (label or b"") + seed + i.to_bytes(4, "big") + prev)
        out += prev
    return bytes(out)


# ---------------------------------------------------------------------------
# 2. KDF（SM3-KDF / HKDF-SHA256 / X9.63-KDF）
# ---------------------------------------------------------------------------

MAX_KDF = 4096


def _klen(klen) -> int:
    try:
        klen = int(klen)
    except (TypeError, ValueError):
        raise ToolError("输出长度必须为整数")
    if klen < 1:
        raise ToolError("输出长度必须大于 0")
    if klen > MAX_KDF:
        raise ToolError(f"输出长度不能超过 {MAX_KDF} 字节")
    return klen


def sm3_kdf(z: bytes, klen: int, shared_info: bytes = b"") -> bytes:
    """GB/T 32918.4 密钥派生函数 KDF(Z, klen)。

    Ha_i = SM3(Z || CT_i)（CT_i 为 32 位大端计数器，从 1 开始），
    若提供 SharedInfo 则追加在计数器之后。
    """
    klen = _klen(klen)
    if not z:
        raise ToolError("请输入共享比特串 Z")
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += _hash("SM3", z + ct.to_bytes(4, "big") + (shared_info or b""))
        ct += 1
        if ct > 0xFFFFFFFF:
            raise ToolError("输出长度过大")
    return bytes(out[:klen])


def hkdf_sha256(ikm: bytes, klen: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    """RFC 5869 HKDF-SHA256（extract + expand）。"""
    klen = _klen(klen)
    if not ikm:
        raise ToolError("请输入共享秘密 Z")
    if klen > 255 * 32:
        raise ToolError("HKDF-SHA256 输出长度不能超过 8160 字节")
    prk = _hmac("SHA256", salt or b"\x00" * 32, ikm)
    out = bytearray()
    t = b""
    i = 1
    while len(out) < klen:
        t = _hmac("SHA256", prk, t + (info or b"") + bytes([i]))
        out += t
        i += 1
    return bytes(out[:klen])


def hash_kdf(algo: str, z: bytes, klen: int, shared_info: bytes = b"") -> bytes:
    """通用迭代 KDF：Hash(Z || CT_i || SharedInfo)，CT 为 32 位大端计数器。"""
    klen = _klen(klen)
    if not z:
        raise ToolError("请输入共享比特串 Z")
    name = _algo_name(algo)
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += _hash(name, z + ct.to_bytes(4, "big") + (shared_info or b""))
        ct += 1
    return bytes(out[:klen])


def x963_kdf(z: bytes, klen: int, shared_info: bytes = b"") -> bytes:
    """ANSI X9.63 KDF（SHA-256）：Hash(Z || CT_i || SharedInfo)。"""
    return hash_kdf("SHA256", z, klen, shared_info)


KDF_TYPES = {
    "SM3": "SM3-KDF（GB/T 32918.4）",
    "SHA256": "SHA-256 迭代 KDF（与原站一致）",
    "HKDF": "HKDF-SHA256（RFC 5869）",
    "X963": "X9.63-KDF（SHA-256）",
}


def kdf(kind: str, z: bytes, klen: int, shared_info: bytes = b"", salt: bytes = b"") -> bytes:
    key = (kind or "SM3").upper().replace("-", "").replace(".", "").replace("_", "")
    if key in ("SM3", "SM3KDF", "GB/T"):
        return sm3_kdf(z, klen, shared_info)
    if key in ("SHA256", "SHA256KDF", "SHA2"):
        return hash_kdf("SHA256", z, klen, shared_info)
    if key in ("HKDF", "HKDFSHA256", "SHA256HKDF", "HKDF256"):
        return hkdf_sha256(z, klen, salt, shared_info)
    if key in ("X963", "X963KDF", "ANSI X9.63", "ANSI/X9.63"):
        return x963_kdf(z, klen, shared_info)
    raise ToolError(f"不支持的 KDF 类型：{kind}")


# ---------------------------------------------------------------------------
# 3. TLCP / TLS 密钥生成
# ---------------------------------------------------------------------------

TLCP_VERSION = "0101"  # TLCP 1.1
MASTER_LEN = 48


def tlcp_master_secret(pre_master: bytes, client_random: bytes, server_random: bytes,
                       label: bytes = b"master secret", algo: str = "SM3") -> bytes:
    """master_secret = PRF(pre_master_secret, "master secret", ClientRandom||ServerRandom)[0..47]"""
    if not pre_master:
        raise ToolError("请输入预主密钥")
    if not client_random or not server_random:
        raise ToolError("请输入客户端随机数与服务端随机数")
    out = prf(algo, pre_master, client_random + server_random, label or b"master secret", 16)
    return out[:MASTER_LEN]


# 与原站保持一致的密钥块切分：分组套件 mac=32/key=16/iv=16；GCM 套件 mac=0/key=16/iv=4
SUITE_PROFILE = {
    1: {"title": "分组算法（CBC + HMAC）", "key": 16, "iv": 16, "mac": 32},
    2: {"title": "GCM（AEAD）", "key": 16, "iv": 4, "mac": 0},
}


def tlcp_key_block(master: bytes, client_random: bytes, server_random: bytes,
                   label: bytes = b"key expansion", algo: str = "SM3",
                   suite_type=1, key_len: int | None = None, iv_len: int | None = None,
                   mac_len: int | None = None) -> dict:
    """key_block = PRF(master_secret, "key expansion", ServerRandom||ClientRandom)

    按 TLCP 约定切分为 client/server 的 MAC Secret、写密钥与 IV。
    """
    if not master:
        raise ToolError("请输入主密钥")
    if len(master) < 16:
        raise ToolError("主密钥长度过短（TLCP 主密钥为 48 字节）")
    if not client_random or not server_random:
        raise ToolError("请输入客户端随机数与服务端随机数")
    try:
        suite_type = int(suite_type or 1)
    except (TypeError, ValueError):
        raise ToolError("密码套件类型必须为 1（分组算法）或 2（GCM）")
    if suite_type not in SUITE_PROFILE:
        raise ToolError("密码套件类型必须为 1（分组算法）或 2（GCM）")
    prof = SUITE_PROFILE[suite_type]
    k_len = int(key_len) if key_len else prof["key"]
    i_len = int(iv_len) if iv_len is not None and iv_len != "" else prof["iv"]
    m_len = int(mac_len) if mac_len is not None and mac_len != "" else prof["mac"]
    need = 2 * (m_len + k_len + i_len)
    block = prf(algo, master, server_random + client_random, label or b"key expansion",
                (need + HASH_LEN[_check_algo(algo)] - 1) // HASH_LEN[_check_algo(algo)])
    block = block[:need]
    off = 0

    def take(size: int) -> bytes:
        nonlocal off
        val = block[off:off + size]
        off += size
        return val

    data = {
        "masterKey": master.hex(),
        "clientWriteMacSecret": take(m_len).hex() if m_len else "",
        "serverWriteMacSecret": take(m_len).hex() if m_len else "",
        "clientWritekey": take(k_len).hex(),
        "serverWritekey": take(k_len).hex(),
        "clientWriteIv": take(i_len).hex(),
        "serverWriteIv": take(i_len).hex(),
        "keyBlock": block.hex(),
        "suite": prof["title"],
        "length": need,
    }
    return data


# ---------------------------------------------------------------------------
# 4. 椭圆曲线点运算（SM2 / NIST / SM9 G1、G2）
# ---------------------------------------------------------------------------

class Curve:
    """素域曲线；beta 不为 None 时表示扩域 Fp2 = Fp[u]/(u^2 - beta)。"""

    def __init__(self, name, p, a, b, n, gx, gy, beta=None, label=None):
        self.name = name
        self.p = p
        self.beta = beta
        self.a = a
        self.b = b
        self.n = n
        self.g = ((gx, gy) if beta is None else (gx, gy))
        self.label = label or name
        self.size = (p.bit_length() + 7) // 8
        self.coord_len = self.size if beta is None else 2 * self.size

    @property
    def is_ext(self) -> bool:
        return self.beta is not None


def _hex(val) -> int:
    return int(val, 16) if isinstance(val, str) else int(val)


def _cur(name, p, a, b, n, gx, gy, label=None):
    return Curve(name, _hex(p), _hex(a), _hex(b), _hex(n), _hex(gx), _hex(gy), None, label)


_CURVES: dict[str, Curve] = {}


def _reg(c: Curve, *aliases: str) -> None:
    _CURVES[c.name.upper()] = c
    for a in aliases:
        _CURVES[a.upper()] = c


SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

_reg(_cur("sm2p256v1", SM2_P, SM2_A, SM2_B, SM2_N, SM2_GX, SM2_GY, "SM2 曲线"),
     "SM2", "SM2P256V1")

_reg(_cur("prime256v1",
          0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
          0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
          0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
          0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
          0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
          "NIST P-256"), "secp256r1", "P-256", "P256")

_reg(_cur("secp256k1",
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, 0,
          7,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
          0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))

_reg(_cur("prime192v1",
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
          0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
          0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
          0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
          0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811,
          "NIST P-192"), "secp192r1", "P-192")

_reg(_cur("secp384r1",
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
          0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
          0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
          0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
          "NIST P-384"), "P-384")

_reg(_cur("secp521r1",
          (1 << 521) - 1,
          ((1 << 521) - 1) - 3,
          0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
          0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
          0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
          0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
          "NIST P-521"), "P-521")

# SM9（GM/T 0044）参数
SM9_Q = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
SM9_N = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
SM9_G1X = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
SM9_G1Y = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
SM9_G2X = (0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B,  # (u 系数, 实部)
           0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141)
SM9_G2Y = (0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7,
           0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96)

_reg(Curve("sm9g1", SM9_Q, 0, 5, SM9_N, SM9_G1X, SM9_G1Y, None, "SM9 G1（Fp）"), "SM9-G1")

# SM9 G2：扩域 Fp2 = Fp[u]/(u²+2)，扭曲线 y² = x³ + 5u
_SM9_G2 = Curve("sm9g2", SM9_Q, (0, 0), (0, 5), SM9_N, 0, 0, SM9_Q - 2, "SM9 G2（Fp2，y²=x³+5u）")
_SM9_G2.g = (SM9_G2X, SM9_G2Y)
_reg(_SM9_G2, "SM9-G2")

CURVE_NAMES = ["sm2p256v1", "prime256v1", "secp256k1", "prime192v1", "secp384r1", "secp521r1", "sm9g1", "sm9g2"]


def get_curve(name: str | None) -> Curve:
    key = (name or "sm2p256v1").strip().upper()
    key = key.replace(" ", "")
    c = _CURVES.get(key)
    if c is None:
        raise ToolError(f"不支持的曲线：{name}")
    return c


# ---- 域运算 ----

def _f_add(c: Curve, x, y):
    if not c.is_ext:
        return (x + y) % c.p
    return ((x[0] + y[0]) % c.p, (x[1] + y[1]) % c.p)


def _f_sub(c: Curve, x, y):
    if not c.is_ext:
        return (x - y) % c.p
    return ((x[0] - y[0]) % c.p, (x[1] - y[1]) % c.p)


def _f_mul(c: Curve, x, y):
    if not c.is_ext:
        return (x * y) % c.p
    a, b = x
    d, e = y
    beta = c.beta % c.p
    return ((a * d + beta * b * e) % c.p, (a * e + b * d) % c.p)


def _f_sq(c: Curve, x):
    return _f_mul(c, x, x)


def _f_inv(c: Curve, x):
    if not c.is_ext:
        if x % c.p == 0:
            raise ToolError("域元素不可逆（出现除零）")
        return pow(x, c.p - 2, c.p)
    a, b = x
    norm = (a * a - c.beta * b * b) % c.p
    if norm == 0:
        raise ToolError("域元素不可逆（出现除零）")
    inv = pow(norm, c.p - 2, c.p)
    return (a * inv % c.p, (-b) * inv % c.p)


def _f_from_int(c: Curve, v: int):
    return v % c.p if not c.is_ext else (v % c.p, 0)


def _f_zero(c: Curve):
    return 0 if not c.is_ext else (0, 0)


def _f_eq(c: Curve, x, y) -> bool:
    return x == y


# ---- 点运算 ----

def point_is_inf(P) -> bool:
    return P is None


def point_add(c: Curve, P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if _f_eq(c, x1, x2):
        if _f_eq(c, y1, y2):
            # 倍点
            num = _f_mul(c, _f_from_int(c, 3), _f_sq(c, x1))
            if not c.is_ext:
                num = (num + c.a) % c.p
            den = _f_mul(c, _f_from_int(c, 2), y1)
            if _f_eq(c, den, _f_zero(c)):
                return None
            lam = _f_mul(c, num, _f_inv(c, den))
        else:
            return None
    else:
        num = _f_sub(c, y2, y1)
        den = _f_sub(c, x2, x1)
        lam = _f_mul(c, num, _f_inv(c, den))
    x3 = _f_sub(c, _f_sub(c, _f_sq(c, lam), x1), x2)
    y3 = _f_sub(c, _f_mul(c, lam, _f_sub(c, x1, x3)), y1)
    return (x3, y3)


def point_neg(c: Curve, P):
    if P is None:
        return None
    x, y = P
    return (x, _f_sub(c, _f_zero(c), y))


def point_sub(c: Curve, P, Q):
    return point_add(c, P, point_neg(c, Q))


def point_mul(c: Curve, k: int, P):
    k %= c.n
    if k == 0 or P is None:
        return None
    R = None
    while k:
        if k & 1:
            R = point_add(c, R, P)
        P = point_add(c, P, P)
        k >>= 1
    return R


def point_on_curve(c: Curve, P) -> bool:
    if P is None:
        return True
    x, y = P
    if not c.is_ext:
        if not (0 <= x < c.p and 0 <= y < c.p):
            return False
        return (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0
    return _f_eq(c, _f_sq(c, y), _f_add(c, _f_mul(c, _f_sq(c, x), x), c.b))


def _sqrt_mod(a: int, p: int) -> int | None:
    a %= p
    if a == 0:
        return 0
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    # Tonelli-Shanks
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
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


def _sqrt_ext(c: Curve, a) -> tuple | None:
    """Fp2（u²=beta）内求平方根。"""
    x, y = a
    beta = c.beta % c.p
    norm = (x * x - beta * y * y) % c.p
    d = _sqrt_mod(norm, c.p)
    if d is None:
        return None
    for sign in (1, -1):
        t = (x + sign * d) % c.p
        half = t * pow(2, c.p - 2, c.p) % c.p
        s0 = _sqrt_mod(half, c.p)
        if s0 is None or s0 == 0:
            continue
        s1 = y * pow(2 * s0 % c.p, c.p - 2, c.p) % c.p
        cand = (s0, s1)
        if _f_eq(c, _f_sq(c, cand), a):
            return cand
    return None


def point_y_from_x(c: Curve, x):
    """由 X 坐标恢复 Y（解压缩）。"""
    if c.is_ext:
        rhs = _f_add(c, _f_mul(c, _f_sq(c, x), x), c.b)
        y = _sqrt_ext(c, rhs)
        return y
    rhs = (x * x * x + c.a * x + c.b) % c.p
    y = _sqrt_mod(rhs, c.p)
    return y


# ---- 点编解码 ----

def _coord_bytes(c: Curve, v: int) -> bytes:
    return int(v).to_bytes(c.size, "big")


def _ext_bytes(c: Curve, v) -> bytes:
    """Fp2 元素按标准写法输出 (u 系数 || 实部)。"""
    return int(v[1]).to_bytes(c.size, "big") + int(v[0]).to_bytes(c.size, "big")


def point_encode(c: Curve, P, compressed: bool = False) -> bytes:
    if P is None:
        return b"\x00"
    x, y = P
    if c.is_ext:
        xb = _ext_bytes(c, x)
        yb = _ext_bytes(c, y)
    else:
        xb = _coord_bytes(c, x)
        yb = _coord_bytes(c, y)
    if compressed:
        parity = (y[1] if c.is_ext else y) & 1
        return bytes([2 + parity]) + xb
    return b"\x04" + xb + yb


def point_decode(c: Curve, data: bytes, prefix_parity: int | None = None):
    """解析 04||X||Y、02/03||X 或裸 X||Y。"""
    if not data:
        raise ToolError("请输入点坐标数据")
    if data[0] == 0x00 and len(data) == 1:
        return None
    clen = c.coord_len
    prefix = data[0] if len(data) in (1 + clen, 1 + 2 * clen) and data[0] in (2, 3, 4, 6, 7) else None
    body = data[1:] if prefix is not None else data
    if len(body) == 2 * clen:
        xb, yb = body[:clen], body[clen:]
        x = _ext_from(c, xb) if c.is_ext else int.from_bytes(xb, "big")
        y = _ext_from(c, yb) if c.is_ext else int.from_bytes(yb, "big")
        P = (x, y)
        if not point_on_curve(c, P):
            raise ToolError("该点不在所选曲线上，请检查曲线名称与坐标")
        return P
    if len(body) == clen:
        x = _ext_from(c, body) if c.is_ext else int.from_bytes(body, "big")
        y = point_y_from_x(c, x)
        if y is None:
            raise ToolError("该 X 坐标在所选曲线上无对应 Y 坐标")
        want = None
        if prefix in (2, 3):
            want = prefix & 1
        elif prefix is None and prefix_parity is not None:
            want = int(prefix_parity) & 1
        if want is not None:
            cur = (y[1] if c.is_ext else y) & 1
            if cur != want:
                y = _f_sub(c, _f_zero(c), y)
        P = (x, y)
        if not point_on_curve(c, P):
            raise ToolError("该点不在所选曲线上，请检查曲线名称与坐标")
        return P
    raise ToolError(f"点坐标长度不正确：期望 {1 + 2 * clen} 字节（未压缩）或 {1 + clen} 字节（压缩）")


def _ext_from(c: Curve, b: bytes):
    size = c.size
    imag = int.from_bytes(b[:size], "big")
    real = int.from_bytes(b[size:2 * size], "big")
    return (real, imag)


def parse_scalar(value: str, fmt: str | None = "HEX") -> int:
    from .common import parse_bytes

    fmt = (fmt or "HEX").upper()
    if fmt in ("DEC", "DECIMAL", "TEXT", "STR"):
        text = (value or "").strip()
        if not text.isdigit():
            raise ToolError("标量必须为十进制整数")
        return int(text)
    raw = parse_bytes(value, "HEX" if fmt not in ("BASE64", "B64") else "BASE64")
    if not raw:
        raise ToolError("请输入标量")
    return int.from_bytes(raw, "big")


POINT_OPS = {
    "1": "add", "add": "add", "+": "add",
    "2": "sub", "sub": "sub", "-": "sub",
    "3": "mul", "mul": "mul", "*": "mul",
    "4": "neg", "neg": "neg", "inv": "neg",
    "5": "decompress", "decompress": "decompress", "y": "decompress",
    "6": "compress", "compress": "compress",
}


def point_operation(op, curve_name, point_one: bytes, point_two: bytes | None = None,
                    point_two_is_scalar: bool = True, compressed: bool = False) -> bytes:
    """统一入口：点加 / 点减 / 数乘 / 取逆 / 解压 / 压缩。"""
    key = str(op or "add").strip().lower()
    name = POINT_OPS.get(key)
    if name is None:
        raise ToolError(f"不支持的点运算类型：{op}")
    c = get_curve(curve_name)
    P = point_decode(c, point_one)

    if name == "add":
        Q = point_decode(c, point_two or b"")
        R = point_add(c, P, Q)
    elif name == "sub":
        Q = point_decode(c, point_two or b"")
        R = point_sub(c, P, Q)
    elif name == "mul":
        if point_two is None or point_two == b"":
            raise ToolError("请输入标量 k")
        k = int.from_bytes(point_two, "big") if isinstance(point_two, bytes) else int(point_two)
        if k <= 0:
            raise ToolError("标量 k 必须为正整数")
        if k >= c.n:
            k %= c.n
            if k == 0:
                raise ToolError("标量 k 必须是 1 ~ n-1 之间的整数")
        R = point_mul(c, k, P)
    elif name == "neg":
        R = point_neg(c, P)
    elif name == "compress":
        return point_encode(c, P, compressed=True)
    else:  # decompress：P 由压缩点解出
        R = P
    return point_encode(c, R, compressed=compressed)


# ---------------------------------------------------------------------------
# 5. SM2 加解密 / 签名（GB/T 32918.2 / 32918.4）
# ---------------------------------------------------------------------------

_SM2 = get_curve("sm2p256v1")


def sm2_pubkey_from_priv(d: int):
    d = int(d) % _SM2.n
    if d == 0:
        raise ToolError("私钥 d 不能为 0")
    return point_mul(_SM2, d, _SM2.g)


def sm2_encrypt(pub_point, msg: bytes, k: int | None = None) -> bytes:
    """SM2 加密，输出 C1C3C2（C1 含 04 前缀）。"""
    if not point_on_curve(_SM2, pub_point):
        raise ToolError("公钥不是合法的 SM2 曲线点")
    if k is None:
        k = int.from_bytes(hashlib.sha256(msg + pub_point[0].to_bytes(32, "big")).digest(), "big") or 1
        k %= _SM2.n
    k = int(k) % _SM2.n
    if k == 0:
        raise ToolError("随机数 k 不能为 0")
    C1 = point_mul(_SM2, k, _SM2.g)
    S = point_mul(_SM2, k, pub_point)
    x2 = _coord_bytes(_SM2, S[0])
    y2 = _coord_bytes(_SM2, S[1])
    t = sm3_kdf(x2 + y2, len(msg)) if msg else b""
    C2 = bytes(a ^ b for a, b in zip(msg, t))
    C3 = _hash("SM3", x2 + msg + y2)
    return point_encode(_SM2, C1) + C3 + C2


def split_sm2_cipher(data: bytes):
    """拆分密文：返回 (C1 点字节, C3, C2, 顺序)。"""
    if len(data) < 64:
        raise ToolError("SM2 密文长度不足（至少需要 65 字节）")
    if data[0] == 0x04:
        c1, rest = data[:65], data[65:]
    else:
        c1, rest = b"\x04" + data[:64], data[64:]
    if len(rest) < 32:
        # 只有 C1
        return c1, b"", b"", "C1"
    return c1, rest[:32], rest[32:], "C1C3C2"


def sm2_decrypt(priv_d: int, data: bytes) -> bytes:
    d = int(priv_d) % _SM2.n
    c1, c3, c2, order = split_sm2_cipher(data)
    if order == "C1":
        raise ToolError("密文只包含 C1 部分，无法解密")
    C1 = point_decode(_SM2, c1)
    S = point_mul(_SM2, d, C1)
    if S is None:
        raise ToolError("C1 与私钥运算结果为无穷远点")
    x2 = _coord_bytes(_SM2, S[0])
    y2 = _coord_bytes(_SM2, S[1])
    for c3_try, c2_try in ((c3, c2), (c2[:32], c2[32:])):
        t = sm3_kdf(x2 + y2, len(c2_try)) if c2_try else b""
        m = bytes(a ^ b for a, b in zip(c2_try, t))
        if _hash("SM3", x2 + m + y2) == c3_try:
            return m
    raise ToolError("密文完整性校验失败（C3 不匹配），可能密钥或数据有误")


def sm2_sign(d: int, e: int | bytes, k: int) -> tuple[int, int]:
    """SM2 签名：r = (e + x1) mod n，s = ((1+d)^-1 * (k - r*d)) mod n。"""
    d = int(d) % _SM2.n
    if d == 0:
        raise ToolError("私钥 d 不能为 0")
    e_int = int.from_bytes(e, "big") if isinstance(e, (bytes, bytearray)) else int(e)
    e_int %= _SM2.n
    k = int(k) % _SM2.n
    if k == 0:
        raise ToolError("随机数 k 不能为 0")
    P = point_mul(_SM2, k, _SM2.g)
    r = (e_int + P[0]) % _SM2.n
    if r == 0 or r + k == _SM2.n:
        raise ToolError("随机数 k 不适用（r 为 0 或 r+k=n），请更换 k")
    s = (pow(1 + d, -1, _SM2.n) * (k - r * d)) % _SM2.n
    if s == 0:
        raise ToolError("计算得到 s=0，请更换 k")
    return r, s


def sm2_verify(pub_point, e: int | bytes, r: int, s: int) -> bool:
    n = _SM2.n
    r, s = int(r) % n, int(s) % n
    if not (1 <= r < n and 1 <= s < n):
        return False
    e_int = int.from_bytes(e, "big") if isinstance(e, (bytes, bytearray)) else int(e)
    e_int %= n
    t = (r + s) % n
    if t == 0:
        return False
    P = point_add(_SM2, point_mul(_SM2, s, _SM2.g), point_mul(_SM2, t, pub_point))
    if P is None:
        return False
    return (e_int + P[0]) % n == r


# ---------------------------------------------------------------------------
# 6. SM2 加密 K 碰撞 / 明文恢复
# ---------------------------------------------------------------------------

DEFAULT_MAX_K = 65536


def _max_k(value, cap: int) -> int:
    if value in (None, ""):
        return DEFAULT_MAX_K
    try:
        m = int(value)
    except (TypeError, ValueError):
        raise ToolError("碰撞上限必须为整数")
    if m < 1:
        raise ToolError("碰撞上限必须大于 0")
    if m > cap:
        raise ToolError(f"碰撞上限不能超过 {cap}")
    return m


def sm2_find_k(c1_point_bytes: bytes, max_k=DEFAULT_MAX_K, cap: int = 1 << 20) -> int | None:
    """在 1..max_k 范围内搜索满足 kG == C1 的随机数 k（逐点累加，O(k) 次点加）。"""
    limit = _max_k(max_k, cap)
    P = point_decode(_SM2, c1_point_bytes)
    if P is None:
        return None
    gx, gy = _SM2.g
    cur = None
    for i in range(1, limit + 1):
        cur = point_add(_SM2, cur, _SM2.g) if cur is not None else (_SM2.g)
        if cur == P:
            return i
        if cur[0] == P[0] and cur[1] == P[1]:
            return i
    return None


def sm2_enc_k_analyze(cipher: bytes, public_key: bytes | None, max_k=DEFAULT_MAX_K,
                      recover: bool = False) -> dict:
    """碰撞 k（并可选恢复明文）。"""
    c1, c3, c2, order = split_sm2_cipher(cipher)
    k = sm2_find_k(c1, max_k)
    res = {
        "c1": c1.hex(),
        "c1Point": point_decode(_SM2, c1),
        "k": None,
        "tried": None,
        "sharedPoint": None,
        "plain": None,
        "recover": recover,
    }
    if k is None:
        raise ToolError("在给定范围内未碰撞到随机数 k，可尝试增大碰撞上限或改用其他样本")
    res["k"] = f"{k:064x}"
    res["tried"] = k
    C1 = point_decode(_SM2, c1)
    detail = []
    detail.append(f"碰撞成功：k = {k}（0x{k:x}），kG 与密文 C1 一致")
    if public_key:
        P = point_decode(_SM2, public_key)
        S = point_mul(_SM2, k, P)
        if S is not None:
            res["sharedPoint"] = point_encode(_SM2, S).hex()
            detail.append(f"共享点 kP = {res['sharedPoint']}")
            if recover and order != "C1":
                x2 = _coord_bytes(_SM2, S[0])
                y2 = _coord_bytes(_SM2, S[1])
                plain = None
                for c3_try, c2_try in ((c3, c2), (c2[:32], c2[32:])):
                    t = sm3_kdf(x2 + y2, len(c2_try)) if c2_try else b""
                    m = bytes(a ^ b for a, b in zip(c2_try, t))
                    if _hash("SM3", x2 + m + y2) == c3_try:
                        plain = m
                        break
                if plain is None:
                    detail.append("C3 校验未通过：公钥可能与密文不匹配")
                else:
                    res["plain"] = plain
                    detail.append("C3 校验通过，明文恢复成功")
    elif recover:
        detail.append("未提供公钥，无法计算共享点，无法恢复明文")
    res["detail"] = "\n".join(detail)
    return res


def sm2_k_reuse_compare(cipher_a: bytes, cipher_b: bytes, public_key: bytes | None = None) -> dict:
    """判断两组密文是否复用同一随机数 k（C1 相同）。"""
    c1a, _, _, _ = split_sm2_cipher(cipher_a)
    c1b, _, _, _ = split_sm2_cipher(cipher_b)
    same = c1a == c1b
    out = {
        "c1A": c1a.hex(),
        "c1B": c1b.hex(),
        "reuse": same,
        "sameX": c1a[1:33] == c1b[1:33],
        "sameY": c1a[33:65] == c1b[33:65],
    }
    lines = [
        f"C1(A) = {out['c1A']}",
        f"C1(B) = {out['c1B']}",
        "两组密文 C1 完全相同：随机数 k 被复用，同明文可直接比对，异明文可由 kP 关联分析。" if same
        else "两组密文 C1 不同：未检测到随机数 k 复用。",
    ]
    if public_key:
        P = point_decode(_SM2, public_key)
        k = sm2_find_k(c1a, 65536)
        if k:
            S = point_mul(_SM2, k, P)
            out["sharedPoint"] = point_encode(_SM2, S).hex() if S else None
            lines.append(f"已由 C1 碰撞得到 k = {k}")
    out["detail"] = "\n".join(lines)
    return out


# ---------------------------------------------------------------------------
# 7. SM2 签名攻击（k 复用 / 弱随机数反推私钥）
# ---------------------------------------------------------------------------

def _split_rs(data: bytes, label: str = "签名值") -> tuple[int, int]:
    if len(data) % 2 == 0 and len(data) >= 4 and len(data) != 64:
        half = len(data) // 2
        return int.from_bytes(data[:half], "big"), int.from_bytes(data[half:], "big")
    if len(data) == 64:
        return int.from_bytes(data[:32], "big"), int.from_bytes(data[32:], "big")
    raise ToolError(f"{label}长度不正确：应为 64 字节的 r||s")


split_rs = _split_rs


def parse_eess(data: bytes) -> tuple[int, int, int]:
    """解析 EESS 签名块。

    与原站一致的布局为 R||S||E（各 32 字节，共 96 字节）；
    若只给 64 字节，则按 R||S 解析，e 值需由「e 值」输入框补充。
    """
    if len(data) == 96:
        return (int.from_bytes(data[64:], "big"), int.from_bytes(data[:32], "big"),
                int.from_bytes(data[32:64], "big"))
    if len(data) == 64:
        return (0, int.from_bytes(data[:32], "big"), int.from_bytes(data[32:], "big"))
    raise ToolError("EESS 数据长度不正确：应为 96 字节（R||S||E）或 64 字节（R||S）")


def d_from_two_rrss(r1: int, s1: int, r2: int, s2: int) -> int:
    """两组同 k 签名反推私钥：d = (s1-s2) / (r2-r1-s1+s2) mod n。"""
    n = _SM2.n
    den = (r2 - r1 - s1 + s2) % n
    if den == 0:
        raise ToolError("两组签名的 r、s 差异为 0，无法反推私钥（请确认随机数 k 确实相同）")
    d = (s1 - s2) * pow(den, -1, n) % n
    if d == 0:
        raise ToolError("反推得到 d=0，数据可能不满足 k 复用条件")
    return d


def k_from_rsd(r: int, s: int, d: int) -> int:
    """k = s*(1+d) + r*d mod n"""
    n = _SM2.n
    return (s * (1 + d) + r * d) % n


def d_from_rsk(r: int, s: int, k: int) -> int:
    """d = (k-s)/(r+s) mod n"""
    n = _SM2.n
    den = (r + s) % n
    if den == 0:
        raise ToolError("r+s ≡ 0 mod n，无法反推私钥")
    d = (k - s) * pow(den, -1, n) % n
    if d == 0:
        raise ToolError("反推得到 d=0，数据可能有误")
    return d


def d2_from_rsd1(r1: int, s1: int, d1: int, r2: int, s2: int) -> int:
    """已知第一组私钥与两组同 k 签名，推导第二组私钥 d2。"""
    k = k_from_rsd(r1, s1, d1)
    return d_from_rsk(r2, s2, k)


def _verify_with_d(d: int, e: int, r: int, s: int) -> bool:
    try:
        return sm2_verify(sm2_pubkey_from_priv(d), e, r, s)
    except ToolError:
        return False


def unravel_rrss(sign_one: bytes, sign_two: bytes, e1: int, e2: int) -> dict:
    r1, s1 = _split_rs(sign_one, "第一组签名值")
    r2, s2 = _split_rs(sign_two, "第二组签名值")
    n = _SM2.n
    same_k = ((e1 + r1) % n) == ((e2 + r2) % n)
    d = d_from_two_rrss(r1, s1, r2, s2)
    k = k_from_rsd(r1, s1, d)
    return {
        "d": f"{d:064x}",
        "k": f"{k:064x}",
        "r1": f"{r1:064x}", "s1": f"{s1:064x}",
        "r2": f"{r2:064x}", "s2": f"{s2:064x}",
        "sameK": same_k,
        "verified": _verify_with_d(d, e1, r1, s1) and _verify_with_d(d, e2, r2, s2),
        "publicKey": point_encode(_SM2, sm2_pubkey_from_priv(d)).hex(),
    }


def unravel_eess(eess_one: bytes, eess_two: bytes, e1_override=None, e2_override=None) -> dict:
    e1, r1, s1 = parse_eess(eess_one)
    e2, r2, s2 = parse_eess(eess_two)
    if e1_override not in (None, "", b""):
        e1 = int.from_bytes(e1_override, "big") if isinstance(e1_override, (bytes, bytearray)) else int(e1_override)
    if e2_override not in (None, "", b""):
        e2 = int.from_bytes(e2_override, "big") if isinstance(e2_override, (bytes, bytearray)) else int(e2_override)
    res = unravel_rrss(r1.to_bytes(32, "big") + s1.to_bytes(32, "big"),
                       r2.to_bytes(32, "big") + s2.to_bytes(32, "big"), e1, e2)
    res["e1"] = f"{e1:064x}"
    res["e2"] = f"{e2:064x}"
    return res


# ---- DER 编解码 ----

def _der_int(v: int) -> bytes:
    body = int(v).to_bytes((int(v).bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + _der_len(len(body)) + body


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def rs_to_der(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + _der_len(len(body)) + body


def der_to_rs(data: bytes) -> tuple[int, int]:
    from . import asn1

    try:
        node = asn1.parse(data)
    except ToolError:
        raise ToolError("DER 签名数据解析失败")
    if node.tag != 0x10 or len(node.children) != 2:
        raise ToolError("DER 签名应为 SEQUENCE { INTEGER r, INTEGER s }")
    r_node, s_node = node.children
    if r_node.tag != 0x02 or s_node.tag != 0x02:
        raise ToolError("DER 签名中的 r、s 必须为 INTEGER")
    return int.from_bytes(r_node.value, "big"), int.from_bytes(s_node.value, "big")

# ---------------------------------------------------------------------------
# 8. PBKDF2（RFC 8018）
# ---------------------------------------------------------------------------

PBKDF2_MAX_TIMES = 2000000


def pbkdf2(password: bytes, salt: bytes, iterations, klen, algo: str = "SM3") -> bytes:
    name = _algo_name(algo)
    try:
        iterations = int(iterations)
    except (TypeError, ValueError):
        raise ToolError("迭代次数必须为整数")
    if iterations < 1:
        raise ToolError("迭代次数必须大于 0")
    if iterations > PBKDF2_MAX_TIMES:
        raise ToolError(f"迭代次数不能超过 {PBKDF2_MAX_TIMES}")
    klen = _klen(klen)
    if not password:
        raise ToolError("请输入口令 Password")
    hlen = HASH_LEN[name]
    blocks = (klen + hlen - 1) // hlen
    out = bytearray()
    for i in range(1, blocks + 1):
        u = _hmac(name, password, salt + i.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = _hmac(name, password, u)
            for j in range(hlen):
                t[j] ^= u[j]
        out += t
    return bytes(out[:klen])


# ---------------------------------------------------------------------------
# 9. 工作模式检测（ECB / CBC / CFB / OFB / CTR / BC）
# ---------------------------------------------------------------------------

MODES = ("ECB", "CBC", "CFB", "OFB", "CTR", "BC")
MODE_LABEL = {
    "ECB": "ECB（电子密码本）",
    "CBC": "CBC（密码分组链接）",
    "CFB": "CFB（密码反馈）",
    "OFB": "OFB（输出反馈）",
    "CTR": "CTR（计数器）",
    "BC": "BC（分组密码，模式未定）",
}
MODE_DESC = {
    "ECB": "ECB模式 - 电子密码本模式（相同明文产生相同密文，分组独立）",
    "CBC": "CBC模式 - 密码分组链接模式（有错误传播，需要填充）",
    "CFB": "CFB模式 - 密码反馈模式（流密码特征，有错误传播，不需要填充）",
    "OFB": "OFB模式 - 输出反馈模式（流密码特征，无错误传播，不需要填充）",
    "CTR": "CTR模式 - 计数器模式（流密码特征，无错误传播，支持并行）",
    "BC": "BC模式 - 分组链接模式（类似 CBC，有错误传播，需要填充）",
}


def _blocks(data: bytes, size: int) -> list[bytes]:
    return [data[i:i + size] for i in range(0, len(data) - size + 1, size)]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def detect_mode(ct1: bytes, ct2: bytes) -> dict:
    if len(ct1) < 16 or len(ct2) < 16:
        raise ToolError("密文长度至少需要 16 字节（32 个十六进制字符）")
    if len(ct1) != len(ct2):
        raise ToolError("两组密文长度必须一致，否则无法做差异分布比较")

    n = len(ct1)
    scores = {m: 0.0 for m in MODES}
    evidence: list[dict] = []

    def add(mode: str, weight: float, text: str) -> None:
        scores[mode] = max(-1.0, scores[mode] + weight)
        evidence.append({"mode": mode, "weight": round(weight, 2), "text": text})

    # --- 分组长度推断 ---
    if n % 16 == 0:
        bs, aligned, guess = 16, True, "16 字节（SM4 / AES 分组）"
    elif n % 8 == 0:
        bs, aligned, guess = 8, True, "8 字节（DES / 3DES 分组）"
    else:
        bs, aligned, guess = 0, False, "无法整除 8/16，倾向于流式模式"

    blk1 = _blocks(ct1, bs) if aligned else []
    blk2 = _blocks(ct2, bs) if aligned else []
    uniq = len(set(blk1)) if blk1 else 0
    dup = len(blk1) - uniq if blk1 else 0
    cross_same = sum(1 for a, b in zip(blk1, blk2) if a == b) if blk1 else 0

    diff = _xor_bytes(ct1, ct2)
    diff_bytes = sum(1 for b in diff if b)
    diff_ratio = diff_bytes / n
    same_bytes = n - diff_bytes
    prefix = 0
    for a, b in zip(ct1, ct2):
        if a != b:
            break
        prefix += 1

    # 证据 1：长度对齐
    if not aligned:
        add("CFB", 0.35, f"密文长度 {n} 字节不是 8/16 的整数倍，分组模式通常需要填充到整块，因此更可能是流式模式")
        add("OFB", 0.35, f"长度非分组整数倍，OFB 无需填充即可输出等长密文")
        add("CTR", 0.35, f"长度非分组整数倍，CTR 无需填充即可输出等长密文")
        add("ECB", -0.30, "长度非分组整数倍与 ECB 的整块输出特征不符")
        add("CBC", -0.30, "长度非分组整数倍与 CBC 的整块输出特征不符")
    else:
        add("BC", 0.05, f"密文长度 {n} 字节是 {bs} 的整数倍，符合分组密码整块输出特征")

    # 证据 2：块内重复
    if aligned and blk1:
        if dup > 0:
            add("ECB", min(0.70, 0.25 * dup),
                f"第一组密文出现 {dup} 个重复分组（共 {len(blk1)} 块），ECB 对相同明文块产生相同密文块")
            add("CBC", -0.20, "出现重复分组，与 CBC 的链式随机化特征不符（CBC 除 IV 碰撞外极少重复）")
            add("CFB", -0.10, "出现重复分组，与 CFB 的反馈随机化特征不符")
        else:
            add("CBC", 0.15, f"第一组 {len(blk1)} 个分组互不相同，符合 CBC/流式模式的随机化特征")
            add("CTR", 0.10, "所有分组互不相同，与计数器模式下的随机密文一致")
            add("OFB", 0.10, "所有分组互不相同，与输出反馈模式的随机密文一致")
        if cross_same > 0:
            add("ECB", 0.30, f"两组密文在相同偏移处有 {cross_same} 个完全相同的分组，说明相同明文块被确定性加密")
            add("BC", 0.15, "相同偏移处出现相同密文块，说明加密过程不含随机化（确定性）")
        if ct1 == ct2:
            add("ECB", 0.35, "两组密文完全一致：在明文不同或 IV 不同的假设下，只有确定性模式（ECB/BC）才会如此")
            add("BC", 0.25, "两组密文完全一致，也可能是相同 IV 的分组模式，需要改用不同 IV 再测一次")

    # 证据 3：差异分布
    if diff_bytes == 0:
        add("ECB", 0.05, "两组密文逐字节相同，差异分布无信息量")
    elif diff_ratio < 0.10:
        add("CTR", 0.40, f"两组密文仅 {diff_bytes}/{n} 字节不同（{diff_ratio:.1%}），差异稀疏且与明文差异位置对齐，符合 CTR 密钥流复用")
        add("OFB", 0.38, f"差异仅 {diff_bytes} 字节，OFB 密钥流与明文无关，异或差异等于明文差异")
        add("CFB", 0.28, f"差异仅 {diff_bytes} 字节，CFB 反馈使差异与明文差异保持一致")
        add("ECB", 0.20, f"差异集中在少数分组内，可能是 ECB 下仅少量明文块发生变化")
        add("CBC", -0.20, "差异过于稀疏，与 CBC 雪崩扩散特征不符")
    elif 0.30 <= diff_ratio <= 0.70:
        add("CBC", 0.32, f"两组密文差异字节占比 {diff_ratio:.1%}，接近随机水平，符合 CBC 链式扩散")
        add("CTR", 0.22, f"差异占比 {diff_ratio:.1%}，符合计数器模式下密钥流完全不同的情况")
        add("OFB", 0.22, f"差异占比 {diff_ratio:.1%}，符合输出反馈模式下密钥流完全不同的情况")
        add("CFB", 0.20, f"差异占比 {diff_ratio:.1%}，符合密码反馈模式下密钥流完全不同的情况")
        add("ECB", -0.10, "差异在全文中近似均匀分布，与 ECB 的块内局部化特征不符")
    else:
        add("BC", 0.06, f"两组密文差异字节占比 {diff_ratio:.1%}，处于中间水平，证据不足以下定论")

    # 证据 4：公共前缀
    if 0 < prefix < (bs or 16) and prefix < n:
        add("CFB", 0.25, f"两组密文前 {prefix} 字节相同后立即分叉，符合 CFB 的字节级反馈（前缀受相同 IV 影响）")
    if prefix >= (bs or 16) and prefix < n:
        add("ECB", 0.15, f"前 {prefix} 字节（≥1 个分组）完全相同，说明起始部分使用相同输入与密钥")
        add("CBC", 0.18, f"前 {prefix} 字节相同，可能是同 IV 下的 CBC 加密")
    elif prefix == n:
        same_bytes = n

    # 证据 5：单块/过短
    if aligned and len(blk1) <= 1:
        add("BC", 0.30, "样本仅一个分组，无法观察链式或反馈特征，只能判定为分组密码")

    # 归一化置信度
    positive = {m: max(0.0, v) for m, v in scores.items()}
    total = sum(positive.values())
    ranked = sorted(positive.items(), key=lambda kv: (-kv[1], MODES.index(kv[0])))
    guesses = []
    for mode, sc in ranked:
        if total <= 0:
            conf = 0.0
        else:
            conf = sc / total
        if sc <= 0 and guesses:
            continue
        reasons = [e["text"] for e in evidence if e["mode"] == mode and e["weight"] > 0]
        if not reasons:
            reasons = ["未发现该模式的正面特征，仅按排除法保留"]
        guesses.append({
            "mode": mode,
            "label": MODE_LABEL[mode],
            "description": MODE_DESC[mode],
            "score": round(sc, 3),
            "confidence": round(conf, 3),
            "reasoning": f"{mode}特征分析：" + "；".join(reasons) + "。",
        })
    if not guesses:
        guesses = [{"mode": "BC", "label": MODE_LABEL["BC"], "description": MODE_DESC["BC"],
                    "score": 0, "confidence": 0.0,
                    "reasoning": "BC特征分析：证据不足，按分组密码模式处理。"}]

    top = guesses[0]["mode"]
    lines = [
        "===== 工作模式检测报告 =====",
        f"密文 1：{n} 字节（{ct1.hex()[:64]}{'…' if n > 32 else ''}）",
        f"密文 2：{n} 字节（{ct2.hex()[:64]}{'…' if n > 32 else ''}）",
        f"分组长度推断：{guess}",
    ]
    if aligned:
        lines.append(f"分组数量：{len(blk1)}，不重复分组：{uniq}，重复分组：{dup}，两组同偏移相同分组：{cross_same}")
    lines.append(f"逐字节差异：{diff_bytes}/{n}（{diff_ratio:.1%}），相同字节：{same_bytes}，公共前缀：{prefix} 字节")
    lines.append("")
    lines.append("===== 证据与置信度 =====")
    for item in evidence:
        if item["weight"] == 0:
            continue
        lines.append(f"[{item['mode']}] {item['weight']:+.2f}  {item['text']}")
    lines.append("")
    lines.append("===== 可能的工作模式 =====")
    for idx, g in enumerate(guesses, 1):
        lines.append(f"{idx}. {g['label']}  置信度 {g['confidence']:.1%}（得分 {g['score']}）")
    lines.append("")
    lines.append("===== 结论与建议 =====")
    lines.append(f"最可能的模式：{MODE_LABEL[top]}。")
    lines.append("检测结果基于密文统计特征推断，仅供参考；建议补充以下验证：")
    lines.append("1) 用相同密钥与 IV、不同明文再加密一组，观察差异是否只出现在首块（ECB 为块内局部化）。")
    lines.append("2) 固定明文、更换 IV 再加密：CBC/CFB 首块会变化，ECB 完全不变。")
    lines.append("3) 构造两个仅首字节不同的明文块：ECB 只影响对应块，CBC 影响其后续全部块。")
    lines.append("4) 若密文长度始终为 16 的整数倍且存在重复块，基本可以判定 ECB。")

    block_diffs = []
    if aligned:
        for idx, (a, b) in enumerate(zip(blk1, blk2)):
            diff_bytes_blk = sum(1 for x, y in zip(a, b) if x != y)
            if diff_bytes_blk == 0:
                kind = "IDENTICAL"
            elif diff_bytes_blk == len(a):
                kind = "COMPLETELY_DIFFERENT"
            else:
                kind = "PARTIALLY_DIFFERENT"
            block_diffs.append({"blockIndex": idx, "totalBytes": len(a),
                                "differentBytes": diff_bytes_blk, "type": kind})
    identical_blocks = sum(1 for d in block_diffs if d["type"] == "IDENTICAL")
    fully_diff = sum(1 for d in block_diffs if d["type"] == "COMPLETELY_DIFFERENT")
    partly_diff = sum(1 for d in block_diffs if d["type"] == "PARTIALLY_DIFFERENT")

    return {
        "top": top,
        "guesses": guesses,
        "analysisData": {
            "totalBlocks": len(blk1),
            "identicalBlocks": identical_blocks,
            "completelyDifferentBlocks": fully_diff,
            "partiallyDifferentBlocks": partly_diff,
            "blockDifferences": block_diffs,
            "isLastBlockFull": bool(aligned and bs and n % bs == 0),
            "lastBlockSize": (n % bs) or bs if aligned else 0,
            "errorPropagation": fully_diff + partly_diff > 0,
            "hasAuthenticationTag": False,
        },
        "blockSize": bs,
        "aligned": aligned,
        "dupBlocks": dup,
        "crossSameBlocks": cross_same,
        "diffBytes": diff_bytes,
        "diffRatio": round(diff_ratio, 4),
        "prefix": prefix,
        "evidence": evidence,
        "detailedAnalysis": "\n".join(lines),
    }


__all__ = [
    "prf", "prf_run", "prf_sm3_hmac", "prf_sm3_direct", "sm3_kdf", "hkdf_sha256", "x963_kdf", "kdf",
    "tlcp_master_secret", "tlcp_key_block",
    "get_curve", "point_operation", "point_add", "point_mul", "point_neg", "point_sub",
    "point_encode", "point_decode", "point_on_curve", "parse_scalar", "CURVE_NAMES",
    "sm2_encrypt", "sm2_decrypt", "sm2_sign", "sm2_verify", "sm2_pubkey_from_priv",
    "sm2_enc_k_analyze", "sm2_k_reuse_compare", "sm2_find_k",
    "unravel_rrss", "unravel_eess", "d_from_two_rrss", "d_from_rsk", "k_from_rsd", "d2_from_rsd1",
    "parse_eess", "rs_to_der", "der_to_rs",
    "pbkdf2", "detect_mode", "MODES",
]
