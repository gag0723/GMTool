"""SM9 标识密码算法（GB/T 38635 / GM/T 0044）—— 纯 Python 实现。

本模块自行实现全部数学运算，不依赖任何第三方密码库（除 SM3 杂凑与 SM4 分组
密码复用 ``gmssl`` 包，与 ``app/core/hashing.py`` 保持一致）。

实现内容
--------
* 256 位 BN 曲线 ``y^2 = x^3 + 5 (mod q)``，群阶 ``N``；
* 塔式扩域 ``Fp2 = Fp[u]/(u^2+2)``、``Fp4 = Fp2[v]/(v^2-u)``、
  ``Fp12 = Fp4[w]/(w^3-v)``；
* ``G1``（Fp 上）与 ``G2``（Fp2 扭曲曲线 ``y^2 = x^3 + 5u`` 上）的点运算，
  采用 Jacobian 射影坐标，标量乘只做一次求逆；
* R-ate 双线性配对（Miller 环长 ``6t+2``，先分子分母分离再统一求逆，
  末次幂指数用 Frobenius 展开，避免大指数直接幂运算）；
* 签名 / 验签、加密 / 解密（流模式与分组模式）、密钥封装 / 解封装、
  主密钥对与用户私钥生成；
* 签名值 ``h||s`` 与 DER 编码互转。

坐标与编码约定（与原站 / GmSSL 一致）
-------------------------------------
* ``Fp2`` 元素 ``a0 + a1*u`` 序列化为 ``a1 || a0``（各 32 字节）；
* ``G1`` 点：``04 || x || y``（65 字节，解析时允许省略 ``04``）；
* ``G2`` 点：``04 || x1 || x0 || y1 || y0``（129 字节，解析时允许省略 ``04``）。

加密与封装格式（与 GM/T 0044 及原站一致）
------------------------------------------
* 密文 ``C = C1(64 字节 x||y) || C3(32 字节) || C2``；
* 流模式：``K = KDF(C1||w||ID, len(M)+32)``，``C2 = M ⊕ K[:len]``；
* 分组模式：``K = KDF(C1||w||ID, 48)``，``C2 = SM4-ECB(K[:16], PKCS#7(M))``；
* 两种模式的完整性校验值均为 ``C3 = SM3(C2 || K2)``，流模式取 ``K[len:]``，
  分组模式取 ``K[16:48]``；
* 密钥封装密文为 65 字节非压缩 G1 点（含 ``04`` 前缀）。
"""
from __future__ import annotations

import os

from gmssl import func as _gm_func
from gmssl import sm3 as _gm_sm3
from gmssl import sm4 as _gm_sm4

from .common import ToolError

# --------------------------------------------------------------------------
# 曲线参数（GB/T 38635.5 / GM/T 0044.5）
# --------------------------------------------------------------------------
P_MOD = 0xB640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D
_HALF = (P_MOD + 1) // 2  # 2 在 Fp 中的逆元
N_ORDER = 0xB640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25
T_TRACE = 0x600000000058F98A
CURVE_B = 5

G1X = 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
G1Y = 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616

HID_SIGN = 0x01
HID_EXCH = 0x02
HID_ENC = 0x03

# Miller 环：6t+2 的有符号二进制表示（最高位隐含在 T=Q 中）
_ATE_BITS = "00100000000000000000000000000000000000010000101100020200101000020"

# 末次幂指数硬部常数
_FE_A2 = 0xD8000000019062ED0000B98B0CB27659
_FE_A3 = 0x2400000000215D941


# --------------------------------------------------------------------------
# 杂凑 / KDF 辅助
# --------------------------------------------------------------------------
def _sm3(data: bytes) -> bytes:
    return bytes.fromhex(_gm_sm3.sm3_hash(_gm_func.bytes_to_list(data)))


def hmac_sm3(key: bytes, data: bytes) -> bytes:
    """HMAC-SM3（RFC 2104 结构）。"""
    block = 64
    if len(key) > block:
        key = _sm3(key)
    key = key.ljust(block, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return _sm3(opad + _sm3(ipad + data))


def sm3_kdf(z: bytes, klen: int) -> bytes:
    """SM3 密钥派生函数：K = SM3(Z || ct)，ct 从 1 开始，输出截断到 klen。"""
    if klen < 0:
        raise ToolError("密钥长度不能为负数")
    if klen == 0:
        return b""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        if ct > 0xFFFFFFFF:
            raise ToolError("密钥长度过大")
        out += _sm3(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


def _modn_from_hash(ha: bytes) -> int:
    """h = (Ha mod (n-1)) + 1，Ha 取 40 字节（320 位）大端整数。"""
    z = int.from_bytes(ha[:40], "big")
    return z % (N_ORDER - 1) + 1


def hash1(user_id: bytes, hid: int) -> int:
    """H1(ID || hid, N)。"""
    z = b"\x01" + user_id + bytes([hid])
    ha = _sm3(z + b"\x00\x00\x00\x01") + _sm3(z + b"\x00\x00\x00\x02")
    return _modn_from_hash(ha)


def hash2(message: bytes, w: bytes) -> int:
    """H2(M || w, N)。"""
    z = b"\x02" + message + w
    ha = _sm3(z + b"\x00\x00\x00\x01") + _sm3(z + b"\x00\x00\x00\x02")
    return _modn_from_hash(ha)


# --------------------------------------------------------------------------
# Fp2 = Fp[u]/(u^2+2)
# --------------------------------------------------------------------------
class Fp2:
    __slots__ = ("a", "b")

    def __init__(self, a: int = 0, b: int = 0):
        self.a = a % P_MOD
        self.b = b % P_MOD

    # -- 构造 ------------------------------------------------------------
    @staticmethod
    def _new(a: int, b: int) -> "Fp2":
        r = Fp2.__new__(Fp2)
        r.a = a % P_MOD
        r.b = b % P_MOD
        return r

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"Fp2({self.a:#x}, {self.b:#x})"

    def __eq__(self, other) -> bool:
        return isinstance(other, Fp2) and self.a == other.a and self.b == other.b

    def __hash__(self) -> int:
        return hash((self.a, self.b))

    def is_zero(self) -> bool:
        return self.a == 0 and self.b == 0

    # -- 运算 ------------------------------------------------------------
    def __add__(self, o: "Fp2") -> "Fp2":
        return Fp2._new(self.a + o.a, self.b + o.b)

    def __sub__(self, o: "Fp2") -> "Fp2":
        return Fp2._new(self.a - o.a, self.b - o.b)

    def __neg__(self) -> "Fp2":
        return Fp2._new(-self.a, -self.b)

    def __mul__(self, o):
        if isinstance(o, int):
            return Fp2._new(self.a * o, self.b * o)
        a0, a1 = self.a, self.b
        b0, b1 = o.a, o.b
        t0 = a0 * b0 % P_MOD
        t1 = a1 * b1 % P_MOD
        return Fp2._new(t0 - 2 * t1, (a0 + a1) * (b0 + b1) - t0 - t1)

    __rmul__ = __mul__

    def mul_u(self) -> "Fp2":
        """乘 u：u*(a+b u) = -2b + a u。"""
        return Fp2._new(-2 * self.b, self.a)

    def sqr(self) -> "Fp2":
        a0, a1 = self.a, self.b
        t = a0 * a1 % P_MOD
        return Fp2._new((a0 + a1) * (a0 - 2 * a1) + t, 2 * t)

    def conj(self) -> "Fp2":
        return Fp2._new(self.a, -self.b)

    def inv(self) -> "Fp2":
        a0, a1 = self.a, self.b
        norm = (a0 * a0 + 2 * a1 * a1) % P_MOD
        if norm == 0:
            raise ToolError("SM9 运算中出现零元求逆")
        inv_norm = pow(norm, P_MOD - 2, P_MOD)
        return Fp2._new(a0 * inv_norm, -a1 * inv_norm)

    def __truediv__(self, o: "Fp2") -> "Fp2":
        return self * o.inv()

    def __pow__(self, e: int) -> "Fp2":
        result = Fp2(1, 0)
        base = self
        while e > 0:
            if e & 1:
                result = result * base
            base = base.sqr()
            e >>= 1
        return result

    def to_bytes(self) -> bytes:
        """序列化：a1 || a0。"""
        return self.b.to_bytes(32, "big") + self.a.to_bytes(32, "big")

    @staticmethod
    def from_bytes(data: bytes) -> "Fp2":
        if len(data) != 64:
            raise ToolError("Fp2 元素长度必须为 64 字节")
        b = int.from_bytes(data[:32], "big")
        a = int.from_bytes(data[32:], "big")
        if a >= P_MOD or b >= P_MOD:
            raise ToolError("Fp2 元素超出基域范围")
        return Fp2(a, b)

    def to_hex(self) -> str:
        return self.to_bytes().hex()


FP2_ZERO = Fp2(0, 0)
FP2_ONE = Fp2(1, 0)


# --------------------------------------------------------------------------
# Fp4 = Fp2[v]/(v^2-u)
# --------------------------------------------------------------------------
class Fp4:
    __slots__ = ("a0", "a1")

    def __init__(self, a0: Fp2 | None = None, a1: Fp2 | None = None):
        self.a0 = a0 if a0 is not None else FP2_ZERO
        self.a1 = a1 if a1 is not None else FP2_ZERO

    def __repr__(self) -> str:  # pragma: no cover
        return f"Fp4({self.a0!r}, {self.a1!r})"

    def __eq__(self, other) -> bool:
        return isinstance(other, Fp4) and self.a0 == other.a0 and self.a1 == other.a1

    def is_zero(self) -> bool:
        return self.a0.is_zero() and self.a1.is_zero()

    def __add__(self, o: "Fp4") -> "Fp4":
        return Fp4(self.a0 + o.a0, self.a1 + o.a1)

    def __sub__(self, o: "Fp4") -> "Fp4":
        return Fp4(self.a0 - o.a0, self.a1 - o.a1)

    def __neg__(self) -> "Fp4":
        return Fp4(-self.a0, -self.a1)

    def __mul__(self, o: "Fp4") -> "Fp4":
        a0, a1 = self.a0, self.a1
        b0, b1 = o.a0, o.a1
        m0 = a0 * b0
        m1 = a1 * b1
        m2 = (a0 + a1) * (b0 + b1) - m0 - m1
        return Fp4(m0 + m1.mul_u(), m2)

    def mul_v(self) -> "Fp4":
        """乘 v：v*(a0+a1 v) = a1*u + a0*v。"""
        return Fp4(self.a1.mul_u(), self.a0)

    def sqr(self) -> "Fp4":
        return self * self

    def conj(self) -> "Fp4":
        """Fp4 在 Fp2 上的共轭（即 v -> -v）。"""
        return Fp4(self.a0, -self.a1)

    def inv(self) -> "Fp4":
        a0, a1 = self.a0, self.a1
        norm = a0 * a0 - (a1 * a1).mul_u()
        inv_norm = norm.inv()
        return Fp4(a0 * inv_norm, -(a1 * inv_norm))

    def __truediv__(self, o: "Fp4") -> "Fp4":
        return self * o.inv()

    def to_bytes(self) -> bytes:
        return self.a1.to_bytes() + self.a0.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> "Fp4":
        if len(data) != 128:
            raise ToolError("Fp4 元素长度必须为 128 字节")
        return Fp4(Fp2.from_bytes(data[64:]), Fp2.from_bytes(data[:64]))


FP4_ZERO = Fp4()
FP4_ONE = Fp4(FP2_ONE)


# --------------------------------------------------------------------------
# Fp12 = Fp4[w]/(w^3-v)
# --------------------------------------------------------------------------
class Fp12:
    __slots__ = ("a0", "a1", "a2")

    def __init__(self, a0: Fp4 | None = None, a1: Fp4 | None = None, a2: Fp4 | None = None):
        self.a0 = a0 if a0 is not None else FP4_ZERO
        self.a1 = a1 if a1 is not None else FP4_ZERO
        self.a2 = a2 if a2 is not None else FP4_ZERO

    def __repr__(self) -> str:  # pragma: no cover
        return f"Fp12({self.a0!r}, {self.a1!r}, {self.a2!r})"

    def __eq__(self, other) -> bool:
        return (isinstance(other, Fp12) and self.a0 == other.a0
                and self.a1 == other.a1 and self.a2 == other.a2)

    def is_one(self) -> bool:
        return self.a0 == FP4_ONE and self.a1.is_zero() and self.a2.is_zero()

    def __add__(self, o: "Fp12") -> "Fp12":
        return Fp12(self.a0 + o.a0, self.a1 + o.a1, self.a2 + o.a2)

    def __sub__(self, o: "Fp12") -> "Fp12":
        return Fp12(self.a0 - o.a0, self.a1 - o.a1, self.a2 - o.a2)

    def __neg__(self) -> "Fp12":
        return Fp12(-self.a0, -self.a1, -self.a2)

    def __mul__(self, o: "Fp12") -> "Fp12":
        a0, a1, a2 = self.a0, self.a1, self.a2
        b0, b1, b2 = o.a0, o.a1, o.a2
        m0 = a0 * b0
        m1 = a1 * b1
        m2 = a2 * b2
        # w^3 = v
        t = (a1 + a2) * (b1 + b2) - m1 - m2
        r0 = m0 + t.mul_v()
        r2 = (a0 + a2) * (b0 + b2) - m0 - m2 + m1
        r1 = (a0 + a1) * (b0 + b1) - m0 - m1 + m2.mul_v()
        return Fp12(r0, r1, r2)

    def sqr(self) -> "Fp12":
        return self * self

    def inv(self) -> "Fp12":
        a0, a1, a2 = self.a0, self.a1, self.a2
        c0 = a0 * a0 - (a1 * a2).mul_v()
        c1 = (a2 * a2).mul_v() - a0 * a1
        c2 = a1 * a1 - a0 * a2
        norm = a0 * c0 + (a2 * c1 + a1 * c2).mul_v()
        inv_norm = norm.inv()
        return Fp12(c0 * inv_norm, c1 * inv_norm, c2 * inv_norm)

    def __truediv__(self, o: "Fp12") -> "Fp12":
        return self * o.inv()

    def __pow__(self, e: int) -> "Fp12":
        if e < 0:
            return self.inv() ** (-e)
        result = Fp12(FP4_ONE)
        base = self
        while e > 0:
            if e & 1:
                result = result * base
            base = base.sqr()
            e >>= 1
        return result

    def mul_line(self, l0: Fp2, l1: Fp2, l4: Fp2) -> "Fp12":
        """乘以稀疏元素 (l0 + l1*v) + l4*w^2（配对直线函数）。"""
        a0, a1, a2 = self.a0, self.a1, self.a2
        L0 = Fp4(l0, l1)
        L2 = Fp4(l4, FP2_ZERO)
        m0 = a0 * L0
        m2 = a2 * L2
        r0 = m0 + ((a1 + a2) * L2 - m2).mul_v()
        r1 = (a0 + a1) * L0 - m0 + m2.mul_v()
        r2 = (a0 + a2) * (L0 + L2) - m0 - m2
        return Fp12(r0, r1, r2)

    def mul_vf(self, c: Fp2) -> "Fp12":
        """乘以 c*v（c ∈ Fp2），用于累积配对分母。"""
        return self * Fp12(Fp4(FP2_ZERO, c))

    def to_bytes(self) -> bytes:
        return self.a2.to_bytes() + self.a1.to_bytes() + self.a0.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> "Fp12":
        if len(data) != 384:
            raise ToolError("Fp12 元素长度必须为 384 字节")
        return Fp12(
            Fp4.from_bytes(data[256:]),
            Fp4.from_bytes(data[128:256]),
            Fp4.from_bytes(data[:128]),
        )


FP12_ONE = Fp12(FP4_ONE)


# --------------------------------------------------------------------------
# Frobenius（惰性推导常数：v^p = beta*v，w^p = delta*w）
# --------------------------------------------------------------------------
_FROB_CACHE: dict = {}


def _fp4_pow(a: Fp4, e: int) -> Fp4:
    result = FP4_ONE
    base = a
    while e > 0:
        if e & 1:
            result = result * base
        base = base * base
        e >>= 1
    return result


def _frob_consts() -> tuple[Fp2, Fp4, Fp4]:
    """返回 (beta, delta, delta^2)。首次调用时按定义计算并缓存。"""
    if not _FROB_CACHE:
        # v^p：v 在 Fp4 中表示为 (0, 1)
        vp = _fp4_pow(Fp4(FP2_ZERO, FP2_ONE), P_MOD)
        beta = vp.a1
        # w^p：w 在 Fp12 中表示为 (0, (1,0), 0)
        wp = Fp12(FP4_ZERO, Fp4(FP2_ONE), FP4_ZERO) ** P_MOD
        delta = wp.a1
        _FROB_CACHE["beta"] = beta
        _FROB_CACHE["delta"] = delta
        _FROB_CACHE["delta2"] = delta * delta
    return _FROB_CACHE["beta"], _FROB_CACHE["delta"], _FROB_CACHE["delta2"]


def _fp4_frob(a: Fp4) -> Fp4:
    beta, _, _ = _frob_consts()
    return Fp4(a.a0.conj(), a.a1.conj() * beta)


def fp12_frob(x: Fp12) -> Fp12:
    """x -> x^p。"""
    _, delta, delta2 = _frob_consts()
    return Fp12(_fp4_frob(x.a0), _fp4_frob(x.a1) * delta, _fp4_frob(x.a2) * delta2)


def fp12_frob2(x: Fp12) -> Fp12:
    return fp12_frob(fp12_frob(x))


def fp12_frob3(x: Fp12) -> Fp12:
    return fp12_frob(fp12_frob2(x))


def fp12_frob6(x: Fp12) -> Fp12:
    return fp12_frob3(fp12_frob3(x))


def _final_exponent_hard(f: Fp12) -> Fp12:
    t0 = f ** _FE_A3
    t0 = t0.inv()
    t1 = fp12_frob(t0)
    t1 = t0 * t1
    t0 = t0 * t1
    t2 = fp12_frob(f)
    t3 = t2 * f
    t3 = t3 ** 9
    t0 = t0 * t3
    t3 = f.sqr().sqr()
    t0 = t0 * t3
    t2 = t2.sqr() * t1
    t1 = fp12_frob2(f) * t2
    t2 = t1 ** _FE_A2
    t0 = t2 * t0
    t1 = fp12_frob3(f)
    return t1 * t0


def final_exponent(f: Fp12) -> Fp12:
    """末次幂：f -> f^((p^12-1)/N)。"""
    t0 = fp12_frob6(f) * f.inv()
    t0 = t0 * fp12_frob2(t0)
    return _final_exponent_hard(t0)


# --------------------------------------------------------------------------
# G1：Fp 上 y^2 = x^3 + 5（Jacobian 射影坐标）
# --------------------------------------------------------------------------
class G1Point:
    """Jacobian 坐标 (X : Y : Z)，仿射点 (x, y) = (X/Z^2, Y/Z^3)。"""

    __slots__ = ("X", "Y", "Z")

    def __init__(self, X: int = 0, Y: int = 1, Z: int = 0):
        self.X = X % P_MOD
        self.Y = Y % P_MOD
        self.Z = Z % P_MOD

    @staticmethod
    def from_affine(x: int, y: int) -> "G1Point":
        return G1Point(x, y, 1)

    def is_infinity(self) -> bool:
        return self.Z % P_MOD == 0

    def to_affine(self) -> tuple[int, int]:
        if self.is_infinity():
            raise ToolError("SM9 点运算结果为单位元，无法转换为仿射坐标")
        z_inv = pow(self.Z, P_MOD - 2, P_MOD)
        z_inv2 = z_inv * z_inv % P_MOD
        x = self.X * z_inv2 % P_MOD
        y = self.Y * z_inv2 % P_MOD * z_inv % P_MOD
        return x, y

    def __eq__(self, other) -> bool:
        if not isinstance(other, G1Point):
            return NotImplemented
        if self.is_infinity() or other.is_infinity():
            return self.is_infinity() and other.is_infinity()
        x1, y1 = self.to_affine()
        x2, y2 = other.to_affine()
        return x1 == x2 and y1 == y2

    def __neg__(self) -> "G1Point":
        return G1Point(self.X, -self.Y, self.Z)

    def dbl(self) -> "G1Point":
        if self.is_infinity() or self.Y % P_MOD == 0:
            return G1Point(0, 1, 0)
        p = P_MOD
        X1, Y1, Z1 = self.X, self.Y, self.Z
        T2 = 3 * X1 * X1 % p
        Y3 = 2 * Y1 % p
        Z3 = Y3 * Z1 % p
        Y3 = Y3 * Y3 % p
        T3 = Y3 * X1 % p
        Y3 = Y3 * Y3 % p * _HALF % p  # /2
        X3 = T2 * T2 % p
        T1 = 2 * T3 % p
        X3 = (X3 - T1) % p
        T1 = (T3 - X3) % p
        T1 = T1 * T2 % p
        Y3 = (T1 - Y3) % p
        return G1Point(X3, Y3, Z3)

    def add(self, other: "G1Point") -> "G1Point":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        p = P_MOD
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X2, Y2, Z2 = other.X, other.Y, other.Z
        T1 = Z1 * Z1 % p
        T2 = Z2 * Z2 % p
        T3 = X2 * T1 % p
        T4 = X1 * T2 % p
        T5 = (T3 + T4) % p
        T3 = (T3 - T4) % p
        T1 = T1 * Z1 % p * Y2 % p
        T2 = T2 * Z2 % p * Y1 % p
        T6 = (T1 + T2) % p
        T1 = (T1 - T2) % p
        if T1 == 0 and T3 == 0:
            return self.dbl()
        if T1 == 0 and T6 == 0:
            return G1Point(0, 1, 0)
        T6 = T1 * T1 % p
        T7 = T3 * Z1 % p * Z2 % p
        T8 = T3 * T3 % p
        T5 = T5 * T8 % p
        T3 = T3 * T8 % p
        T4 = T4 * T8 % p
        T6 = (T6 - T5) % p
        T4 = (T4 - T6) % p
        T1 = T1 * T4 % p
        T2 = T2 * T3 % p
        T1 = (T1 - T2) % p
        return G1Point(T6, T1, T7)

    def mul(self, k: int) -> "G1Point":
        k %= N_ORDER
        result = G1Point(0, 1, 0)
        addend = self
        while k > 0:
            if k & 1:
                result = result.add(addend)
            addend = addend.dbl()
            k >>= 1
        return result

    def to_bytes(self, prefix: bool = True) -> bytes:
        x, y = self.to_affine()
        raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
        return (b"\x04" + raw) if prefix else raw


G1_GENERATOR = G1Point.from_affine(G1X, G1Y)


def g1_from_bytes(data: bytes) -> G1Point:
    if len(data) == 65:
        if data[0] != 0x04:
            raise ToolError("G1 点编码前缀必须为 04（非压缩格式）")
        data = data[1:]
    if len(data) != 64:
        raise ToolError("G1 点长度必须为 64 或 65 字节")
    x = int.from_bytes(data[:32], "big")
    y = int.from_bytes(data[32:], "big")
    if x >= P_MOD or y >= P_MOD:
        raise ToolError("G1 点坐标超出基域范围")
    if (y * y - (x * x * x + CURVE_B)) % P_MOD != 0:
        raise ToolError("G1 点不在曲线上")
    return G1Point.from_affine(x, y)


# --------------------------------------------------------------------------
# G2：Fp2 上扭曲曲线 y^2 = x^3 + 5u（Jacobian 射影坐标）
# --------------------------------------------------------------------------
G2X_A0 = 0x3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B
G2X_A1 = 0x85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141
G2Y_A0 = 0xA7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7
G2Y_A1 = 0x17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96


class G2Point:
    __slots__ = ("X", "Y", "Z")

    def __init__(self, X: Fp2 | None = None, Y: Fp2 | None = None, Z: Fp2 | None = None):
        self.X = X if X is not None else FP2_ZERO
        self.Y = Y if Y is not None else FP2_ONE
        self.Z = Z if Z is not None else FP2_ZERO

    @staticmethod
    def from_affine(x: Fp2, y: Fp2) -> "G2Point":
        return G2Point(x, y, FP2_ONE)

    def is_infinity(self) -> bool:
        return self.Z.is_zero()

    def to_affine(self) -> tuple[Fp2, Fp2]:
        if self.is_infinity():
            raise ToolError("SM9 点运算结果为单位元，无法转换为仿射坐标")
        z_inv = self.Z.inv()
        z_inv2 = z_inv * z_inv
        x = self.X * z_inv2
        y = self.Y * z_inv2 * z_inv
        return x, y

    def __eq__(self, other) -> bool:
        if not isinstance(other, G2Point):
            return NotImplemented
        if self.is_infinity() or other.is_infinity():
            return self.is_infinity() and other.is_infinity()
        x1, y1 = self.to_affine()
        x2, y2 = other.to_affine()
        return x1 == x2 and y1 == y2

    def __neg__(self) -> "G2Point":
        return G2Point(self.X, -self.Y, self.Z)

    def dbl(self) -> "G2Point":
        if self.is_infinity() or self.Y.is_zero():
            return G2Point(FP2_ZERO, FP2_ONE, FP2_ZERO)
        X1, Y1, Z1 = self.X, self.Y, self.Z
        T2 = (X1.sqr()) * 3
        Y3 = Y1 + Y1
        Z3 = Y3 * Z1
        Y3 = Y3.sqr()
        T3 = Y3 * X1
        Y3 = Y3.sqr() * _HALF
        X3 = T2.sqr()
        T1 = T3 + T3
        X3 = X3 - T1
        T1 = T3 - X3
        T1 = T1 * T2
        Y3 = T1 - Y3
        return G2Point(X3, Y3, Z3)

    def add(self, other: "G2Point") -> "G2Point":
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        X1, Y1, Z1 = self.X, self.Y, self.Z
        X2, Y2, Z2 = other.X, other.Y, other.Z
        T1 = Z1.sqr()
        T2 = Z2.sqr()
        T3 = X2 * T1
        T4 = X1 * T2
        T5 = T3 + T4
        T3 = T3 - T4
        T1 = T1 * Z1 * Y2
        T2 = T2 * Z2 * Y1
        T6 = T1 + T2
        T1 = T1 - T2
        if T1.is_zero() and T3.is_zero():
            return self.dbl()
        if T1.is_zero() and T6.is_zero():
            return G2Point(FP2_ZERO, FP2_ONE, FP2_ZERO)
        T6 = T1.sqr()
        T7 = T3 * Z1 * Z2
        T8 = T3.sqr()
        T5 = T5 * T8
        T3 = T3 * T8
        T4 = T4 * T8
        T6 = T6 - T5
        T4 = T4 - T6
        T1 = T1 * T4
        T2 = T2 * T3
        T1 = T1 - T2
        return G2Point(T6, T1, T7)

    def mul(self, k: int) -> "G2Point":
        k %= N_ORDER
        result = G2Point(FP2_ZERO, FP2_ONE, FP2_ZERO)
        addend = self
        while k > 0:
            if k & 1:
                result = result.add(addend)
            addend = addend.dbl()
            k >>= 1
        return result

    def to_bytes(self, prefix: bool = True) -> bytes:
        x, y = self.to_affine()
        raw = x.to_bytes() + y.to_bytes()
        return (b"\x04" + raw) if prefix else raw


G2_GENERATOR = G2Point.from_affine(Fp2(G2X_A0, G2X_A1), Fp2(G2Y_A0, G2Y_A1))


def g2_from_bytes(data: bytes) -> G2Point:
    if len(data) == 129:
        if data[0] != 0x04:
            raise ToolError("G2 点编码前缀必须为 04（非压缩格式）")
        data = data[1:]
    if len(data) != 128:
        raise ToolError("G2 点长度必须为 128 或 129 字节")
    x = Fp2.from_bytes(data[:64])
    y = Fp2.from_bytes(data[64:])
    # y^2 = x^3 + 5u
    if not (y.sqr() == x.sqr() * x + Fp2(0, CURVE_B)):
        raise ToolError("G2 点不在扭曲曲线上")
    return G2Point.from_affine(x, y)


# --------------------------------------------------------------------------
# R-ate 双线性配对
# --------------------------------------------------------------------------
def _twist_line_tangent(T: G2Point, xq: int, yq: int):
    """T 处切线：返回稀疏分子 (a0, a1, a4) 与分母系数 b1。

    分子 = (a0 + a1*v) + a4*w^2，分母 = b1*v，均在 Fp12 中。
    """
    XP, YP, ZP = T.X, T.Y, T.Z
    t0 = ZP.sqr()
    t1 = t0 * ZP
    b1 = t1 * YP                     # 分母 b1*v = Y*Z^3*v
    a1 = -(b1 * yq)                  # -Y*Z^3*y
    t1 = XP.sqr()
    t0 = t0 * t1
    a4 = (t0 * xq) * 3 * _HALF       # 1.5*X^2*Z^2*x
    t1 = t1 * XP * 3 * _HALF         # 1.5*X^3
    a0 = YP.sqr() - t1
    return a0, a1, a4, b1


def _twist_line_secant(T: G2Point, P: G2Point, xq: int, yq: int):
    """T、P 连线：返回稀疏分子 (a0, a1, a4) 与分母系数 b1。"""
    XP, YP, ZP = P.X, P.Y, P.Z
    XT, YT, ZT = T.X, T.Y, T.Z
    T0 = ZP.sqr()
    T1 = T0 * XT
    T0 = T0 * ZP
    T2 = ZT.sqr()
    T3 = T2 * XP
    T2 = T2 * ZT * YP
    T1 = T1 - T3
    T1 = T1 * ZT * ZP
    T4 = T1 * T0
    b1 = T4
    T1 = T1 * YP
    T3 = T0 * YT - T2
    T0 = T0 * T3 * xq
    a4 = T0
    T3 = T3 * XP * ZP
    a0 = T1 - T3
    a1 = -(b1 * yq)
    return a0, a1, a4, b1


def _miller_loop(q: G2Point, p: G1Point) -> Fp12:
    xq, yq = p.to_affine()
    T = q
    f_num = FP12_ONE
    f_den = FP4_ONE
    neg_q = -q
    for ch in _ATE_BITS:
        f_num = f_num.sqr()
        l0, l1, l4, d = _twist_line_tangent(T, xq, yq)
        f_num = f_num.mul_line(l0, l1, l4)
        f_den = f_den * Fp4(FP2_ZERO, d)
        T = T.dbl()
        if ch == "1":
            l0, l1, l4, d = _twist_line_secant(T, q, xq, yq)
            f_num = f_num.mul_line(l0, l1, l4)
            f_den = f_den * Fp4(FP2_ZERO, d)
            T = T.add(q)
        elif ch == "2":
            l0, l1, l4, d = _twist_line_secant(T, neg_q, xq, yq)
            f_num = f_num.mul_line(l0, l1, l4)
            f_den = f_den * Fp4(FP2_ZERO, d)
            T = T.add(neg_q)

    # 两个 Frobenius 附加直线
    q1 = G2Point(q.X.conj(), q.Y.conj(), q.Z.conj() * _PI1_C)
    q2 = G2Point(q.X, -q.Y, q.Z * _PI2_C)
    for extra in (q1, q2):
        l0, l1, l4, d = _twist_line_secant(T, extra, xq, yq)
        f_num = f_num.mul_line(l0, l1, l4)
        f_den = f_den * Fp4(FP2_ZERO, d)
        T = T.add(extra)

    return f_num * Fp12(f_den).inv()


def _pairing_miller(q: G2Point, p: G1Point) -> Fp12:
    return final_exponent(_miller_loop(q, p))


_PI1_C = 0x3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B
_PI2_C = 0xF300000002A3A6F2780272354F8B78F4D5FC11967BE65334

_PAIRING_CACHE: dict = {}
_PAIRING_CACHE_MAX = 32


def pairing(q: G2Point, p: G1Point) -> Fp12:
    """R-ate 配对 e(P, Q)，其中 p ∈ G1、q ∈ G2。

    结果按 (G2 编码, G1 编码) 缓存，签名/验签时 e(P1, Ppubs) 会被复用。
    """
    key = (q.to_bytes(), p.to_bytes())
    hit = _PAIRING_CACHE.get(key)
    if hit is not None:
        return hit
    value = _pairing_miller(q, p)
    if len(_PAIRING_CACHE) >= _PAIRING_CACHE_MAX:
        _PAIRING_CACHE.pop(next(iter(_PAIRING_CACHE)))
    _PAIRING_CACHE[key] = value
    return value


# --------------------------------------------------------------------------
# 主密钥、用户私钥
# --------------------------------------------------------------------------
def rand_scalar() -> int:
    while True:
        k = int.from_bytes(os.urandom(32), "big") % N_ORDER
        if k:
            return k


def generate_master_keypair(kind: str = "SIGN") -> dict:
    """生成主密钥对。kind: SIGN（签名）或 ENC（加密）。"""
    kind = (kind or "SIGN").upper()
    if kind not in ("SIGN", "ENC"):
        raise ToolError("主密钥类型只能为 SIGN 或 ENC")
    k = rand_scalar()
    if kind == "SIGN":
        pub = G2_GENERATOR.mul(k)
        return {"type": kind, "privateKey": f"{k:064X}", "publicKey": pub.to_bytes().hex().upper()}
    pub = G1_GENERATOR.mul(k)
    return {"type": kind, "privateKey": f"{k:064X}", "publicKey": pub.to_bytes().hex().upper()}


def generate_user_key(master_priv: int, user_id: bytes, key_type) -> bytes:
    """由主私钥与用户标识派生用户私钥（key_type: 1 签名 / 2 交换 / 3 加密）。"""
    try:
        kt = int(key_type)
    except (TypeError, ValueError):
        raise ToolError("用户私钥类型必须为 1、2 或 3")
    if kt not in (1, 2, 3):
        raise ToolError("用户私钥类型只能为 1（签名）、2（密钥交换加密）或 3（解密与解封加密）")
    if master_priv <= 0 or master_priv >= N_ORDER:
        raise ToolError("主私钥必须为 1 到 N-1 之间的整数")
    hid = {1: HID_SIGN, 2: HID_EXCH, 3: HID_ENC}[kt]
    t = (hash1(user_id, hid) + master_priv) % N_ORDER
    if t == 0:
        raise ToolError("用户私钥派生失败（t1 为 0），请更换主密钥")
    t = master_priv * pow(t, N_ORDER - 2, N_ORDER) % N_ORDER
    if kt == 1:
        return G1_GENERATOR.mul(t).to_bytes()
    return G2_GENERATOR.mul(t).to_bytes()


# --------------------------------------------------------------------------
# 签名 / 验签
# --------------------------------------------------------------------------
def _sign_g(pub: G2Point) -> Fp12:
    return pairing(pub, G1_GENERATOR)


def sign(master_pub: G2Point, user_priv: G1Point, user_id: bytes,
         message: bytes, rand: int | None = None) -> bytes:
    """SM9 签名，返回 h||s（32 + 65 = 97 字节，s 带 04 前缀）。"""
    if message is None:
        message = b""
    g = _sign_g(master_pub)
    r = rand if rand is not None else rand_scalar()
    if r <= 0 or r >= N_ORDER:
        raise ToolError("随机数 r 必须为 1 到 N-1 之间的整数")
    while True:
        w = g ** r
        h = hash2(message, w.to_bytes())
        l = (r - h) % N_ORDER
        if l != 0:
            break
        r = rand_scalar()
    s = user_priv.mul(l)
    return h.to_bytes(32, "big") + s.to_bytes()


def verify(master_pub: G2Point, user_id: bytes, message: bytes, signature: bytes) -> bool:
    """SM9 验签。signature 为 h||s（97 字节或 96 字节无前缀）。"""
    if len(signature) in (96, 97):
        h_raw = signature[:32]
        s_raw = signature[32:]
    else:
        raise ToolError("签名值长度错误，应为 h||s 格式（96 或 97 字节）")
    h = int.from_bytes(h_raw, "big")
    if h <= 0 or h >= N_ORDER:
        return False
    try:
        s = g1_from_bytes(s_raw)
    except ToolError:
        return False
    g = _sign_g(master_pub)
    t = g ** h
    h1 = hash1(user_id, HID_SIGN)
    p2 = G2_GENERATOR.mul(h1).add(master_pub)
    u = pairing(p2, s)
    w = u * t
    h2 = hash2(message, w.to_bytes())
    return h2 == h


# --------------------------------------------------------------------------
# 加密 / 解密
# --------------------------------------------------------------------------
MODE_STREAM = "STREAM"
MODE_BLOCK = "BLOCK"


def _enc_g(pub: G1Point) -> Fp12:
    return pairing(G2_GENERATOR, pub)


def _sm4_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """SM4-ECB 加密（输入须为 16 字节整数倍）。"""
    if not data or len(data) % 16:
        raise ToolError("SM4 输入长度必须为 16 的整数倍")
    cipher = _gm_sm4.CryptSM4()
    cipher.padding_mode = None          # 关闭 gmssl 自带填充，交由调用方处理
    cipher.set_key(key, _gm_sm4.SM4_ENCRYPT)
    return cipher.crypt_ecb(data)


def _sm4_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ToolError("SM4 密文长度必须为 16 的整数倍")
    cipher = _gm_sm4.CryptSM4()
    cipher.padding_mode = None
    cipher.set_key(key, _gm_sm4.SM4_DECRYPT)
    return cipher.crypt_ecb(data)


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    """PKCS#7 填充：整块时追加一个完整填充块（与原站行为一致）。"""
    n = block - len(data) % block
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise ToolError("分组密文长度必须为 16 的整数倍")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ToolError("分组填充校验失败，密文可能已被篡改")
    return data[:-n]


def _kem_core(pub: G1Point, user_id: bytes, klen: int, rand: int | None = None) -> tuple[bytes, G1Point]:
    q = G1_GENERATOR.mul(hash1(user_id, HID_ENC)).add(pub)
    g = _enc_g(pub)
    r = rand if rand is not None else rand_scalar()
    if r <= 0 or r >= N_ORDER:
        raise ToolError("随机数 r 必须为 1 到 N-1 之间的整数")
    while True:
        c1 = q.mul(r)
        w = g ** r
        k = sm3_kdf(c1.to_bytes(prefix=False) + w.to_bytes() + user_id, klen)
        if k.strip(b"\x00"):
            return k, c1
        r = rand_scalar()


def encrypt(master_pub: G1Point, user_id: bytes, message: bytes,
            mode: str = MODE_STREAM, rand: int | None = None) -> bytes:
    """SM9 加密，返回 C1(64 字节) || C3(32 字节) || C2。"""
    mode = (mode or MODE_STREAM).upper()
    if mode not in (MODE_STREAM, MODE_BLOCK):
        raise ToolError("加密模式只能为 BLOCK（分组）或 STREAM（流）")
    if not message:
        raise ToolError("待加密的消息不能为空")
    if mode == MODE_STREAM:
        k, c1 = _kem_core(master_pub, user_id, len(message) + 32, rand)
        ks, km = k[: len(message)], k[len(message):]
        c2 = bytes(a ^ b for a, b in zip(message, ks))
    else:
        # 分组模式：K[0:16] 为 SM4 密钥，K[16:48] 为完整性校验密钥
        k, c1 = _kem_core(master_pub, user_id, 48, rand)
        c2 = _sm4_ecb_encrypt(k[:16], _pkcs7_pad(message))
        km = k[16:48]
    c3 = _sm3(c2 + km)
    return c1.to_bytes(prefix=False) + c3 + c2


def decrypt(user_priv: G2Point, user_id: bytes, cipher: bytes, mode: str = MODE_STREAM) -> bytes:
    """SM9 解密。"""
    mode = (mode or MODE_STREAM).upper()
    if mode not in (MODE_STREAM, MODE_BLOCK):
        raise ToolError("加密模式只能为 BLOCK（分组）或 STREAM（流）")
    if len(cipher) < 64 + 32:
        raise ToolError("密文长度不足")
    c1 = g1_from_bytes(cipher[:64])
    c3 = cipher[64:96]
    c2 = cipher[96:]
    w = pairing(user_priv, c1)
    if mode == MODE_STREAM:
        klen = len(c2) + 32
    else:
        klen = 48
    k = sm3_kdf(c1.to_bytes(prefix=False) + w.to_bytes() + user_id, klen)
    if mode == MODE_STREAM:
        ks, km = k[: len(c2)], k[len(c2):]
    else:
        ks, km = k[:16], k[16:48]
    if c3 != _sm3(c2 + km):
        raise ToolError("密文完整性校验失败（C3 校验值不匹配）")
    if mode == MODE_STREAM:
        return bytes(a ^ b for a, b in zip(c2, ks))
    return _pkcs7_unpad(_sm4_ecb_decrypt(ks, c2))


# --------------------------------------------------------------------------
# 密钥封装 / 解封装
# --------------------------------------------------------------------------
def kem_encaps(master_pub: G1Point, user_id: bytes, klen: int, rand: int | None = None) -> tuple[bytes, bytes]:
    if klen <= 0 or klen > 1024:
        raise ToolError("密钥长度必须为 1 到 1024 字节")
    k, c1 = _kem_core(master_pub, user_id, klen, rand)
    return k, c1.to_bytes()      # 65 字节（含 04 前缀）


def kem_decaps(user_priv: G2Point, user_id: bytes, cipher: bytes, klen: int) -> bytes:
    if klen <= 0 or klen > 1024:
        raise ToolError("密钥长度必须为 1 到 1024 字节")
    c1 = g1_from_bytes(cipher)
    w = pairing(user_priv, c1)
    k = sm3_kdf(c1.to_bytes(prefix=False) + w.to_bytes() + user_id, klen)
    if not k.strip(b"\x00"):
        raise ToolError("解封装得到全零密钥，密文或标识不匹配")
    return k


# --------------------------------------------------------------------------
# 签名值编码：h||s <-> DER
# --------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def sig_to_der(raw: bytes) -> bytes:
    """h||s -> DER：SEQUENCE { OCTET STRING h(32), BIT STRING s(65) }。"""
    if len(raw) == 96:
        raw = raw[:32] + b"\x04" + raw[32:]
    if len(raw) != 97:
        raise ToolError("裸签名值长度必须为 96 或 97 字节")
    h, s = raw[:32], raw[32:]
    body = b"\x04" + _der_len(len(h)) + h + b"\x03" + _der_len(len(s) + 1) + b"\x00" + s
    return b"\x30" + _der_len(len(body)) + body


def _der_read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(data):
        raise ToolError("DER 数据不完整")
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise ToolError("DER 长度字段非法")
        ln = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + ln > len(data):
        raise ToolError("DER 数据长度不足")
    return tag, data[pos:pos + ln], pos + ln


def sig_from_der(der: bytes) -> bytes:
    """DER -> h||s（97 字节，s 带 04 前缀）。"""
    tag, body, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ToolError("DER 签名缺少 SEQUENCE 头")
    tag, h, pos = _der_read(body, 0)
    if tag != 0x04 or len(h) != 32:
        raise ToolError("DER 签名中的 h 必须为 32 字节 OCTET STRING")
    tag, s, _ = _der_read(body, pos)
    if tag != 0x03 or len(s) != 66 or s[0] != 0:
        raise ToolError("DER 签名中的 s 必须为 65 字节 BIT STRING")
    s = s[1:]
    if len(s) == 65 and s[0] != 0x04:
        raise ToolError("DER 签名中的 s 不是非压缩点编码")
    if len(s) == 64:
        s = b"\x04" + s
    return h + s


# --------------------------------------------------------------------------
# 曲线参数展示
# --------------------------------------------------------------------------
CURVE_INFO = [
    {"key": "curve_equation", "name": "曲线方程", "value": "y^2=x^3+b, 256位BN椭圆曲线"},
    {"key": "curve_t", "name": "嵌入度 t", "value": "60000000 0058F98A"},
    {"key": "curve_q", "name": "素数 q",
     "value": "B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D"},
    {"key": "curve_n", "name": "阶 n",
     "value": "B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25"},
    {"key": "curve_g1_x", "name": "G1生成元 xp1",
     "value": "93DE051D 62BF718F F5ED0704 487D01D6 E1E40869 09DC3280 E8C4E481 7C66DDDD"},
    {"key": "curve_g1_y", "name": "G1生成元 yp1",
     "value": "21FE8DDA 4F21E607 63106512 5C395BBC 1C1C00CB FA602435 0C464CD7 0A3EA616"},
    {"key": "curve_g2_x", "name": "G2生成元 xp2",
     "value": "85AEF3D0 78640C98 597B6027 B441A01F F1DD2C19 0F5E93C4 54806C11 D8806141 "
              "37227552 92130B08 D2AAB97F D34EC120 EE265948 D19C17AB F9B7213B AF82D65B"},
    {"key": "curve_g2_y", "name": "G2生成元 yp2",
     "value": "17509B09 2E845C12 66BA0D26 2CBEE6ED 0736A96F A347C8BD 856DC76B 84EBEB96 "
              "A7CF28D5 19BE3DA6 5F317015 3D278FF2 47EFBA98 A71A0811 6215BBA5 C999A7C7"},
]


__all__ = [
    "P_MOD", "N_ORDER", "CURVE_INFO", "Fp2", "Fp4", "Fp12",
    "G1Point", "G2Point", "G1_GENERATOR", "G2_GENERATOR",
    "pairing", "hash1", "hash2", "sm3_kdf", "hmac_sm3",
    "generate_master_keypair", "generate_user_key",
    "sign", "verify", "encrypt", "decrypt", "kem_encaps", "kem_decaps",
    "sig_to_der", "sig_from_der", "g1_from_bytes", "g2_from_bytes",
]