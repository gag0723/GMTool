"""对称密码算法（全部本地实现，无外部依赖网络）。

覆盖：
    * 分组密码：SM4（GB/T 32907）、AES-128/192/256、DES、3DES-2KEY、3DES-3KEY
    * 工作模式：ECB / CBC / CTR / OFB / CFB / XTS（GB/T 17964-2021 与 IEEE 1619 两种 tweak）
    * 填充：PKCS7、ISO 10126、ISO 7816-4、ANSI X9.23、ZERO、NO PADDING，
            GB/T 17964-2021 附录 C.3（方式二 = ISO/IEC 9797-1 method 2）、
            C.4（方式三 = ISO/IEC 9797-1 method 3）
    * 序列密码：ZUC-128（GM/T 0001，128-EEA3 / 128-EIA3）、ZUC-256（ZUC-256 草案）
    * 认证加密：GCM（SM4-GCM 自行实现 GHASH，AES-GCM 与 pycryptodome 交叉校验）

所有算法均给出可复现的标准向量校验（见 tests/test_sym.py）。
"""
from __future__ import annotations

import os
import struct
from typing import Iterable

from .common import ToolError

# ---------------------------------------------------------------------------
# 常量表
# ---------------------------------------------------------------------------

# GB/T 32907-2016 SM4 S 盒
SM4_SBOX = (
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
)

SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
SM4_CK = tuple(
    ((4 * i + 0) * 7 % 256) << 24 | ((4 * i + 1) * 7 % 256) << 16
    | ((4 * i + 2) * 7 % 256) << 8 | ((4 * i + 3) * 7 % 256)
    for i in range(32)
)

# 算法参数：密钥长度、分组长度
ALGOS = {
    "SM4": (16, 16),
    "AES128": (16, 16),
    "AES192": (24, 16),
    "AES256": (32, 16),
    "DES": (8, 8),
    "DESEDE16": (16, 8),
    "DESEDE24": (24, 8),
}

ALGO_LABEL = {
    "SM4": "SM4",
    "AES128": "AES-128",
    "AES192": "AES-192",
    "AES256": "AES-256",
    "DES": "DES",
    "DESEDE16": "3DES-2KEY",
    "DESEDE24": "3DES-3KEY",
}

MODES = ("ECB", "CBC", "CTR", "OFB", "CFB", "XTS")

PADDINGS = ("PKCS7", "ISO_10126", "ISO7816_4", "ANSIX923", "ZERO", "NOPADDING", "M2", "M3")

_PADDING_ALIAS = {
    "PKCS7": "PKCS7",
    "PKCS5": "PKCS7",
    "ISO_10126": "ISO_10126",
    "ISO10126": "ISO_10126",
    "ISO-10126": "ISO_10126",
    "ISO7816_4": "ISO7816_4",
    "ISO7816-4": "ISO7816_4",
    "ISO78164": "ISO7816_4",
    "ANSIX923": "ANSIX923",
    "ANSIX9.23": "ANSIX923",
    "ANSI_X923": "ANSIX923",
    "ZERO": "ZERO",
    "ZEROS": "ZERO",
    "NOPADDING": "NOPADDING",
    "NO_PADDING": "NOPADDING",
    "NONE": "NOPADDING",
    "M2": "M2",
    "GBM2": "M2",
    "M3": "M3",
    "GBM3": "M3",
}


def _to_u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _rotl32(value: int, n: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << n) | (value >> (32 - n))) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# SM4（GB/T 32907-2016）
# ---------------------------------------------------------------------------


def _sm4_tau(a: int) -> int:
    b = SM4_SBOX
    return (b[(a >> 24) & 0xFF] << 24) | (b[(a >> 16) & 0xFF] << 16) | (b[(a >> 8) & 0xFF] << 8) | b[a & 0xFF]


def _sm4_t(a: int) -> int:
    b = _sm4_tau(a)
    return b ^ _rotl32(b, 2) ^ _rotl32(b, 10) ^ _rotl32(b, 18) ^ _rotl32(b, 24)


def _sm4_t_prime(a: int) -> int:
    b = _sm4_tau(a)
    return b ^ _rotl32(b, 13) ^ _rotl32(b, 23)


def sm4_round_keys(key: bytes) -> list[int]:
    """由 16 字节密钥派生 32 个轮密钥。"""
    if len(key) != 16:
        raise ToolError("SM4 密钥长度必须为 16 字节")
    mk = struct.unpack(">4I", key)
    k = [mk[i] ^ SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        nxt = k[i] ^ _sm4_t_prime(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i])
        k.append(nxt)
        rk.append(nxt)
    return rk


def sm4_encrypt_block(rk: list[int], block: bytes) -> bytes:
    x = list(struct.unpack(">4I", block))
    for i in range(32):
        x.append(x[0] ^ _sm4_t(x[1] ^ x[2] ^ x[3] ^ rk[i]))
        x.pop(0)
    return struct.pack(">4I", x[3], x[2], x[1], x[0])


def sm4_decrypt_block(rk: list[int], block: bytes) -> bytes:
    return sm4_encrypt_block(rk[::-1], block)


def sm4_encrypt_block_with_key(key: bytes, block: bytes) -> bytes:
    """便捷函数：单分组加密（用于标准向量验证）。"""
    return sm4_encrypt_block(sm4_round_keys(key), block)


# ---------------------------------------------------------------------------
# 分组密码对象（统一 block_size / encrypt_block / decrypt_block 接口）
# ---------------------------------------------------------------------------


class BlockCipher:
    block_size = 16

    def encrypt_block(self, block: bytes) -> bytes:  # pragma: no cover - 抽象
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:  # pragma: no cover - 抽象
        raise NotImplementedError


class SM4Cipher(BlockCipher):
    block_size = 16

    def __init__(self, key: bytes):
        self._rk = sm4_round_keys(key)

    def encrypt_block(self, block: bytes) -> bytes:
        return sm4_encrypt_block(self._rk, block)

    def decrypt_block(self, block: bytes) -> bytes:
        return sm4_decrypt_block(self._rk, block)


class _PyBlock(BlockCipher):
    """借助 pycryptodome 的单分组（ECB）封装。"""

    def __init__(self, cipher):
        self._c = cipher
        self.block_size = cipher.block_size

    def encrypt_block(self, block: bytes) -> bytes:
        return self._c.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._c.decrypt(block)


class TripleDESCipher(BlockCipher):
    """3DES（EDE）：2KEY 用 K1|K2|K1，3KEY 用 K1|K2|K3。

    直接以 DES 单分组拼装，避免 pycryptodome 对 2KEY/退化密钥的限制。
    """

    block_size = 8

    def __init__(self, key: bytes, keys: int):
        from Crypto.Cipher import DES

        if keys == 2:
            k1, k2 = key[:8], key[8:16]
            k3 = k1
        else:
            k1, k2, k3 = key[:8], key[8:16], key[16:24]
        self._d1 = DES.new(k1, DES.MODE_ECB)
        self._d2 = DES.new(k2, DES.MODE_ECB)
        self._d3 = DES.new(k3, DES.MODE_ECB)

    def encrypt_block(self, block: bytes) -> bytes:
        return self._d3.encrypt(self._d2.decrypt(self._d1.encrypt(block)))

    def decrypt_block(self, block: bytes) -> bytes:
        return self._d1.decrypt(self._d2.encrypt(self._d3.decrypt(block)))


def get_cipher(algo: str, key: bytes) -> BlockCipher:
    """按算法名创建分组密码对象，并校验密钥长度。"""
    algo = (algo or "SM4").upper()
    if algo not in ALGOS:
        raise ToolError(f"不支持的算法：{algo}")
    key_len, block_len = ALGOS[algo]
    if len(key) != key_len:
        raise ToolError(f"算法 {ALGO_LABEL[algo]} 的密钥长度必须为 {key_len} 字节，当前为 {len(key)} 字节")
    if algo == "SM4":
        return SM4Cipher(key)
    if algo.startswith("AES"):
        from Crypto.Cipher import AES

        return _PyBlock(AES.new(key, AES.MODE_ECB))
    if algo == "DES":
        from Crypto.Cipher import DES

        return _PyBlock(DES.new(key, DES.MODE_ECB))
    if algo == "DESEDE16":
        return TripleDESCipher(key, 2)
    if algo == "DESEDE24":
        return TripleDESCipher(key, 3)
    raise ToolError(f"不支持的算法：{algo}")  # pragma: no cover


def alg_params(algo: str) -> tuple[int, int]:
    algo = (algo or "SM4").upper()
    if algo not in ALGOS:
        raise ToolError(f"不支持的算法：{algo}")
    return ALGOS[algo]


# ---------------------------------------------------------------------------
# 填充
# ---------------------------------------------------------------------------


def normalize_padding(name: str | None) -> str:
    key = (name or "PKCS7").strip().upper().replace(" ", "")
    if key not in _PADDING_ALIAS:
        raise ToolError(f"不支持的填充方式：{name}")
    return _PADDING_ALIAS[key]


def pad(data: bytes, block_size: int, scheme: str) -> bytes:
    scheme = normalize_padding(scheme)
    if scheme == "NOPADDING":
        if block_size and len(data) % block_size:
            raise ToolError(f"NO PADDING 模式下数据长度必须为分组长度（{block_size} 字节）的整数倍")
        return data
    if scheme == "ZERO":
        # 零填充：总是至少补 1 字节，补齐到分组整数倍
        n = block_size - (len(data) % block_size)
        return data + b"\x00" * n
    n = block_size - (len(data) % block_size)
    if scheme == "PKCS7":
        return data + bytes([n]) * n
    if scheme == "ISO_10126":
        return data + os.urandom(n - 1) + bytes([n])
    if scheme in ("ISO7816_4", "M2"):
        # ISO/IEC 7816-4 与 GB/T 17964-2021 附录 C.3（填充方式二）一致
        return data + b"\x80" + b"\x00" * (n - 1)
    if scheme in ("ANSIX923", "M3"):
        # GB/T 17964-2021 附录 C.4（填充方式三）= ISO/IEC 9797-1 method 3
        return data + b"\x00" * (n - 1) + bytes([n])
    raise ToolError(f"不支持的填充方式：{scheme}")  # pragma: no cover


def unpad(data: bytes, block_size: int, scheme: str) -> bytes:
    scheme = normalize_padding(scheme)
    if scheme == "NOPADDING":
        return data
    if not data or len(data) % block_size:
        raise ToolError("密文长度不是分组长度的整数倍")
    if scheme == "ZERO":
        return data.rstrip(b"\x00")
    if scheme in ("PKCS7",):
        n = data[-1]
        if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
            raise ToolError("PKCS7 填充校验失败")
        return data[:-n]
    if scheme == "ISO_10126":
        n = data[-1]
        if n < 1 or n > block_size:
            raise ToolError("ISO10126 填充校验失败")
        return data[:-n]
    if scheme in ("ISO7816_4", "M2"):
        chunk = data[-block_size:]
        idx = chunk.rfind(b"\x80")
        if idx < 0 or chunk[idx + 1:].strip(b"\x00"):
            raise ToolError("ISO7816-4 填充校验失败")
        return data[: len(data) - block_size + idx]
    if scheme in ("ANSIX923", "M3"):
        n = data[-1]
        if n < 1 or n > block_size:
            raise ToolError("ANSI X9.23 填充校验失败")
        # 只按末字节长度裁切：兼容部分实现用随机字节填充的情形（如原站）
        return data[:-n]
    raise ToolError(f"不支持的填充方式：{scheme}")  # pragma: no cover


# ---------------------------------------------------------------------------
# 工作模式（ECB / CBC / CTR / OFB / CFB）
# ---------------------------------------------------------------------------


def _blocks(data: bytes, size: int) -> Iterable[bytes]:
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _ctr_stream(cipher: BlockCipher, iv: bytes, length: int) -> bytes:
    """CTR 模式的密钥流：计数器按整个分组大端递增。"""
    size = cipher.block_size
    if len(iv) != size:
        raise ToolError(f"CTR 模式的 IV 长度必须为 {size} 字节")
    counter = int.from_bytes(iv, "big")
    out = bytearray()
    while len(out) < length:
        out += cipher.encrypt_block(counter.to_bytes(size, "big"))
        counter = (counter + 1) % (1 << (8 * size))
    return bytes(out[:length])


def _ofb_stream(cipher: BlockCipher, iv: bytes, length: int) -> bytes:
    size = cipher.block_size
    if len(iv) != size:
        raise ToolError(f"OFB 模式的 IV 长度必须为 {size} 字节")
    out = bytearray()
    reg = iv
    while len(out) < length:
        reg = cipher.encrypt_block(reg)
        out += reg
    return bytes(out[:length])


def mode_encrypt(cipher: BlockCipher, data: bytes, mode: str, iv: bytes = b"") -> bytes:
    mode = (mode or "ECB").upper()
    size = cipher.block_size
    if mode == "ECB":
        if len(data) % size:
            raise ToolError(f"ECB 模式数据长度必须为 {size} 字节的整数倍")
        return b"".join(cipher.encrypt_block(b) for b in _blocks(data, size))
    if mode == "CBC":
        if len(iv) != size:
            raise ToolError(f"CBC 模式的 IV 长度必须为 {size} 字节")
        if len(data) % size:
            raise ToolError(f"CBC 模式数据长度必须为 {size} 字节的整数倍")
        out = bytearray()
        prev = iv
        for block in _blocks(data, size):
            prev = cipher.encrypt_block(_xor(block, prev))
            out += prev
        return bytes(out)
    if mode == "CTR":
        return _xor(data, _ctr_stream(cipher, iv, len(data)))
    if mode == "OFB":
        return _xor(data, _ofb_stream(cipher, iv, len(data)))
    if mode == "CFB":
        if len(iv) != size:
            raise ToolError(f"CFB 模式的 IV 长度必须为 {size} 字节")
        out = bytearray()
        reg = iv
        for block in _blocks(data, size):
            ks = cipher.encrypt_block(reg)
            enc = _xor(block, ks)
            out += enc
            reg = enc + ks[len(enc):]
        return bytes(out)
    raise ToolError(f"不支持的工作模式：{mode}")


def mode_decrypt(cipher: BlockCipher, data: bytes, mode: str, iv: bytes = b"") -> bytes:
    mode = (mode or "ECB").upper()
    size = cipher.block_size
    if mode == "ECB":
        if len(data) % size:
            raise ToolError(f"ECB 模式数据长度必须为 {size} 字节的整数倍")
        return b"".join(cipher.decrypt_block(b) for b in _blocks(data, size))
    if mode == "CBC":
        if len(iv) != size:
            raise ToolError(f"CBC 模式的 IV 长度必须为 {size} 字节")
        if len(data) % size:
            raise ToolError(f"CBC 模式数据长度必须为 {size} 字节的整数倍")
        out = bytearray()
        prev = iv
        for block in _blocks(data, size):
            out += _xor(cipher.decrypt_block(block), prev)
            prev = block
        return bytes(out)
    if mode == "CTR":
        return _xor(data, _ctr_stream(cipher, iv, len(data)))
    if mode == "OFB":
        return _xor(data, _ofb_stream(cipher, iv, len(data)))
    if mode == "CFB":
        if len(iv) != size:
            raise ToolError(f"CFB 模式的 IV 长度必须为 {size} 字节")
        out = bytearray()
        reg = iv
        for block in _blocks(data, size):
            ks = cipher.encrypt_block(reg)
            out += _xor(block, ks)
            reg = block + ks[len(block):]
        return bytes(out)
    raise ToolError(f"不支持的工作模式：{mode}")


# ---------------------------------------------------------------------------
# XTS（GB/T 17964-2021 与 IEEE 1619 两种 tweak 乘加约定）
# ---------------------------------------------------------------------------


def _xts_mul_alpha(tweak: bytearray, big_endian: bool) -> None:
    """tweak = tweak * α（GF(2^128)，模 x^128 + x^7 + x^2 + x + 1）。

    IEEE 1619 采用小端字节序（P1619 约定）；GB/T 17964-2021 采用大端字节序。
    """
    carry = 0
    if big_endian:
        # GB/T 17964-2021：tweak 按比特串大端约定参与 GF(2^128) 乘 α，
        # 逐字节右移、进位进入下一字节最高位，溢出时异或 0xE1（0x87 的比特反射）
        for i in range(16):
            nxt = tweak[i] & 1
            tweak[i] = ((tweak[i] >> 1) | (carry << 7)) & 0xFF
            carry = nxt
        if carry:
            tweak[0] ^= 0xE1
    else:
        for i in range(16):
            nxt = tweak[i] >> 7
            tweak[i] = ((tweak[i] << 1) | carry) & 0xFF
            carry = nxt
        if carry:
            tweak[0] ^= 0x87


def xts_encrypt(cipher1: BlockCipher, cipher2: BlockCipher, data: bytes, tweak: bytes, is_gb: bool = True) -> bytes:
    size = cipher1.block_size
    if size != 16:
        raise ToolError("XTS 模式仅支持 16 字节分组的算法（SM4 / AES 系列）")
    if len(tweak) != 16:
        raise ToolError("XTS 模式的 Tweak 长度必须为 16 字节")
    if len(data) < size:
        raise ToolError(f"XTS 模式数据长度至少为 {size} 字节")
    t = bytearray(cipher2.encrypt_block(tweak))
    blocks = [data[i:i + size] for i in range(0, len(data), size)]
    last = blocks[-1]
    out = []
    if len(last) == size:
        for block in blocks:
            out.append(_xor(cipher1.encrypt_block(_xor(block, bytes(t))), bytes(t)))
            _xts_mul_alpha(t, bool(is_gb))
        return b"".join(out)
    # 末尾分组不足：密文挪用（CTS）
    head, penult, tail = blocks[:-2], blocks[-2], blocks[-1]
    for block in head:
        out.append(_xor(cipher1.encrypt_block(_xor(block, bytes(t))), bytes(t)))
        _xts_mul_alpha(t, bool(is_gb))
    t_penult = bytes(t)
    _xts_mul_alpha(t, bool(is_gb))
    t_last = bytes(t)
    cc = _xor(cipher1.encrypt_block(_xor(penult, t_penult)), t_penult)
    c_tail = cc[: len(tail)]
    pp = tail + cc[len(tail):]
    c_penult = _xor(cipher1.encrypt_block(_xor(pp, t_last)), t_last)
    out.append(c_penult)
    out.append(c_tail)
    return b"".join(out)


def xts_decrypt(cipher1: BlockCipher, cipher2: BlockCipher, data: bytes, tweak: bytes, is_gb: bool = True) -> bytes:
    size = cipher1.block_size
    if size != 16:
        raise ToolError("XTS 模式仅支持 16 字节分组的算法（SM4 / AES 系列）")
    if len(tweak) != 16:
        raise ToolError("XTS 模式的 Tweak 长度必须为 16 字节")
    if len(data) < size:
        raise ToolError(f"XTS 模式数据长度至少为 {size} 字节")
    t = bytearray(cipher2.encrypt_block(tweak))
    blocks = [data[i:i + size] for i in range(0, len(data), size)]
    last = blocks[-1]
    out = []
    if len(last) == size:
        for block in blocks:
            out.append(_xor(cipher1.decrypt_block(_xor(block, bytes(t))), bytes(t)))
            _xts_mul_alpha(t, bool(is_gb))
        return b"".join(out)
    head, penult, tail = blocks[:-2], blocks[-2], blocks[-1]
    for block in head:
        out.append(_xor(cipher1.decrypt_block(_xor(block, bytes(t))), bytes(t)))
        _xts_mul_alpha(t, bool(is_gb))
    t_penult = bytes(t)
    _xts_mul_alpha(t, bool(is_gb))
    t_last = bytes(t)
    pp = _xor(cipher1.decrypt_block(_xor(penult, t_last)), t_last)
    plain_tail = pp[: len(tail)]
    cc = tail + pp[len(tail):]
    plain_penult = _xor(cipher1.decrypt_block(_xor(cc, t_penult)), t_penult)
    out.append(plain_penult)
    out.append(plain_tail)
    return b"".join(out)


# ---------------------------------------------------------------------------
# 分组密码统一入口
# ---------------------------------------------------------------------------


def block_crypt(
    algo: str,
    key: bytes,
    mode: str,
    padding: str,
    data: bytes,
    iv: bytes = b"",
    encrypt: bool = True,
    tweak: bytes = b"",
    is_gb: bool = True,
) -> bytes:
    """分组密码加解密统一入口（含填充处理）。"""
    algo = (algo or "SM4").upper()
    mode = (mode or "ECB").upper()
    key_len, block_len = alg_params(algo)
    if mode == "XTS":
        if algo not in ("SM4", "AES128", "AES192", "AES256"):
            raise ToolError("XTS 模式仅支持 SM4 与 AES 系列算法")
        if len(key) != 2 * key_len:
            raise ToolError(f"XTS 模式的密钥长度必须为 {2 * key_len} 字节（双倍长度密钥）")
        c1 = get_cipher(algo, key[:key_len])
        c2 = get_cipher(algo, key[key_len:])
        if encrypt:
            return xts_encrypt(c1, c2, data, tweak, is_gb)
        return xts_decrypt(c1, c2, data, tweak, is_gb)

    if mode not in MODES:
        raise ToolError(f"不支持的工作模式：{mode}")
    cipher = get_cipher(algo, key)
    if mode != "ECB" and len(iv) != block_len:
        raise ToolError(f"算法 {ALGO_LABEL[algo]} 的 IV 长度必须为 {block_len} 字节，当前为 {len(iv)} 字节")
    if mode in ("CTR", "OFB", "CFB") and padding in ("NOPADDING", "NO_PADDING", "NONE", ""):
        # 流模式 + NO PADDING：明文按实际长度加解密（与原站一致）
        if encrypt:
            return mode_encrypt(cipher, data, mode, iv)
        return mode_decrypt(cipher, data, mode, iv)
    if encrypt:
        return mode_encrypt(cipher, pad(data, block_len, padding), mode, iv)
    plain = mode_decrypt(cipher, data, mode, iv)
    return unpad(plain, block_len, padding)


# ---------------------------------------------------------------------------
# ZUC（GM/T 0001 与 ZUC-256 草案）
# ---------------------------------------------------------------------------

ZUC_S0 = (
    0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
    0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
    0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
    0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
    0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
    0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
    0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
    0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
    0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
    0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
    0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
    0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
    0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
    0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
    0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
    0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60,
)

ZUC_S1 = (
    0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
    0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
    0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
    0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
    0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
    0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
    0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
    0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
    0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
    0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
    0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
    0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
    0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2,
)

# ZUC-128 的 15 比特常量 D
ZUC_D128 = (
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC,
)

# ZUC-256 的 7 比特常量（密钥流形态：d0=0x22, d2=0x24）
ZUC_D256_STREAM = (
    0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
)
# MAC 长度对应的 d0 / d2 取值（ZUC-256 草案 / 3GPP TS 35.246 6.2.7）
_ZUC256_MAC_D = {
    32: (0x22, 0x25),
    64: (0x23, 0x24),
    128: (0x23, 0x25),
}

_MASK31 = 0x7FFFFFFF


def _add31(a: int, b: int) -> int:
    c = a + b
    return (c & _MASK31) + (c >> 31)


class ZUC:
    """ZUC-128 / ZUC-256 密钥流发生器（含 MAC）。

    key 16 字节 + IV 16 字节 → ZUC-128；key 32 字节 + IV 25 字节 → ZUC-256。
    """

    def __init__(self, key: bytes, iv: bytes, mac_bits: int = 0):
        if len(key) == 16:
            if len(iv) != 16:
                raise ToolError("ZUC-128 需要 16 字节密钥与 16 字节 IV")
            self.variant = "ZUC128"
            self._load128(key, iv)
        elif len(key) == 32:
            if len(iv) != 25:
                raise ToolError("ZUC-256 需要 32 字节密钥与 25 字节 IV")
            self.variant = "ZUC256"
            self._load256(key, iv, mac_bits)
        else:
            raise ToolError("ZUC 密钥长度必须为 16 字节（ZUC-128）或 32 字节（ZUC-256）")
        self._s = self._s[:]
        self._R1 = 0
        self._R2 = 0
        self._init()

    # -- 密钥装载 ---------------------------------------------------------
    def _load128(self, key: bytes, iv: bytes) -> None:
        self._s = [
            (key[i] << 23) | (ZUC_D128[i] << 8) | iv[i] for i in range(16)
        ]

    def _load256(self, key: bytes, iv: bytes, mac_bits: int) -> None:
        d = list(ZUC_D256_STREAM)
        if mac_bits:
            if mac_bits not in _ZUC256_MAC_D:
                raise ToolError("ZUC-256 的 MAC 长度只支持 32 / 64 / 128 比特")
            d[0], d[2] = _ZUC256_MAC_D[mac_bits]
        k = key
        # IV16..IV24 为 6 比特串（占用字节低 6 位），高 2 位按标准截断
        i0, i1, i2, i3, i4, i5, i6, i7, i8, i9 = (iv[j] for j in range(10))
        i10, i11, i12, i13, i14, i15, i16 = (iv[j] for j in range(10, 17))
        i17 = iv[17] & 0x3F
        i18 = iv[18] & 0x3F
        i19 = iv[19] & 0x3F
        i20 = iv[20] & 0x3F
        i21 = iv[21] & 0x3F
        i22 = iv[22] & 0x3F
        i23 = iv[23] & 0x3F
        i24 = iv[24] & 0x3F

        def cat(a, b, c, e):
            return (a << 23) | (b << 16) | (c << 8) | e

        self._s = [
            cat(k[0], d[0], k[21], k[16]),
            cat(k[1], d[1], k[22], k[17]),
            cat(k[2], d[2], k[23], k[18]),
            cat(k[3], d[3], k[24], k[19]),
            cat(k[4], d[4], k[25], k[20]),
            cat(i0, d[5] | i17, k[5], k[26]),
            cat(i1, d[6] | i18, k[6], k[27]),
            cat(i10, d[7] | i19, k[7], i2),
            cat(k[8], d[8] | i20, i3, i11),
            cat(k[9], d[9] | i21, i12, i4),
            cat(i5, d[10] | i22, k[10], k[28]),
            cat(k[11], d[11] | i23, i6, i13),
            cat(k[12], d[12] | i24, i7, i14),
            cat(k[13], d[13], i15, i8),
            cat(k[14], d[14] | (k[31] >> 4), i16, i9),
            cat(k[15], d[15] | (k[31] & 0x0F), k[30], k[29]),
        ]

    # -- 基本运算 ---------------------------------------------------------
    @staticmethod
    def _mul_pow2(x: int, k: int) -> int:
        return ((x << k) | (x >> (31 - k))) & _MASK31

    def _lfsr_v(self) -> int:
        s = self._s
        v = self._mul_pow2(s[15], 15)
        v = _add31(v, self._mul_pow2(s[13], 17))
        v = _add31(v, self._mul_pow2(s[10], 21))
        v = _add31(v, self._mul_pow2(s[4], 20))
        v = _add31(v, self._mul_pow2(s[0], 8))
        v = _add31(v, s[0])
        return v

    def _lfsr_init_mode(self, u: int) -> None:
        v = _add31(self._lfsr_v(), u)
        if v == 0:
            v = _MASK31
        self._s.pop(0)
        self._s.append(v)

    def _lfsr_work_mode(self) -> None:
        v = self._lfsr_v()
        if v == 0:
            v = _MASK31
        self._s.pop(0)
        self._s.append(v)

    def _bit_reorganization(self) -> None:
        s = self._s
        self.X0 = ((s[15] & 0x7FFF8000) << 1) | (s[14] & 0xFFFF)
        self.X1 = ((s[11] & 0xFFFF) << 16) | (s[9] >> 15)
        self.X2 = ((s[7] & 0xFFFF) << 16) | (s[5] >> 15)
        self.X3 = ((s[2] & 0xFFFF) << 16) | (s[0] >> 15)

    def _f(self) -> int:
        W = _to_u32((self.X0 ^ self._R1) + self._R2)
        W1 = _to_u32(self._R1 + self.X1)
        W2 = self._R2 ^ self.X2
        u = (W1 << 16 | W2 >> 16) & 0xFFFFFFFF
        v = (W2 << 16 | W1 >> 16) & 0xFFFFFFFF
        u = u ^ _rotl32(u, 2) ^ _rotl32(u, 10) ^ _rotl32(u, 18) ^ _rotl32(u, 24)
        v = v ^ _rotl32(v, 8) ^ _rotl32(v, 14) ^ _rotl32(v, 22) ^ _rotl32(v, 30)
        s0, s1 = ZUC_S0, ZUC_S1
        self._R1 = (
            (s0[(u >> 24) & 0xFF] << 24) | (s1[(u >> 16) & 0xFF] << 16)
            | (s0[(u >> 8) & 0xFF] << 8) | s1[u & 0xFF]
        )
        self._R2 = (
            (s0[(v >> 24) & 0xFF] << 24) | (s1[(v >> 16) & 0xFF] << 16)
            | (s0[(v >> 8) & 0xFF] << 8) | s1[v & 0xFF]
        )
        return W

    def _init(self) -> None:
        for _ in range(32):
            self._bit_reorganization()
            w = self._f()
            self._lfsr_init_mode(w >> 1)
        self._bit_reorganization()
        self._f()
        self._lfsr_work_mode()

    def next_word(self) -> int:
        self._bit_reorganization()
        z = self._f() ^ self.X3
        self._lfsr_work_mode()
        return z & 0xFFFFFFFF

    def keystream(self, length: int) -> bytes:
        out = bytearray()
        while len(out) < length:
            out += struct.pack(">I", self.next_word())
        return bytes(out[:length])


def zuc_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """ZUC 加解密（异或密钥流，加解密相同）。"""
    z = ZUC(key, iv)
    return bytes(a ^ b for a, b in zip(data, z.keystream(len(data))))


def _bit_at(data: bytes, index: int) -> int:
    return (data[index >> 3] >> (7 - (index & 7))) & 1


def _window(words: list[int], bitpos: int) -> int:
    """取密钥流比特串中从 bitpos 开始的 32 比特窗口（大端）。"""
    shift = bitpos & 31
    idx = bitpos >> 5
    first = words[idx]
    if shift == 0:
        return first
    second = words[idx + 1]
    return ((first << shift) | (second >> (32 - shift))) & 0xFFFFFFFF


def zuc_mac(key: bytes, iv: bytes, data: bytes, mac_bits: int = 32) -> bytes:
    """ZUC 完整性算法 MAC。

    * ZUC-128：GM/T 0001 / 128-EIA3，输出 4 字节
    * ZUC-256：ZUC-256 草案 / 3GPP TS 35.246 的 256-NIA6，输出 4 / 8 / 16 字节
    """
    nbits = len(data) * 8
    if len(key) == 16:
        if mac_bits not in (0, 32):
            raise ToolError("ZUC-128 仅支持 4 字节（32 比特）MAC")
        z = ZUC(key, iv)
        nwords = (nbits + 64 + 31) // 32
        words = [z.next_word() for _ in range(nwords + 1)]
        t = 0
        for i in range(nbits):
            if _bit_at(data, i):
                t ^= _window(words, i)
        t ^= _window(words, nbits)
        t ^= words[nwords - 1]
        return struct.pack(">I", t & 0xFFFFFFFF)

    if mac_bits not in (32, 64, 128):
        raise ToolError("ZUC-256 的 MAC 长度只支持 4 / 8 / 16 字节")
    # ZUC-256 MAC（3GPP TS 35.246 256-NIA6，参照 GmSSL 参考实现）：
    #   T[0..n-1] = 密钥流前 n 个字；K0[0..n-1] = 后续 n 个字作为滑动窗口；
    #   每个消息比特为 1 时 T[j] ^= K0[j]，随后 K0 整体左移 1 位并补入下一密钥流字；
    #   处理结束后 T[j] ^= K0[j] 输出。
    width = mac_bits // 32
    z = ZUC(key, iv, mac_bits=mac_bits)
    t = [z.next_word() for _ in range(width)]
    k0 = [z.next_word() for _ in range(width)]
    mask = 0xFFFFFFFF
    nbits = len(data) * 8
    for base in range(0, nbits, 32):
        k1 = z.next_word()
        chunk = data[base // 8: base // 8 + 4]
        m = int.from_bytes(chunk + b"\x00" * (4 - len(chunk)), "big")
        bits = min(32, nbits - base)
        for _ in range(bits):
            if m & 0x80000000:
                for j in range(width):
                    t[j] ^= k0[j]
            m = (m << 1) & mask
            for j in range(width - 1):
                k0[j] = ((k0[j] << 1) | (k0[j + 1] >> 31)) & mask
            k0[width - 1] = ((k0[width - 1] << 1) | (k1 >> 31)) & mask
            k1 = (k1 << 1) & mask
    for j in range(width):
        t[j] ^= k0[j]
    return b"".join(struct.pack(">I", x & 0xFFFFFFFF) for x in t)


# ---------------------------------------------------------------------------
# GCM（NIST SP 800-38D；SM4-GCM 使用自实现的 GHASH）
# ---------------------------------------------------------------------------

GCM_ALGOS = ("SM4", "AES128", "AES192", "AES256")
_R = 0xE1 << 120


def _gf128_mul(x: int, y: int) -> int:
    """GF(2^128) 乘法（GCM 约定，多项式 x^128 + x^7 + x^2 + x + 1）。"""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    def blocks(buf: bytes):
        for i in range(0, len(buf), 16):
            chunk = buf[i:i + 16]
            if len(chunk) < 16:
                chunk = chunk + b"\x00" * (16 - len(chunk))
            yield chunk

    y = 0
    for chunk in blocks(aad):
        y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), h)
    for chunk in blocks(ciphertext):
        y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), h)
    lens = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    y = _gf128_mul(y ^ int.from_bytes(lens, "big"), h)
    return y


class GCM:
    """通用 GCM 实现（分组长度 16 字节）。"""

    def __init__(self, algo: str, key: bytes):
        algo = (algo or "SM4").upper()
        if algo not in GCM_ALGOS:
            raise ToolError(f"GCM 模式不支持算法：{algo}")
        self.algo = algo
        self.cipher = get_cipher(algo, key)
        self.h = int.from_bytes(self.cipher.encrypt_block(b"\x00" * 16), "big")

    def _j0(self, iv: bytes) -> int:
        if len(iv) == 12:
            return int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
        return self._j0_slow(iv)

    def _j0_slow(self, iv: bytes) -> int:
        y = 0
        for i in range(0, len(iv), 16):
            chunk = iv[i:i + 16]
            if len(chunk) < 16:
                chunk = chunk + b"\x00" * (16 - len(chunk))
            y = _gf128_mul(y ^ int.from_bytes(chunk, "big"), self.h)
        y = _gf128_mul(y ^ (len(iv) * 8), self.h)
        return y

    def _gctr(self, icb: int, data: bytes) -> bytes:
        out = bytearray()
        counter = icb
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            ks = self.cipher.encrypt_block(counter.to_bytes(16, "big"))
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
        return bytes(out)

    def _tag(self, j0: int, aad: bytes, ciphertext: bytes) -> bytes:
        s = _ghash(self.h, aad, ciphertext)
        ek = int.from_bytes(self.cipher.encrypt_block(j0.to_bytes(16, "big")), "big")
        return (ek ^ s).to_bytes(16, "big")

    def encrypt(self, iv: bytes, plain: bytes, aad: bytes = b"", tag_len: int = 16) -> tuple[bytes, bytes]:
        if tag_len not in (4, 8, 12, 13, 14, 15, 16):
            raise ToolError("GCM 的 Tag 长度只支持 4 / 8 / 16 字节")
        j0 = self._j0(iv)
        cipher = self._gctr((j0 & ~0xFFFFFFFF) | (((j0 & 0xFFFFFFFF) + 1) & 0xFFFFFFFF), plain)
        tag = self._tag(j0, aad, cipher)
        return cipher, tag[:tag_len]

    def decrypt(self, iv: bytes, cipher: bytes, aad: bytes = b"", tag: bytes = b"", tag_len: int = 16) -> bytes:
        if tag_len not in (4, 8, 12, 13, 14, 15, 16):
            raise ToolError("GCM 的 Tag 长度只支持 4 / 8 / 16 字节")
        if len(tag) != tag_len:
            raise ToolError(f"认证标签长度必须为 {tag_len} 字节，当前为 {len(tag)} 字节")
        j0 = self._j0(iv)
        expect = self._tag(j0, aad, cipher)[:tag_len]
        if not _constant_time_eq(expect, tag):
            raise ToolError("解密失败：认证标签校验不通过")
        return self._gctr((j0 & ~0xFFFFFFFF) | (((j0 & 0xFFFFFFFF) + 1) & 0xFFFFFFFF), cipher)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
