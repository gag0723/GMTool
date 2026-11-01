"""消息鉴别码（MAC）本地实现。

实现 GB/T 15852.1-2020《信息技术 安全技术 消息鉴别码 第 1 部分：采用分组密码的机制》
定义的 8 种 MAC 算法（与 ISO/IEC 9797-1 的通用模型一致）：

    1. CBC-MAC        —— 初始变换 1 + 最终迭代 1 + 输出变换 1
    2. EMAC           —— 初始变换 1 + 输出变换 2（第二把密钥再加密一次）
    3. ANSI-retail-MAC—— 初始变换 1 + 输出变换 3（K2 解密后再用 K1 加密）
    4. MacDES         —— 初始变换 2（K'' 派生）+ 输出变换 2
    5. CMAC           —— RFC 4493 / NIST SP 800-38B（子密钥派生 + 末块掩码）
    6. LMAC           —— 末块用第二把密钥加密的 CBC-MAC 变体
    7. TrCBC          —— CBC-MAC 的截断变体（消息非整分组时取尾部字节）
    8. CBCR           —— CBC with rotating transformations（初始向量 E_K(0)，末块循环移位）

填充方式按 ISO/IEC 9797-1 定义：
    PKCS7      —— PKCS#7：补 n 个值为 n 的字节（总是补一整块）
    M2         —— ISO/IEC 9797-1 填充方法 2：补 0x80 再补 0x00（对齐时也补一整块）
    M3         —— ISO/IEC 9797-1 填充方法 3：前置一个"消息比特长度"整块，再补 0x00
    NOPADDING  —— 不填充（消息长度必须是分组长度的整数倍）
CMAC 与 CBCR 固定使用标准中的"填充方法 4"（未对齐才补 0x80），与界面上的填充选项无关。

所有计算均在本地完成，不访问网络、不落盘。
"""
from __future__ import annotations

from Crypto.Cipher import AES, DES, DES3
from gmssl import sm4

from .common import ToolError

# 算法 -> (分组长度, 密钥长度)
ALGOS: dict[str, tuple[int, int]] = {
    "SM4": (16, 16),
    "AES128": (16, 16),
    "AES192": (16, 24),
    "AES256": (16, 32),
    "DES": (8, 8),
    "DESEDE16": (8, 16),
    "DESEDE24": (8, 24),
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

# 兼容各种写法
_ALIAS = {
    "SM4": "SM4",
    "AES": "AES128",
    "AES128": "AES128",
    "AES-128": "AES128",
    "AES192": "AES192",
    "AES-192": "AES192",
    "AES256": "AES256",
    "AES-256": "AES256",
    "DES": "DES",
    "DESEDE": "DESEDE24",
    "DESEDE16": "DESEDE16",
    "DESEDE24": "DESEDE24",
    "3DES": "DESEDE24",
    "3DES-2KEY": "DESEDE16",
    "3DES-3KEY": "DESEDE24",
    "TRIPLEDES": "DESEDE24",
}

# MAC 模式 -> (初始变换, 末块处理, 输出变换, 截断方式, 固定填充)
#   初始变换 1: H1 = E_K(D1)      2: H1 = E_K''(E_K(D1))      3: H1 = E_K(D1 ^ E_K(0))
#   末块处理 1: E_K(Dq ^ H)       2: E_K2(Dq ^ H)             3: CMAC 子密钥掩码      4: CBCR 循环移位
#   输出变换 1: G = H             2: G = E_K2(H)              3: G = E_K1(D_K2(H))
#   截断方式 1: 取前 tlen 字节     2: 消息非整分组时取后 tlen 字节
MODES: dict[str, tuple[int, int, int, int, str | None]] = {
    "CBCMAC": (1, 1, 1, 1, None),
    "CMAC": (1, 3, 1, 1, "M4"),
    "EMAC": (1, 1, 2, 1, None),
    "ANSIRETAILMAC": (1, 1, 3, 1, None),
    "MACDES": (2, 1, 2, 1, None),
    "LMAC": (1, 2, 1, 1, None),
    "CBCR": (3, 4, 1, 1, "M4"),
    "TRCBC": (1, 1, 1, 2, None),
}

MODE_LABEL = {
    "CBCMAC": "CBC-MAC",
    "CMAC": "CMAC",
    "EMAC": "EMAC",
    "ANSIRETAILMAC": "ANSI-retail-MAC",
    "MACDES": "MacDES",
    "LMAC": "LMAC",
    "CBCR": "CBCR",
    "TRCBC": "TrCBC",
}

_MODE_ALIAS = {
    "CBCMAC": "CBCMAC",
    "CBC-MAC": "CBCMAC",
    "CBC": "CBCMAC",
    "CMAC": "CMAC",
    "OMAC": "CMAC",
    "EMAC": "EMAC",
    "ANSIRETAILMAC": "ANSIRETAILMAC",
    "ANSI-RETAIL-MAC": "ANSIRETAILMAC",
    "ANSIRETAIL": "ANSIRETAILMAC",
    "RETAILMAC": "ANSIRETAILMAC",
    "MACDES": "MACDES",
    "LMAC": "LMAC",
    "CBCR": "CBCR",
    "TRCBC": "TRCBC",
    "TR-CBC": "TRCBC",
}

PADDINGS = ("PKCS7", "M2", "M3", "NOPADDING")
_PAD_ALIAS = {
    "PKCS7": "PKCS7",
    "PKCS#7": "PKCS7",
    "PAD1": "M1",
    "M1": "M1",
    "M2": "M2",
    "PAD2": "M2",
    "ISO9797M2": "M2",
    "M3": "M3",
    "PAD3": "M3",
    "ISO9797M3": "M3",
    "M4": "M4",
    "PAD4": "M4",
    "NOPADDING": "NOPADDING",
    "NONE": "NOPADDING",
    "NO": "NOPADDING",
}

PAD_LABEL = {
    "PKCS7": "PKCS7",
    "M1": "填充方式一（补零）",
    "M2": "填充方式二（0x80 补位）",
    "M3": "填充方式三（前置长度块）",
    "M4": "填充方式四（0x80 补位，对齐不补）",
    "NOPADDING": "NO PADDING",
}

# 需要第二把密钥的模式
TWO_KEY_MODES = ("EMAC", "ANSIRETAILMAC", "MACDES")


def normalize_algo(value: str | None) -> str:
    key = (value or "SM4").strip().upper().replace("_", "-")
    if key in _ALIAS:
        return _ALIAS[key]
    raise ToolError(f"不支持的分组算法：{value}")


def normalize_mode(value: str | None) -> str:
    key = (value or "CBCMAC").strip().upper().replace("_", "-")
    if key in _MODE_ALIAS:
        return _MODE_ALIAS[key]
    raise ToolError(f"不支持的 MAC 模式：{value}")


def normalize_padding(value: str | None) -> str:
    key = (value or "M2").strip().upper().replace(" ", "").replace("_", "")
    if key in _PAD_ALIAS:
        return _PAD_ALIAS[key]
    raise ToolError(f"不支持的填充方式：{value}")


# --------------------------------------------------------------------------- #
# 分组密码原语
# --------------------------------------------------------------------------- #
class BlockCipher:
    """只做"单个分组"的加/解密，供各 MAC 模式拼装。"""

    def __init__(self, algo: str, key: bytes):
        self.algo = algo
        self.size, key_len = ALGOS[algo]
        if len(key) != key_len:
            raise ToolError(
                f"{ALGO_LABEL[algo]} 的密钥长度必须为 {key_len} 字节（当前 {len(key)} 字节）"
            )
        self.key = key
        if algo == "SM4":
            self._enc = sm4.CryptSM4(padding_mode=None)
            self._enc.set_key(key, sm4.SM4_ENCRYPT)
            self._dec = sm4.CryptSM4(padding_mode=None)
            self._dec.set_key(key, sm4.SM4_DECRYPT)
        elif algo.startswith("AES"):
            self._enc = AES.new(key, AES.MODE_ECB)
            self._dec = self._enc
        elif algo.startswith("DESEDE"):
            self._enc = DES3.new(key, DES3.MODE_ECB)
            self._dec = self._enc
        else:
            self._enc = DES.new(key, DES.MODE_ECB)
            self._dec = self._enc

    def encrypt(self, block: bytes) -> bytes:
        if len(block) != self.size:
            raise ToolError("分组长度不正确")
        if self.algo == "SM4":
            return self._enc.crypt_ecb(block)
        return self._enc.encrypt(block)

    def decrypt(self, block: bytes) -> bytes:
        if len(block) != self.size:
            raise ToolError("分组长度不正确")
        if self.algo == "SM4":
            return self._dec.crypt_ecb(block)
        return self._dec.decrypt(block)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _rotate_left(data: bytes) -> bytes:
    """整串按位循环左移 1 位（下标 0 为最高位字节）。"""
    out = bytearray(len(data))
    carry = 0
    for i in range(len(data) - 1, -1, -1):
        b = data[i]
        out[i] = ((b << 1) & 0xFF) | carry
        carry = (b >> 7) & 1
    return bytes(out)


def _rotate_right(data: bytes) -> bytes:
    """整串按位循环右移 1 位：末字节最低位回卷到首字节最高位。"""
    out = bytearray(len(data))
    carry = 0
    for i in range(len(data)):
        b = data[i]
        out[i] = (b >> 1) | ((carry & 1) << 7)
        carry = b & 1
    out[0] |= (data[-1] & 1) << 7
    return bytes(out)


# --------------------------------------------------------------------------- #
# 填充
# --------------------------------------------------------------------------- #
def pad_message(data: bytes, method: str, size: int) -> tuple[list[bytes], bool]:
    """返回 (分组列表, 末块是否为"部分块补齐")。"""
    method = normalize_padding(method)
    if method == "NOPADDING":
        if not data:
            raise ToolError("选择 NO PADDING 时消息不能为空")
        if len(data) % size:
            raise ToolError(
                f"选择 NO PADDING 时消息长度必须是 {size} 字节的整数倍（当前 {len(data)} 字节）"
            )
        return [data[i:i + size] for i in range(0, len(data), size)], False

    if method == "M4":
        if len(data) % size == 0:
            return [data[i:i + size] for i in range(0, len(data), size)], False
        padded = data + b"\x80" + b"\x00" * (size - 1 - len(data) % size)
        blocks = [padded[i:i + size] for i in range(0, len(padded), size)]
        return blocks, True

    if method == "M1":
        if len(data) % size == 0:
            return [data[i:i + size] for i in range(0, len(data), size)], False
        padded = data + b"\x00" * (size - len(data) % size)
        return [padded[i:i + size] for i in range(0, len(padded), size)], True

    if method == "M3":
        length_block = len(data) * 8
        if length_block >= (1 << (8 * size)):
            raise ToolError("消息过长，无法使用填充方式三")
        head = length_block.to_bytes(size, "big")
        zeros = (-len(data)) % size
        body = data + b"\x00" * zeros
        full = head + body
        return [full[i:i + size] for i in range(0, len(full), size)], False

    if method == "M2":
        padded = data + b"\x80" + b"\x00" * (size - 1 - len(data) % size)
        blocks = [padded[i:i + size] for i in range(0, len(padded), size)]
        return blocks, True

    # PKCS7
    n = size - len(data) % size
    padded = data + bytes([n]) * n
    blocks = [padded[i:i + size] for i in range(0, len(padded), size)]
    return blocks, True


# --------------------------------------------------------------------------- #
# CMAC（RFC 4493 / NIST SP 800-38B / GB/T 15852.1 算法 5）
# --------------------------------------------------------------------------- #
def _cmac_subkeys(cipher: BlockCipher) -> tuple[bytes, bytes]:
    """K1 = multx(E_K(0))，K2 = multx(K1)。"""
    poly = 0x87 if cipher.size == 16 else 0x1B
    l = cipher.encrypt(b"\x00" * cipher.size)

    def multx(value: bytes) -> bytes:
        carry = value[0] >> 7
        out = bytearray(_rotate_left(value))
        if carry:
            out[-1] ^= poly
        return bytes(out)

    k1 = multx(l)
    k2 = multx(k1)
    return k1, k2


def cmac(algo: str, key: bytes, data: bytes, tlen: int | None = None) -> bytes:
    cipher = BlockCipher(algo, key)
    k1, k2 = _cmac_subkeys(cipher)
    size = cipher.size
    complete = bool(data) and len(data) % size == 0
    if complete:
        blocks = [data[i:i + size] for i in range(0, len(data), size)]
        last = _xor(blocks[-1], k1)
    else:
        padded = data + b"\x80" + b"\x00" * (size - 1 - len(data) % size)
        blocks = [padded[i:i + size] for i in range(0, len(padded), size)]
        last = _xor(blocks[-1], k2)
    h = b"\x00" * size
    for block in blocks[:-1]:
        h = cipher.encrypt(_xor(h, block))
    h = cipher.encrypt(_xor(h, last))
    return _truncate(h, tlen, size, False)


def _truncate(value: bytes, tlen: int | None, size: int, tail: bool) -> bytes:
    if tlen is None or tlen == "" or int(tlen) == size:
        return value
    tlen = int(tlen)
    if tlen <= 0 or tlen > size:
        raise ToolError(f"MAC 长度必须在 1~{size} 字节之间")
    return value[-tlen:] if tail else value[:tlen]


# --------------------------------------------------------------------------- #
# 主计算
# --------------------------------------------------------------------------- #
def mac_calc(
    algo: str,
    mode: str,
    key: bytes,
    data: bytes,
    padding: str = "M2",
    key2: bytes | None = None,
    tlen: int | None = None,
) -> dict:
    algo = normalize_algo(algo)
    mode = normalize_mode(mode)
    size, key_len = ALGOS[algo]
    if tlen in (None, ""):
        tlen = size
    try:
        tlen = int(tlen)
    except (TypeError, ValueError):
        raise ToolError("MAC 长度必须为整数")
    if tlen <= 0 or tlen > size:
        raise ToolError(f"{ALGO_LABEL[algo]} 的 MAC 长度必须在 1~{size} 字节之间")

    if not key:
        raise ToolError("请输入密钥一")
    if len(key) != key_len:
        raise ToolError(
            f"{ALGO_LABEL[algo]} 的密钥一长度必须为 {key_len} 字节（当前 {len(key)} 字节）"
        )

    init_t, last_t, out_t, trunc_t, fixed_pad = MODES[mode]
    pad_method = fixed_pad or normalize_padding(padding)

    if mode in TWO_KEY_MODES:
        if not key2:
            raise ToolError(f"{MODE_LABEL[mode]} 模式需要输入密钥二")
        if len(key2) != key_len:
            raise ToolError(
                f"{ALGO_LABEL[algo]} 的密钥二长度必须为 {key_len} 字节（当前 {len(key2)} 字节）"
            )

    if mode == "LMAC" and key2 and len(key2) != key_len:
        raise ToolError(
            f"{ALGO_LABEL[algo]} 的密钥二长度必须为 {key_len} 字节（当前 {len(key2)} 字节）"
        )

    if mode == "CMAC":
        value = cmac(algo, key, data, tlen)
        return {
            "mac": value,
            "algo": ALGO_LABEL[algo],
            "mode": MODE_LABEL[mode],
            "padding": "填充方式四（CMAC 固定）",
            "macLen": tlen,
            "blockSize": size,
            "keyBits": key_len * 8,
            "messageLen": len(data),
            "blocks": (len(data) + size - 1) // size if data else 1,
        }

    cipher = BlockCipher(algo, key)
    if mode == "LMAC" and not key2:
        # GB/T 15852.1-2020 密钥诱导 1：未提供密钥二时由密钥一派生链密钥与末块密钥
        chain_key, last_key = _derive_lmac_keys(cipher, key_len)
        cipher = BlockCipher(algo, chain_key)
        key2 = last_key
    blocks, partial = pad_message(data, pad_method, size)
    # 截断方式 2 依据"原始消息是否整分组"判断（与标准一致）
    tail_trunc = trunc_t == 2 and len(data) % size != 0

    if len(blocks) == 1:
        h = b"\x00" * size
    elif init_t == 1:
        h = cipher.encrypt(blocks[0])
    elif init_t == 2:
        # MacDES：K'' 由密钥二按"每隔 4 比特取补"派生
        kpp = bytes(b ^ 0xF0 for b in (key2 or b""))
        h = BlockCipher(algo, kpp).encrypt(cipher.encrypt(blocks[0]))
    else:
        h = cipher.encrypt(_xor(blocks[0], cipher.encrypt(b"\x00" * size)))

    for block in blocks[1:-1]:
        h = cipher.encrypt(_xor(h, block))

    last = blocks[-1]
    if last_t == 1:
        h = cipher.encrypt(_xor(h, last))
    elif last_t == 2:
        # LMAC：末块用第二把密钥（未提供时已按标准"密钥诱导 1"派生）
        h = BlockCipher(algo, key2 or b"").encrypt(_xor(h, last))
    elif last_t == 4:
        # CBCR：末块异或后按是否对齐做循环移位
        mixed = _xor(h, last)
        h = cipher.encrypt(_rotate_right(mixed) if not partial else _rotate_left(mixed))

    if out_t == 2:
        h = BlockCipher(algo, key2 or b"").encrypt(h)
    elif out_t == 3:
        h = cipher.encrypt(BlockCipher(algo, key2 or b"").decrypt(h))

    value = _truncate(h, tlen, size, tail_trunc)
    return {
        "mac": value,
        "algo": ALGO_LABEL[algo],
        "mode": MODE_LABEL[mode],
        "padding": PAD_LABEL.get("M4" if fixed_pad == "M4" else pad_method, pad_method),
        "macLen": tlen,
        "blockSize": size,
        "keyBits": key_len * 8,
        "messageLen": len(data),
        "blocks": len(blocks),
    }


def _derive_lmac_keys(cipher: BlockCipher, key_len: int) -> tuple[bytes, bytes]:
    """GB/T 15852.1-2020 密钥诱导 1：K1 = E_K(1)||E_K(2)||…（截取密钥长度），K2 继续向后派生。"""
    size = cipher.size
    t = max(1, (key_len + size - 1) // size)

    def gen(start: int) -> bytes:
        buf = b""
        for i in range(start, start + t):
            buf += cipher.encrypt(i.to_bytes(size, "big"))
        return buf[:key_len]

    return gen(1), gen(1 + t)


def mac_hex(**kwargs) -> str:
    return mac_calc(**kwargs)["mac"].hex()
