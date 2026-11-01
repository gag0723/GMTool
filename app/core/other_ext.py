"""其他常用工具的计算内核。

包含四类与密码学相关的通用能力：

1. 密文长度分析：根据输入数据长度（比特）推测可能的算法（哈希 / 对称 / 非对称）。
2. 大数运算：把 HEX / Base64 数据按大端无符号大整数处理，支持常见算术与位运算。
3. 取模运算：``(A op B) mod P`` 与模幂 ``A^B mod P``。
4. 逻辑运算：按字节做 AND / OR / XOR / NOT（较短一方左侧补 0）。
5. 字节逆序：整段逆序与按 2 / 4 / 8 / 16 字节分组内翻转。

长度表的名称、长度（bit）、安全强度（bit）已与原站 ``/api/other/query/cipher/length``
逐条对齐（去重）；输出 HEX 一律大写，与原站保持一致。

所有函数都是纯函数，不读写文件、不访问网络；非法输入一律抛 ``ToolError``。
"""
from __future__ import annotations

import base64

from .common import ToolError, parse_bytes

# ---------------------------------------------------------------------------
# 密文长度分析（长度单位：bit，与原站一致）
# ---------------------------------------------------------------------------

# 哈希：11 种杂凑算法 + 2 种基于分组密码的 MAC（原站表中存在，归入“哈希算法”分组）
HASH_ALGOS = [
    {"name": "MD5", "length": 128, "strength": 64, "kind": "hash", "note": "已不安全，仅用于兼容性校验"},
    {"name": "SHA1", "length": 160, "strength": 80, "kind": "hash", "note": "已不推荐用于安全场景"},
    {"name": "SHA224", "length": 224, "strength": 112, "kind": "hash", "note": "SHA-2 家族"},
    {"name": "SHA256", "length": 256, "strength": 128, "kind": "hash", "note": "SHA-2 家族"},
    {"name": "SHA384", "length": 384, "strength": 192, "kind": "hash", "note": "SHA-2 家族"},
    {"name": "SHA512", "length": 512, "strength": 256, "kind": "hash", "note": "SHA-2 家族"},
    {"name": "SM3", "length": 256, "strength": 128, "kind": "hash", "note": "GB/T 32905 国产杂凑算法"},
    {"name": "SHA3-224", "length": 224, "strength": 112, "kind": "hash", "note": "Keccak 海绵结构"},
    {"name": "SHA3-256", "length": 256, "strength": 128, "kind": "hash", "note": "Keccak 海绵结构"},
    {"name": "SHA3-384", "length": 384, "strength": 192, "kind": "hash", "note": "Keccak 海绵结构"},
    {"name": "SHA3-512", "length": 512, "strength": 256, "kind": "hash", "note": "Keccak 海绵结构"},
    {"name": "SM4-CBC-MAC", "length": 128, "strength": 128, "kind": "mac", "note": "基于 SM4 的分组 MAC，输出 16 字节"},
    {"name": "AES-CBC-MAC", "length": 128, "strength": 128, "kind": "mac", "note": "基于 AES 的分组 MAC，输出 16 字节"},
]

# 对称：block = 分组长度(bit)，key = 密钥长度(bit)；kind=stream 表示流密码
SYMMETRIC_ALGOS = [
    {"name": "AES-128", "block": 128, "key": 128, "strength": 128, "kind": "block", "note": "FIPS 197"},
    {"name": "AES-192", "block": 128, "key": 192, "strength": 192, "kind": "block", "note": "FIPS 197"},
    {"name": "AES-256", "block": 128, "key": 256, "strength": 256, "kind": "block", "note": "FIPS 197"},
    {"name": "DES", "block": 64, "key": 64, "strength": 56, "kind": "block", "note": "已不安全，56 位密钥可被穷举"},
    {"name": "3DES", "block": 64, "key": 192, "strength": 112, "kind": "block", "note": "有效强度约 112 位，已逐步淘汰"},
    {"name": "SM4", "block": 128, "key": 128, "strength": 128, "kind": "block", "note": "GB/T 32907 分组密码"},
    {"name": "IDEA", "block": 128, "key": 128, "strength": 128, "kind": "block", "note": "分组长度 128 位"},
    {"name": "Blowfish", "block": 128, "key": 128, "strength": 128, "kind": "block", "note": "分组长度 64 位可配置，此处按 128 位计"},
    {"name": "RC4", "block": 0, "key": 128, "strength": 40, "kind": "stream", "note": "流密码，密文长度等于明文长度"},
    {"name": "ChaCha20", "block": 0, "key": 256, "strength": 256, "kind": "stream", "note": "流密码，密文长度等于明文长度"},
    {"name": "ZUC-128", "block": 0, "key": 128, "strength": 128, "kind": "stream", "note": "GM/T 0001 祖冲之序列密码"},
    {"name": "ZUC-256", "block": 0, "key": 256, "strength": 256, "kind": "stream", "note": "GM/T 0001 祖冲之序列密码（256 位）"},
    {"name": "Salsa20", "block": 0, "key": 256, "strength": 256, "kind": "stream", "note": "流密码，密文长度等于明文长度"},
]

# 非对称：length = 典型密文/签名长度(bit)
ASYMMETRIC_ALGOS = [
    {"name": "RSA-1024-ENC", "length": 1024, "strength": 80, "kind": "rsa", "note": "模长 1024 位，已不推荐"},
    {"name": "RSA-2048-ENC", "length": 2048, "strength": 112, "kind": "rsa", "note": "模长 2048 位，当前最低推荐"},
    {"name": "RSA-3072-ENC", "length": 3072, "strength": 128, "kind": "rsa", "note": "模长 3072 位，等强度于 128 位对称"},
    {"name": "RSA-4096-ENC", "length": 4096, "strength": 140, "kind": "rsa", "note": "模长 4096 位，安全强度约 140 位"},
    {"name": "ECC-256-ENC", "length": 768, "strength": 128, "kind": "ec", "note": "C1(64)+密文，最小 96 字节"},
    {"name": "ECC-384-ENC", "length": 1152, "strength": 192, "kind": "ec", "note": "C1(96)+密文，最小 144 字节"},
    {"name": "ECC-521-ENC", "length": 1563, "strength": 256, "kind": "ec", "note": "C1(130)+密文"},
    {"name": "SM2-ENC", "length": 768, "strength": 128, "kind": "sm2", "note": "GB/T 32918，C1(65)+C3(32)+C2(m)，最短 96 字节"},
    {"name": "SM9-ENC", "length": 768, "strength": 128, "kind": "sm9", "note": "GM/T 0044 标识密码，C1(64)+C3(32)+C2(m)，最短 96 字节"},
    {"name": "SM2-SIGN", "length": 512, "strength": 128, "kind": "sm2", "note": "SM2 签名（r‖s 各 32 字节）"},
    {"name": "ECDSA-256-SIGN", "length": 512, "strength": 128, "kind": "ec", "note": "r‖s 各 32 字节"},
    {"name": "ECDSA-384-SIGN", "length": 768, "strength": 192, "kind": "ec", "note": "r‖s 各 48 字节"},
    {"name": "DSA-1024-SIGN", "length": 512, "strength": 80, "kind": "dsa", "note": "r‖s 各 160 位"},
    {"name": "DSA-2048-SIGN", "length": 512, "strength": 112, "kind": "dsa", "note": "r‖s 各 224/256 位"},
    {"name": "RSA-PSS-1024-SIGN", "length": 1024, "strength": 80, "kind": "rsa", "note": "RSA-PSS 签名，长度等于模长"},
    {"name": "RSA-PSS-2048-SIGN", "length": 2048, "strength": 112, "kind": "rsa", "note": "RSA-PSS 签名，长度等于模长"},
]

LENGTH_GROUPS = {
    "HASH": ("哈希算法", HASH_ALGOS),
    "SYMMETRIC": ("对称算法", SYMMETRIC_ALGOS),
    "ASYMMETRIC": ("非对称算法", ASYMMETRIC_ALGOS),
}

GROUP_ALIASES = {
    "1": "HASH", "HASH": "HASH", "哈希": "HASH", "哈希算法": "HASH",
    "2": "SYMMETRIC", "SYMMETRIC": "SYMMETRIC", "对称": "SYMMETRIC", "对称算法": "SYMMETRIC",
    "3": "ASYMMETRIC", "ASYMMETRIC": "ASYMMETRIC", "非对称": "ASYMMETRIC", "非对称算法": "ASYMMETRIC",
}


def _group_key(kind) -> str:
    key = GROUP_ALIASES.get(str(kind or "").strip().upper()) or GROUP_ALIASES.get(str(kind or "").strip())
    if not key:
        raise ToolError("分组类型只能是哈希算法(1)、对称算法(2)或非对称算法(3)")
    return key


def _len_text(bits: int) -> str:
    if bits % 8 == 0:
        return f"{bits} 位 / {bits // 8} 字节"
    return f"{bits} 位"


def length_table(kind) -> dict:
    """返回某一分组（哈希 / 对称 / 非对称）的完整算法长度与安全强度表。"""
    key = _group_key(kind)
    title, algos = LENGTH_GROUPS[key]
    rows = []
    for a in algos:
        row = {
            "name": a["name"],
            "length": _len_text(a["length"] if key != "SYMMETRIC" else
                                (a["block"] or a["key"])),
            "lengthBits": a["length"] if key != "SYMMETRIC" else (a["block"] or a["key"]),
            "strength": a["strength"],
            "note": a["note"],
            "kind": a["kind"],
        }
        if key == "SYMMETRIC":
            row["keyLength"] = _len_text(a["key"])
            row["stream"] = a["kind"] == "stream"
        rows.append(row)
    return {"group": key, "title": title, "rows": rows, "total": len(rows)}


def analyze_cipher_length(value, fmt: str = "HEX") -> dict:
    """根据数据长度（比特）推测可能的算法。

    判定规则与原站 ``/api/other/query/cipher`` 对齐：

    * 哈希 / MAC：摘要长度与数据长度**完全相等**才命中；
    * 分组密码：长度是分组长度的整数倍即命中（含 DES 的 64 位分组）；
    * 流密码：任何长度都可能，标记为 ``possible``（原站同样恒返回）；
    * 非对称：密文/签名长度与数据长度**完全相等**才命中。
    """
    data = parse_bytes(value, fmt)
    bits = len(data) * 8
    if bits == 0:
        raise ToolError("请输入待分析的数据")

    hashes = []
    for a in HASH_ALGOS:
        if bits == a["length"]:
            hashes.append({
                "name": a["name"],
                "length": _len_text(a["length"]),
                "lengthBits": a["length"],
                "strength": a["strength"],
                "match": "exact",
                "kind": a["kind"],
                "note": a["note"],
            })

    symmetric = []
    for a in SYMMETRIC_ALGOS:
        if a["kind"] == "stream":
            symmetric.append({
                "name": a["name"],
                "length": _len_text(a["key"]),
                "lengthBits": a["key"],
                "strength": a["strength"],
                "match": "possible",
                "note": a["note"],
            })
        elif bits % a["block"] == 0:
            symmetric.append({
                "name": a["name"],
                "length": _len_text(a["block"]),
                "lengthBits": a["block"],
                "strength": a["strength"],
                "match": "exact",
                "note": f"共 {bits // a['block']} 个分组；{a['note']}",
            })

    asymmetric = []
    for a in ASYMMETRIC_ALGOS:
        if bits == a["length"]:
            asymmetric.append({
                "name": a["name"],
                "length": _len_text(a["length"]),
                "lengthBits": a["length"],
                "strength": a["strength"],
                "match": "exact",
                "note": a["note"],
            })

    hints = []
    if not hashes and not symmetric and not asymmetric:
        hints.append("未匹配到任何已知算法的标准长度，数据可能带有头部、填充或编码后再被截断。")
    else:
        if bits % 128 == 0:
            hints.append("长度为 128 位的整数倍，符合 SM4 / AES 分组密文特征（也可能只是巧合同余）。")
        if bits in (128, 160, 224, 256, 384, 512):
            hints.append("长度与常见哈希摘要一致，若数据不可逆请优先按哈希算法排查。")
        if bits >= 768:
            hints.append("长度不小于 96 字节，可能是非对称算法密文或带 IV 的对称密文。")
    return {
        "length": bits,
        "bits": bits,
        "bytes": len(data),
        "hash": hashes,
        "symmetric": symmetric,
        "asymmetric": asymmetric,
        "hints": hints,
        "summary": (f"数据长度 {bits} 位（{len(data)} 字节）：哈希 {len(hashes)} 项、"
                    f"对称 {len(symmetric)} 项、非对称 {len(asymmetric)} 项"),
    }


# ---------------------------------------------------------------------------
# 大数运算
# ---------------------------------------------------------------------------

BIG_OPS = ("add", "sub", "mul", "div", "mod", "pow", "cmp", "shl", "shr", "and", "or", "xor")
MOD_OPS = ("add", "sub", "mul", "pow")

_MAX_POW_EXPONENT = 65536
_MAX_SHIFT = 1 << 20
_MAX_RESULT_BITS = 1 << 21


def parse_big_int(value, fmt: str, name: str) -> int:
    data = parse_bytes(value, fmt)
    if not data:
        raise ToolError(f"请输入数据 {name}")
    return int.from_bytes(data, "big")


def int_to_bytes(number: int) -> bytes:
    if number < 0:
        raise ToolError("无符号大数不支持负数结果")
    if number == 0:
        return b"\x00"
    return number.to_bytes((number.bit_length() + 7) // 8, "big")


def signed_bytes(number: int) -> bytes:
    """按 BigInteger.toByteArray() 语义输出：正数最高位为 1 时前置 0x00，负数取最小补码。

    与原站一致，例如 ``0x80`` → ``0080``，``-128`` → ``80``，``-129`` → ``FF7F``。
    """
    if number == 0:
        return b"\x00"
    if number > 0:
        data = number.to_bytes((number.bit_length() + 7) // 8, "big")
        return b"\x00" + data if data[0] & 0x80 else data
    magnitude = -number
    width = max(1, (magnitude.bit_length() + 7) // 8)
    if magnitude > (1 << (8 * width - 1)):
        width += 1
    value = (1 << (8 * width)) + number
    return value.to_bytes(width, "big")


def _fmt(data: bytes, fmt: str) -> str:
    """按指定格式输出，HEX 统一大写（与原站一致）。"""
    fmt = (fmt or "HEX").upper()
    if fmt in ("HEX", "HEXADECIMAL"):
        return data.hex().upper()
    if fmt in ("DEC", "DECIMAL", "10"):
        return str(int.from_bytes(data, "big")) if data else "0"
    if fmt in ("TEXT", "STR", "STRING", "UTF8", "UTF-8"):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise ToolError("结果无法按 UTF-8 文本展示，请切换为十六进制或 Base64")
    if fmt in ("BASE64", "B64"):
        return base64.b64encode(data).decode()
    if fmt in ("BIN", "BINARY"):
        return "".join(f"{b:08b}" for b in data)
    raise ToolError(f"不支持的输出格式：{fmt}")


def _require(op: str, allowed, label: str) -> str:
    op = (op or "").lower()
    if op not in allowed:
        raise ToolError(f"{label}不支持的运算类型：{op or '(空)'}")
    return op


def big_number(op: str, a_value, a_fmt: str, b_value, b_fmt: str, result_fmt: str = "HEX") -> dict:
    """无符号大整数运算。A、B 均按大端序解释，HEX 输出大写。"""
    op = _require(op, BIG_OPS, "大数运算")
    a = parse_big_int(a_value, a_fmt, "A")
    b = parse_big_int(b_value, b_fmt, "B")

    negative = False
    if op == "add":
        out = a + b
    elif op == "sub":
        out = a - b
        negative = out < 0
    elif op == "mul":
        out = _check_size(a * b)
    elif op == "div":
        if b == 0:
            raise ToolError("除数 B 不能为 0")
        out = a // b
    elif op == "mod":
        if b == 0:
            raise ToolError("模数 B 不能为 0")
        out = a % b
    elif op == "pow":
        if b > _MAX_POW_EXPONENT:
            raise ToolError(f"指数过大，最大支持 {_MAX_POW_EXPONENT}")
        out = _check_size(pow(a, b))
    elif op == "cmp":
        out = -1 if a < b else (0 if a == b else 1)
    elif op == "shl":
        if b > _MAX_SHIFT:
            raise ToolError(f"位移位数过大，最大支持 {_MAX_SHIFT}")
        out = _check_size(a << b)
    elif op == "shr":
        if b > _MAX_SHIFT:
            raise ToolError(f"位移位数过大，最大支持 {_MAX_SHIFT}")
        out = a >> b
    elif op == "and":
        out = a & b
    elif op == "or":
        out = a | b
    else:  # xor
        out = a ^ b

    if op == "cmp":
        return {
            "op": op,
            "result": {-1: "A < B", 0: "A == B", 1: "A > B"}[out],
            "compare": out,
            "bytes": 0,
            "bits": 0,
            "decimal": str(out),
            "hex": "",
            "note": "",
        }

    data = signed_bytes(out)
    note = ""
    if negative:
        note = "A < B，按原站规则以补码（最小字节宽度）表示负差值"
    return {
        "op": op,
        "result": _fmt(data, result_fmt),
        "format": (result_fmt or "HEX").upper(),
        "bytes": len(data),
        "bits": len(data) * 8,
        "decimal": str(out),
        "hex": data.hex().upper(),
        "note": note,
    }


def _check_size(number: int) -> int:
    if number.bit_length() > _MAX_RESULT_BITS:
        raise ToolError("计算结果超过 2 Mbit，已拒绝执行，请缩小输入规模")
    return number


def mod_number(op: str, a_value, a_fmt: str, b_value, b_fmt: str,
               p_value, p_fmt: str, result_fmt: str = "HEX") -> dict:
    """取模运算：``(A op B) mod P``，其中 pow 表示 ``A^B mod P``。"""
    op = _require(op, MOD_OPS, "取模运算")
    a = parse_big_int(a_value, a_fmt, "A")
    b = parse_big_int(b_value, b_fmt, "B")
    p = parse_big_int(p_value, p_fmt, "P")
    if p == 0:
        raise ToolError("模数 P 必须大于 0")
    if op == "add":
        out = (a + b) % p
    elif op == "sub":
        out = (a - b) % p
    elif op == "mul":
        out = _check_size(a * b) % p
    else:
        if b > _MAX_POW_EXPONENT:
            raise ToolError(f"指数过大，最大支持 {_MAX_POW_EXPONENT}")
        out = pow(a, b, p)
    data = signed_bytes(out)
    return {
        "op": op,
        "result": _fmt(data, result_fmt),
        "format": (result_fmt or "HEX").upper(),
        "bytes": len(data),
        "bits": len(data) * 8,
        "decimal": str(out),
        "hex": data.hex().upper(),
        "modulus": str(p),
    }


# ---------------------------------------------------------------------------
# 逻辑运算
# ---------------------------------------------------------------------------

LOGIC_OPS = ("AND", "OR", "XOR", "NOT")


def logic_op(op: str, a_value, a_fmt: str, b_value=None, b_fmt: str = "HEX",
             result_fmt: str = "HEX") -> dict:
    """按字节执行 AND / OR / XOR / NOT。

    数据长度不一致时按较长一方处理，较短一方**左侧补 0**（与原站一致），
    因此结果长度等于 A、B 中较长的字节数。
    """
    op = (op or "").upper()
    if op not in LOGIC_OPS:
        raise ToolError("逻辑运算只支持 AND、OR、XOR、NOT")
    a = parse_bytes(a_value, a_fmt)
    if not a:
        raise ToolError("请输入数据 A")

    if op == "NOT":
        out = bytes((~x) & 0xFF for x in a)
        return {
            "op": op,
            "result": _fmt(out, result_fmt),
            "bytes": len(out),
            "bits": len(out) * 8,
            "hex": out.hex().upper(),
            "note": "按字节取反，仅使用数据 A",
        }

    b = parse_bytes(b_value, b_fmt)
    if not b:
        raise ToolError("请输入数据 B")
    length = max(len(a), len(b))
    a2 = a.rjust(length, b"\x00")
    b2 = b.rjust(length, b"\x00")
    if len(a) != len(b):
        note = f"数据 A（{len(a)} 字节）与数据 B（{len(b)} 字节）长度不一致，较短一方左侧补 0 后按 {length} 字节运算"
    else:
        note = ""
    if op == "AND":
        out = bytes(x & y for x, y in zip(a2, b2))
    elif op == "OR":
        out = bytes(x | y for x, y in zip(a2, b2))
    else:
        out = bytes(x ^ y for x, y in zip(a2, b2))
    return {
        "op": op,
        "result": _fmt(out, result_fmt),
        "bytes": len(out),
        "bits": len(out) * 8,
        "hex": out.hex().upper(),
        "note": note,
    }


# ---------------------------------------------------------------------------
# 字节逆序
# ---------------------------------------------------------------------------

REVERSE_MODES = {"all": 0, "1": 1, "2": 2, "4": 4, "8": 8, "16": 16}


def byte_reverse(value, fmt: str = "HEX", mode: str = "all",
                 result_fmt: str = "HEX") -> dict:
    """整段逆序或按 N 字节分组内的字节序翻转。

    ``mode='all'`` 表示整段逆序（与原站 ``/other/byte/reverse`` 一致）；
    ``mode='2'/'4'/'8'/'16'`` 为扩展能力，表示按该字节数分组、每组内部字节
    逆序（常用于大小端互换）。数据长度必须是分组大小的整数倍，否则报错。
    """
    data = parse_bytes(value, fmt)
    if not data:
        raise ToolError("请输入待逆序的数据")
    key = str(mode or "all").lower()
    if key not in REVERSE_MODES:
        raise ToolError("逆序方式只支持整段逆序或按 2 / 4 / 8 / 16 字节分组")

    if key == "all":
        out = data[::-1]
        groups = 1
        label = "整段逆序"
    else:
        size = REVERSE_MODES[key]
        if size == 1:
            out = bytes(data)
            groups = len(data)
            label = "按 1 字节分组（结果不变）"
        else:
            if len(data) % size != 0:
                raise ToolError(
                    f"数据长度 {len(data)} 字节不是 {size} 的整数倍，无法按 {size} 字节分组翻转"
                )
            out = b"".join(data[i:i + size][::-1] for i in range(0, len(data), size))
            groups = len(data) // size
            label = f"按 {size} 字节分组内翻转"
    return {
        "result": _fmt(out, result_fmt),
        "mode": key,
        "label": label,
        "bytes": len(out),
        "groups": groups,
        "hex": out.hex().upper(),
    }


def describe_int(number: int) -> dict:
    data = int_to_bytes(number)
    return {
        "hex": data.hex().upper(),
        "decimal": str(number),
        "bits": number.bit_length(),
        "bytes": len(data),
    }


__all__ = [
    "HASH_ALGOS", "SYMMETRIC_ALGOS", "ASYMMETRIC_ALGOS", "LENGTH_GROUPS",
    "BIG_OPS", "MOD_OPS", "LOGIC_OPS", "REVERSE_MODES",
    "length_table", "analyze_cipher_length", "big_number", "mod_number",
    "logic_op", "byte_reverse", "parse_big_int", "int_to_bytes", "describe_int",
]
