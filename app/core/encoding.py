"""编码转换、字符集转换、算法识别。"""
from __future__ import annotations

import codecs
import urllib.parse

from .common import ToolError, format_bytes, parse_bytes

CHARSETS = [
    "UTF-8", "GBK", "GB18030", "GB2312", "BIG5", "UTF-16LE", "UTF-16BE",
    "ISO-8859-1", "ASCII", "Shift_JIS", "EUC-KR", "Windows-1252",
]


def convert(data: str, from_fmt: str, to_fmt: str) -> dict:
    raw = parse_bytes(data, from_fmt)
    out = format_bytes(raw, to_fmt)
    return {"result": out, "length": len(raw), "bits": len(raw) * 8}


def charset_convert(text: str, source: str, target: str) -> dict:
    """字符集转换（与原站同语义：按源字符集编码为字节，再按目标字符集解读展示）。

    返回 result（展示字符串，不可解码字节用 ? 代替，与原站 Java 行为一致）、
    hex（底层字节序列，无损，可供复制使用）与字节数。"""
    if source.upper().replace("-", "") == target.upper().replace("-", ""):
        return {"result": text, "hex": text.encode(source, "strict").hex(),
                "length": len(text.encode(source, "strict"))}
    try:
        codecs.lookup(source)
        codecs.lookup(target)
    except LookupError as e:
        raise ToolError(f"不支持的字符集：{e}")
    try:
        raw = text.encode(source, "strict")
    except UnicodeEncodeError:
        raise ToolError("输入文本无法按源字符集编码，请检查选择是否正确")
    display = raw.decode(target, errors="replace").replace("\ufffd", "?")
    return {"result": display, "hex": raw.hex(), "length": len(raw)}


def url_decode(text: str) -> str:
    try:
        return urllib.parse.unquote(text, errors="strict")
    except Exception:
        return urllib.parse.unquote(text)


HASH_SIZES = {
    "MD5": 16, "SHA-1": 20, "SHA-224": 28, "SHA-256": 32, "SHA-384": 48,
    "SHA-512": 64, "SM3": 32, "SHA3-224": 28, "SHA3-256": 32, "SHA3-384": 48,
    "SHA3-512": 64,
}

SYM_SIZES = {
    "SM4": [16], "AES-128": [16], "AES-192": [24], "AES-256": [32],
    "DES": [8], "3DES": [8, 16, 24], "ZUC-128": [16], "ZUC-256": [32],
}


def identify(data: bytes) -> dict:
    n = len(data)
    hashes = [{"algo": k, "value": v} for k, v in HASH_SIZES.items() if v == n]
    syms = [{"algo": k, "value": v} for k, v in SYM_SIZES.items() if n in v]
    asyms = []
    if n == 64:
        asyms.append({"algo": "SM2 公钥（未压缩，04||X||Y）", "value": 64})
        asyms.append({"algo": "SM2 签名值（R||S）", "value": 64})
    if n == 65 and data[:1] == b"\x04":
        asyms.append({"algo": "SM2/SM9 未压缩公钥", "value": 65})
    if n in (33,) and data[:1] in (b"\x02", b"\x03"):
        asyms.append({"algo": "SM2 压缩公钥", "value": 33})
    if n > 0 and n % 16 == 0:
        syms.append({"algo": f"分组密码密文（{n // 16} 个 16 字节分组）", "value": n})
    return {"length": n, "bits": n * 8, "hash": hashes, "symmetric": syms, "asymmetric": asyms}
