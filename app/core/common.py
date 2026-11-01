"""公共工具：格式转换、错误类型、响应封装。

所有模块统一遵循：
    POST /api/...  JSON  ->  {"code":0,"msg":"成功","data": ...}
    失败              ->  {"code":1,"msg":"错误说明"}
"""
from __future__ import annotations

import base64
import binascii
import os
import re
from typing import Any

FORMATS = ("TEXT", "HEX", "BASE64")

# 运行期数据目录（本地 CA 等）。Windows 独立包下随包目录走，可用 CIPHERBOX_DATA 覆盖。
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("CIPHERBOX_DATA") or os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)


class ToolError(Exception):
    """业务错误，会被转换为 {code:1,msg:...}。"""


def ok(data: Any = None, msg: str = "成功") -> dict:
    return {"code": 0, "msg": msg, "data": data}


def fail(msg: str) -> dict:
    return {"code": 1, "msg": msg}


def _strip_ws(value: str) -> str:
    return re.sub(r"[\s\r\n\t]+", "", value or "")


def parse_bytes(value: Any, fmt: str | None = "TEXT") -> bytes:
    """把指定格式的输入转换成 bytes。"""
    fmt = (fmt or "TEXT").upper()
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    if fmt in ("TEXT", "STR", "STRING", "UTF8", "UTF-8"):
        return value.encode("utf-8")
    if fmt == "HEX":
        v = _strip_ws(value)
        v = re.sub(r"^0[xX]", "", v)
        v = v.replace(":", "")
        if len(v) % 2 != 0:
            raise ToolError("十六进制数据长度必须为偶数")
        try:
            return bytes.fromhex(v)
        except ValueError:
            raise ToolError("十六进制数据格式非法")
    if fmt in ("BASE64", "B64"):
        v = _strip_ws(value)
        v = v.replace("-", "+").replace("_", "/")
        pad = (-len(v)) % 4
        v = v + "=" * pad
        try:
            return base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            raise ToolError("Base64 数据格式非法")
    if fmt in ("BIN", "BINARY"):
        v = _strip_ws(value)
        if not re.fullmatch(r"[01]*", v):
            raise ToolError("二进制数据只能包含 0 和 1")
        if len(v) % 8 != 0:
            raise ToolError("二进制数据长度必须为 8 的倍数")
        return int(v, 2).to_bytes(len(v) // 8, "big") if v else b""
    raise ToolError(f"不支持的数据格式：{fmt}")


def format_bytes(data: bytes, fmt: str | None = "HEX") -> str:
    fmt = (fmt or "HEX").upper()
    if fmt in ("TEXT", "STR", "STRING", "UTF8", "UTF-8"):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise ToolError("结果无法按 UTF-8 文本展示，请切换为十六进制或 Base64")
    if fmt == "HEX":
        return data.hex()
    if fmt in ("BASE64", "B64"):
        return base64.b64encode(data).decode()
    if fmt in ("BIN", "BINARY"):
        return "".join(f"{b:08b}" for b in data)
    raise ToolError(f"不支持的输出格式：{fmt}")


def hexlify(data: bytes) -> str:
    return data.hex()


def unhexlify(text: str) -> bytes:
    return parse_bytes(text, "HEX")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return parse_bytes(text, "BASE64")


def require(value: Any, name: str) -> str:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        raise ToolError(f"请输入{name}")
    return value


def as_int(value: Any, name: str, default: int | None = None) -> int:
    if value in (None, ""):
        if default is None:
            raise ToolError(f"请输入{name}")
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ToolError(f"{name}必须为整数")
