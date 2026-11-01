"""电子签章校验 / 时间戳解析验证 接口。

POST /api/sig/signature/parse    {file, fileFormat, fileName}  或 multipart file
POST /api/sig/timestamp/parse    {tokenData, tokenFormat}
POST /api/sig/timestamp/verify   {tokenData, tokenFormat, originalData, originalFormat}
"""
from __future__ import annotations

import base64
import binascii

from flask import Blueprint, request

from ..core import sig as sigcore
from ..core.common import ToolError, ok, parse_bytes, require

bp = Blueprint("sig", __name__, url_prefix="/api/sig")

MAX_SIZE = 10 * 1024 * 1024


def _payload() -> dict:
    return request.get_json(silent=True) or {}


def _file_bytes(payload: dict) -> bytes:
    """支持 multipart 上传与 JSON 内嵌 base64。"""
    if "file" in request.files:
        data = request.files["file"].read()
        if len(data) > MAX_SIZE:
            raise ToolError("文件大小不能超过 10 MB")
        return data

    raw = payload.get("file")
    if raw is None:
        raw = payload.get("fileB64") or payload.get("fileData")
    if isinstance(raw, dict):  # {name, b64}
        raw = raw.get("b64") or raw.get("text") or ""
    if not raw or (isinstance(raw, str) and not raw.strip()):
        raise ToolError("请上传签章文件（PDF 或 OFD）")

    fmt = (payload.get("fileFormat") or "BASE64").upper()
    if fmt == "AUTO":
        fmt = "BASE64"
    data = parse_bytes(raw, fmt)
    if len(data) > MAX_SIZE:
        raise ToolError("文件大小不能超过 10 MB")
    return data


@bp.post("/signature/parse")
def signature_parse():
    payload = _payload()
    data = _file_bytes(payload)
    result = sigcore.check_signature(data)
    result["fileName"] = payload.get("fileName") or (
        request.files["file"].filename if "file" in request.files else None
    )
    return ok(result)


@bp.post("/signature/verify")
def signature_verify():
    """与 parse 等价（原站只有 parse，保留别名便于前端复用）。"""
    return signature_parse()


@bp.post("/timestamp/parse")
def timestamp_parse():
    payload = _payload()
    token = require(payload.get("tokenData"), "时间戳令牌数据")
    data = parse_bytes(token, payload.get("tokenFormat") or "HEX")
    return ok(sigcore.parse_timestamp(data))


@bp.post("/timestamp/verify")
def timestamp_verify():
    payload = _payload()
    token = require(payload.get("tokenData"), "时间戳令牌数据")
    data = parse_bytes(token, payload.get("tokenFormat") or "HEX")
    original = None
    if payload.get("originalData") not in (None, ""):
        original = parse_bytes(payload.get("originalData"), payload.get("originalFormat") or "TEXT")
    return ok(sigcore.verify_timestamp(data, original))


@bp.post("/certificate/export")
def certificate_export():
    """把 base64 DER 证书转换为 PEM 文本，便于前端直接下载。"""
    payload = _payload()
    raw = require(payload.get("cert"), "证书数据")
    try:
        der = base64.b64decode(str(raw).strip())
    except (binascii.Error, ValueError):
        raise ToolError("证书数据不是合法的 Base64")
    if not der:
        raise ToolError("证书数据为空")
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
    return ok({"pem": pem})
