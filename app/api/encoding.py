from flask import Blueprint, request

from ..core import asn1, encoding
from ..core.common import ToolError, ok, parse_bytes

bp = Blueprint("encoding", __name__, url_prefix="/api/encoding")


def _p():
    return request.get_json(silent=True) or {}


@bp.post("/convert")
def convert():
    p = _p()
    data = p.get("data") or ""
    result = encoding.convert(data, p.get("fromFormat") or p.get("dataFormat") or "TEXT", p.get("toFormat") or "HEX")
    return ok(result)


@bp.post("/charset")
def charset():
    p = _p()
    text = p.get("data") or ""
    src = p.get("sourceCharset") or "UTF-8"
    dst = p.get("targetCharset") or "GBK"
    return ok(encoding.charset_convert(text, src, dst))


@bp.get("/charsets")
def charsets():
    return ok(encoding.CHARSETS)


@bp.post("/url")
def url_decode():
    p = _p()
    return ok(encoding.url_decode(p.get("data") or ""))


@bp.post("/asn1/parse")
def asn1_parse():
    p = _p()
    data = parse_bytes(p.get("data"), p.get("dataFormat") or "HEX")
    if not data:
        raise ToolError("请输入 ASN.1 格式数据")
    node = asn1.parse_der(data)
    return ok(asn1.to_tree(node))


@bp.post("/identify")
def identify():
    p = _p()
    data = parse_bytes(p.get("data"), p.get("dataFormat") or "HEX")
    return ok(encoding.identify(data))
