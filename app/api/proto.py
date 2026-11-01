"""协议分析工具接口：TLS / SSH / IPSec / UKey 流量包解析。

接口前缀 /api/proto，统一返回 {"code":0,"msg":"成功","data":{...}}。
支持两种入参：
  1. JSON：{"file": "<base64>", "pcap": "<base64>", "pcapFormat": "BASE64",
            "srcAddr": "", "dstAddr": "", "dstPort": 443, "fileName": "a.pcap"}
  2. multipart/form-data：pcapFile=<文件>（与在线站点一致，便于交叉验证）
"""
from __future__ import annotations

import base64
import binascii

from flask import Blueprint, request

from ..core import protocols
from ..core.common import ToolError, ok, parse_bytes

bp = Blueprint("proto", __name__, url_prefix="/api/proto")

MAX_PCAP_BYTES = 24 * 1024 * 1024


def _payload() -> dict:
    return request.get_json(silent=True) or {}


def _read_upload() -> bytes | None:
    """取出上传的 pcap（multipart 或 JSON 内的 base64）。"""
    files = request.files or {}
    for key in ("pcapFile", "file", "capture"):
        item = files.get(key)
        if item is None:
            continue
        raw = item.read()
        if raw:
            return raw
    p = _payload()
    return None


def _load_capture(p: dict) -> bytes:
    raw = _read_upload()
    if raw is not None:
        _check_size(raw)
        return raw
    value = p.get("file") or p.get("pcap") or ""
    fmt = p.get("pcapFormat") or ("BASE64" if p.get("pcap") else "BASE64")
    if isinstance(value, str) and value.startswith("data:") and "," in value:
        value = value.split(",", 1)[1]
        fmt = "BASE64"
    if not value:
        raise ToolError("请先选择流量包文件（.pcap / .pcapng）")
    raw = parse_bytes(value, fmt or "BASE64")
    _check_size(raw)
    return raw


def _check_size(raw: bytes) -> None:
    if not raw:
        raise ToolError("流量包内容为空，请重新选择文件")
    if len(raw) > MAX_PCAP_BYTES:
        raise ToolError("流量包过大（超过 24 MB），请先裁剪后重试")


def _filters(p: dict) -> dict:
    src_ip = (p.get("srcAddr") or p.get("srcIp") or "").strip()
    dst_ip = (p.get("dstAddr") or p.get("dstIp") or "").strip()
    filename = p.get("fileName") or ""
    if not src_ip and not dst_ip and filename:
        ips = protocols.parse_ips_from_filename(filename)
        if len(ips) >= 2:
            src_ip, dst_ip = ips[0], ips[1]
    def _port(*keys):
        for k in keys:
            v = p.get(k)
            if v in (None, ""):
                continue
            try:
                n = int(v)
            except (TypeError, ValueError):
                raise ToolError("端口必须为 0-65535 的整数")
            if not (0 <= n <= 65535):
                raise ToolError("端口必须为 0-65535 的整数")
            return n
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": _port("srcPort"),
        "dst_port": _port("dstPort"),
        "ssh_port": _port("sshPort", "dstPort"),
        "file_name": filename,
    }


@bp.post("/tls/parse")
def tls_parse():
    p = _payload()
    raw = _load_capture(p)
    f = _filters(p)
    data = protocols.parse_tls(
        raw, src_ip=f["src_ip"], dst_ip=f["dst_ip"],
        src_port=f["src_port"], dst_port=f["dst_port"], file_name=f["file_name"],
    )
    return ok(data, "解析成功")


@bp.post("/ssh/parse")
def ssh_parse():
    p = _payload()
    raw = _load_capture(p)
    f = _filters(p)
    secret = (p.get("kexSecret") or "").strip()
    data = protocols.parse_ssh(
        raw, src_ip=f["src_ip"], dst_ip=f["dst_ip"],
        src_port=f["src_port"], dst_port=f["ssh_port"], kex_secret=secret,
        file_name=f["file_name"],
    )
    return ok(data, "解析成功")


@bp.post("/ipsec/parse")
def ipsec_parse():
    p = _payload()
    raw = _load_capture(p)
    f = _filters(p)
    data = protocols.parse_ipsec(
        raw, src_ip=f["src_ip"], dst_ip=f["dst_ip"],
        src_port=f["src_port"], dst_port=f["dst_port"], file_name=f["file_name"],
    )
    return ok(data, "解析成功")


@bp.post("/ukey/parse")
def ukey_parse():
    p = _payload()
    raw = _load_capture(p)
    data = protocols.parse_ukey(
        raw,
        factory=(p.get("factory") or "").strip(),
        public_key=(p.get("publicKey") or "").strip(),
        file_name=p.get("fileName") or "",
    )
    return ok(data, "解析成功")


@bp.post("/sample")
def sample_pcap():
    """返回一个内置样例 pcap（base64），便于前端在无文件时演示。"""
    from pathlib import Path

    base = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    kind = (_payload().get("type") or "tls").lower()
    name = {"tls": "tls_session.pcap", "ssh": "ssh_session.pcap",
            "ipsec": "ipsec_ikev2.pcap", "ukey": "ukey_ccid.pcap"}.get(kind)
    path = base / (name or "tls_session.pcap")
    if not path.exists():
        raise ToolError("内置样例不存在，请先运行 tests/make_fixtures.py 生成")
    raw = path.read_bytes()
    return ok({"name": path.name, "size": len(raw), "base64": base64.b64encode(raw).decode()}, "读取成功")
