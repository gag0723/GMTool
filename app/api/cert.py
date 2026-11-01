"""数字证书相关接口（/api/cert）。

路由总览（兼容参考站命名，两种前缀都可用）：
    POST /api/cert/format/check      （别名 /check/format）   证书格式逐项校验
    POST /api/cert/chain/check       （别名 /check/chain/tree）证书链验证（树结构）
    POST /api/cert/status/check      （别名 /check/crl、/check/ocsp）证书撤销检查
    POST /api/cert/crl/status/check  （别名 /check/crl/format、/check/crl/chain）CRL 有效性
    POST /api/cert/sign/issue        （别名 /gen/csr、/gen/cert、/sign/csr、/sign/pfx）签发
    POST /api/cert/parse/asn1        ASN.1 树解析
    GET  /api/cert/ca/info           本地 CA 信息

全部为本地计算，不发起任何网络请求。
"""
from __future__ import annotations

from flask import Blueprint, request

from ..core import cert as core
from ..core.common import ToolError, ok

bp = Blueprint("cert", __name__, url_prefix="/api/cert")


def _p() -> dict:
    return request.get_json(silent=True) or {}


def _first(p: dict, *names: str, default=None):
    for name in names:
        value = p.get(name)
        if value not in (None, ""):
            return value
    return default


def _fmt(value) -> str:
    fmt = str(value or "PEM").upper()
    return "AUTO" if fmt in ("DER", "BIN", "BINARY") else fmt


# --------------------------------------------------------------------------- #
# 1. 证书格式检查
# --------------------------------------------------------------------------- #
def _format_check(p: dict) -> dict:
    text = _first(p, "cert", "certContent", "data", "content")
    if not text:
        raise ToolError("请输入待校验的证书内容")
    certs = core.load_certs(str(text), _fmt(_first(p, "certFormat", "format")), "证书")
    cert = certs[0]
    items = core.format_items(cert)
    status, summary = core.summarize(items)
    return {
        "items": items,
        "cert": core.cert_info_view(cert),
        "summary": summary,
        "status": status,
        "parsedCount": len(certs),
    }


@bp.post("/format/check")
@bp.post("/check/format")
def format_check():
    return ok(_format_check(_p()))


# --------------------------------------------------------------------------- #
# 2. 证书链验证
# --------------------------------------------------------------------------- #
def _chain_check(p: dict) -> dict:
    nodes = p.get("nodes")
    if isinstance(nodes, list) and nodes:
        clean = []
        for idx, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise ToolError("证书节点格式不正确")
            clean.append(
                {
                    "nodeId": str(node.get("nodeId") or node.get("id") or f"node-{idx}"),
                    "parentId": node.get("parentId"),
                    "name": node.get("name") or f"证书节点 {idx + 1}",
                    "cert": node.get("cert") or "",
                    "certFormat": _fmt(node.get("certFormat")),
                }
            )
        return core.check_chain(clean)

    text = _first(p, "chainCerts", "certs", "chain", "cert")
    if isinstance(text, list):
        text = "\n".join(str(x) for x in text)
    if not text:
        raise ToolError("请提供证书链（多张证书）或节点列表")
    return core.chain_from_certs(str(text), _fmt(_first(p, "chainCertsFormat", "certFormat", "format")))


@bp.post("/chain/check")
@bp.post("/check/chain")
@bp.post("/check/chain/tree")
def chain_check():
    return ok(_chain_check(_p()))


# --------------------------------------------------------------------------- #
# 3. 证书撤销状态检查（CRL / OCSP）
# --------------------------------------------------------------------------- #
def _status_check(p: dict) -> dict:
    mode = str(p.get("mode") or "AUTO").upper()
    cert_text = _first(p, "cert", "certContent")
    cert_fmt = _fmt(_first(p, "certFormat", "format"))
    response = _first(p, "ocspResponse", "ocsp")
    crl_text = _first(p, "crl", "crlContent")
    address = _first(p, "ocspAddress", "ocspUrl", default="")

    if mode == "OCSP" or (mode == "AUTO" and response):
        data = core.check_cert_status_ocsp(
            str(cert_text) if cert_text else None,
            cert_fmt,
            str(response) if response else "",
            _fmt(_first(p, "ocspResponseFormat", "ocspFormat")),
            str(address) if address else "",
        )
        data["mode"] = "OCSP"
        return data

    if mode == "CRL" and not crl_text:
        raise ToolError("请输入 CRL 内容")
    if not crl_text:
        if address:
            raise ToolError(core.OFFLINE_OCSP_HINT)
        raise ToolError("请输入 CRL 内容，或粘贴 OCSP 响应进行离线验证")
    if not cert_text:
        raise ToolError("请输入待校验的证书")
    data = core.check_cert_status_crl(str(cert_text), cert_fmt, str(crl_text), _fmt(_first(p, "crlFormat")))
    data["mode"] = "CRL"
    return data


@bp.post("/status/check")
@bp.post("/check/crl")
@bp.post("/check/ocsp")
def status_check():
    return ok(_status_check(_p()))


# --------------------------------------------------------------------------- #
# 4. CRL 有效性校验
# --------------------------------------------------------------------------- #
def _crl_check(p: dict) -> dict:
    crl_text = _first(p, "crl", "crlContent", "data")
    if not crl_text:
        raise ToolError("请输入待校验的 CRL 内容")
    base_text = _first(p, "baseCert", "issuerCert", "caCert", default="")
    data = core.check_crl_validity(
        str(crl_text),
        _fmt(_first(p, "crlFormat", "format")),
        str(base_text) if base_text else None,
        _fmt(_first(p, "baseCertFormat", "caCertFormat")),
    )
    data["crlInfoText"] = _crl_text(data["crl"])
    if data.get("valid") is False:
        data["code"] = 1
    return data


def _crl_text(crl: dict) -> str:
    """把 CRL 解析结果拼成便于阅读的文本（与原站展示字段对齐）。"""
    lines = [
        f"CRL版本: {crl['version']}",
        f"颁发者: {crl['issuer']}",
        f"本次更新时间: {crl['thisUpdate']}",
        f"下次更新时间: {crl['nextUpdate'] or '（未声明）'}",
        f"签名算法: {crl['sigAlg']}",
        f"CRL编号: {crl['crlNumber'] if crl['crlNumber'] is not None else '（未声明）'}",
        f"授权密钥标识符: {crl['aki'] or '（未声明）'}",
        f"已吊销证书数量: {crl['entryCount']}",
        "",
        "吊销证书列表：",
    ]
    entries = crl.get("entries") or []
    if not entries:
        lines.append("（无）")
    for entry in entries:
        lines.append(f"序列号: {entry['serial']}")
        lines.append(f"吊销日期: {entry['revocationDate']}")
        lines.append(f"吊销原因: {entry['reason']}")
        lines.append("------------------------")
    return "\n".join(lines)


@bp.post("/crl/status/check")
@bp.post("/check/crl/format")
@bp.post("/check/crl/chain")
def crl_check():
    data = _crl_check(_p())
    return ok(data)


# --------------------------------------------------------------------------- #
# 5. 证书签发（CSR / 证书 / PFX）
# --------------------------------------------------------------------------- #
@bp.post("/sign/issue")
@bp.post("/sign/csr")
@bp.post("/sign/pfx")
@bp.post("/gen/csr")
@bp.post("/gen/cert")
def sign_issue():
    p = _p()
    path = request.path.rsplit("/", 1)[-1]
    action = str(_first(p, "action", "step", default="")).lower()
    if path in ("csr",) or action in ("csr", "gen_csr", "gencsr", "csr_gen"):
        return ok(core.gen_csr(p))
    if path == "pfx" or action in ("pfx", "gen_pfx", "genpfx", "pkcs12"):
        p["withPfx"] = True
    elif action in ("issue", "sign", "cert", "gen_cert"):
        p["withPfx"] = bool(p.get("withPfx") or p.get("pfx"))
    return ok(core.issue_certificate(p))


@bp.get("/ca/info")
def ca_info():
    family = (request.args.get("algorithm") or "SM2").upper()
    if family not in ("SM2", "RSA"):
        raise ToolError("本地 CA 仅支持 SM2 / RSA")
    return ok(core.ca_info(family))


# --------------------------------------------------------------------------- #
# 6. ASN.1 解析
# --------------------------------------------------------------------------- #
@bp.post("/parse/asn1")
def parse_asn1():
    p = _p()
    text = _first(p, "cert", "data", "content", "asn1")
    if not text:
        raise ToolError("请输入需要解析的 ASN.1 数据")
    data = core.asn1_tree(str(text), _fmt(_first(p, "certFormat", "format")))
    return ok(data)
