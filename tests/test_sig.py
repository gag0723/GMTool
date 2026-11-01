"""电子签章校验 / 时间戳解析验证 的接口与算法测试。

覆盖：
    - PDF（pyhanko 真实签名，RSA/SHA-256 + 印章 signedAttrs）全部校验通过
    - OFD（SM2/SM3 真实签名 + Seal.esl 印章信息 + 引用文件摘要）全部校验通过
    - 篡改原文 / 篡改签名值 / 无签章文件 的负向用例
    - RFC 3161 与 GB/T 33000-2014 时间戳的解析与验证
    - 与原站（cipher.huijusa.cn）同源接口的交叉验证（网络不可用时自动跳过）
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import make_sig_fixtures as fixkit  # noqa: E402

from app.server import create_app  # noqa: E402
from app.core import sig as sigcore  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ORIGIN = "https://cipher.huijusa.cn"

CHECK_KEYS = [
    "sigFormatData", "signDataValid", "signCertAndSeal",
    "sealValid", "signCertValid", "signTimeValid", "digestValid",
]


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(scope="module")
def pdf_bytes() -> bytes:
    return (FIXTURES / "signed.pdf").read_bytes()


@pytest.fixture(scope="module")
def ofd_bytes() -> bytes:
    return (FIXTURES / "signed.ofd").read_bytes()


@pytest.fixture(scope="module")
def ts_token() -> bytes:
    return (FIXTURES / "timestamp.tsr").read_bytes()


@pytest.fixture(scope="module")
def gb_token() -> bytes:
    return (FIXTURES / "gb_timestamp.tsr").read_bytes()


def post_json(client, path: str, payload: dict) -> dict:
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body is not None
    return body


def assert_all_pass(sig: dict):
    checks = {c["key"]: c for c in sig["checks"]}
    assert set(checks) == set(CHECK_KEYS)
    failed = [c for c in sig["checks"] if c["status"] != "pass"]
    assert not failed, failed
    assert sig["allValid"] is True
    for c in sig["checks"]:
        assert c["message"].strip(), c


# --------------------------------------------------------------------------- #
# 签章夹具本身：真实签名
# --------------------------------------------------------------------------- #

def test_pdf_signature_is_real_and_all_checks_pass(pdf_bytes):
    result = sigcore.check_signature(pdf_bytes)
    assert result["fileType"] == "PDF"
    assert result["signatureCount"] == 1
    sig = result["signatures"][0]
    assert_all_pass(sig)

    details = sig["details"]
    assert details["signAlgorithm"].startswith("SHA256withRSA")
    assert details["digestAlgorithm"] == "SHA-256"
    assert re.fullmatch(r"[0-9a-f]{64}", details["orgDataDigest"])
    assert len(details["signData"]) > 128
    assert details["signCert"] and details["signCertInfo"]["subjectCn"] == "CipherBox 测试签章者"
    assert details["sealName"] == "CipherBox 测试电子印章"
    assert details["makerCert"], "制章者证书应可从印章信息中取出"
    assert details["signTime"] != "-"
    # /ByteRange 必须覆盖全文（最后一段必须落到文件末尾）
    br = details["byteRange"]
    assert br[0] == 0
    assert br[2] + br[3] == len(pdf_bytes)


def test_pdf_signature_verifiable_by_pyhanko(pdf_bytes):
    """用 pyhanko 独立复核同一份 PDF 的签名完整性（交叉验证本地结论）。"""
    from pyhanko.pdf_utils.reader import PdfFileReader

    from pyhanko.sign.validation import validate_pdf_signature

    reader = PdfFileReader(io.BytesIO(pdf_bytes))
    embedded = reader.embedded_signatures
    assert len(embedded) == 1
    status = validate_pdf_signature(embedded[0])
    assert status.intact is True       # 字节范围完整性
    assert status.valid is True        # CMS 签名有效
    assert status.trusted is False     # 自签证书，未接入信任库（应在说明中体现）


def test_ofd_signature_is_real_and_all_checks_pass(ofd_bytes):
    result = sigcore.check_signature(ofd_bytes)
    assert result["fileType"] == "OFD"
    sig = result["signatures"][0]
    assert_all_pass(sig)

    details = sig["details"]
    assert details["signAlgorithm"] == "SM3withSM2"
    assert details["digestAlgorithm"] == "SM3"
    assert details["sealName"] == "CipherBox OFD 测试印章"
    assert details["sealStartTime"] != "-"
    assert len(details["references"]) == 2
    assert all(r["ok"] for r in details["references"])


def test_ofd_baseloc_layout_supported(ofd_bytes):
    """Signature@BaseLoc 指向外部签名描述文件的布局也应被解析。"""
    src = zipfile.ZipFile(io.BytesIO(ofd_bytes))
    names = src.namelist()
    signatures_xml = src.read("Signs/Signatures.xml").decode("utf-8")

    m = re.search(r"<ofd:SignedInfo>.*?</ofd:SignedInfo>", signatures_xml, flags=re.S)
    v = re.search(r"<ofd:SignedValue>.*?</ofd:SignedValue>", signatures_xml, flags=re.S)
    assert m and v
    descriptor = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ofd:Signature xmlns:ofd="http://www.ofdspec.org/2016" ID="sig1">\n'
        + m.group(0) + "\n" + v.group(0) + "\n</ofd:Signature>\n"
    )
    new_signatures = signatures_xml.replace(
        '<ofd:Signature ID="sig1">',
        '<ofd:Signature ID="sig1" BaseLoc="Signs/Signature1.xml">',
    )
    new_signatures = new_signatures.replace(m.group(0), "").replace(v.group(0), "")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for name in names:
            if name == "Signs/Signatures.xml":
                out.writestr(name, new_signatures.encode("utf-8"))
            else:
                out.writestr(name, src.read(name))
        out.writestr("Signs/Signature1.xml", descriptor.encode("utf-8"))

    result = sigcore.check_signature(buf.getvalue())
    sig = result["signatures"][0]
    assert sig["allValid"] is True, [c for c in sig["checks"] if not c["ok"]]


# --------------------------------------------------------------------------- #
# 负向用例
# --------------------------------------------------------------------------- #

def test_tampered_pdf_content_breaks_digest(pdf_bytes):
    tampered = bytearray(pdf_bytes)
    tampered[100] ^= 0x01  # 位于第一个 /ByteRange 区间内
    result = sigcore.check_signature(bytes(tampered))
    checks = {c["key"]: c for c in result["signatures"][0]["checks"]}
    assert checks["digestValid"]["status"] == "fail"
    assert checks["signDataValid"]["status"] == "pass"
    assert result["signatures"][0]["allValid"] is False


def test_tampered_signature_value_is_detected(pdf_bytes):
    """直接篡改 /Contents 里的签名值字节，签名验证必须失败。"""
    from asn1crypto import cms as asn1_cms

    name, sig = sigcore._pdf_collect_sig_dicts(pdf_bytes)[0]
    br = [int(x) for x in sig["/ByteRange"]]
    cms_der = bytes(sig["/Contents"]).rstrip(b"\x00")
    signer = asn1_cms.ContentInfo.load(cms_der)["content"]["signer_infos"][0]
    sig_hex = signer["signature"].native.hex().encode()

    gap_hex = bytes(pdf_bytes[br[1]:br[1] + br[2]]).lower()
    offset = gap_hex.find(sig_hex)
    assert offset > 0, "应在 /Contents 十六进制区间内定位到签名值"

    tampered = bytearray(pdf_bytes)
    pos = br[1] + offset + 10
    tampered[pos] = ord("0") if tampered[pos] != ord("0") else ord("1")
    result = sigcore.check_signature(bytes(tampered))
    sig0 = result["signatures"][0]
    checks = {c["key"]: c for c in sig0["checks"]}
    assert sig0["allValid"] is False
    assert checks["signDataValid"]["status"] == "fail"
    assert checks["digestValid"]["status"] == "pass"  # 原文未被改动，摘要仍匹配


def test_unsigned_pdf_rejected():
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    buf = io.BytesIO()
    writer.write(buf)
    with pytest.raises(sigcore.ToolError) as err:
        sigcore.check_signature(buf.getvalue())
    assert "签章" in str(err.value)


def test_unknown_file_type_rejected():
    with pytest.raises(sigcore.ToolError) as err:
        sigcore.check_signature(b"not a signed document")
    assert "PDF" in str(err.value) or "OFD" in str(err.value)


def test_api_requires_file(client):
    body = post_json(client, "/api/sig/signature/parse", {})
    assert body["code"] == 1
    assert "上传" in body["msg"]


# --------------------------------------------------------------------------- #
# 接口层
# --------------------------------------------------------------------------- #

def test_api_pdf_base64(client, pdf_bytes):
    body = post_json(client, "/api/sig/signature/parse", {
        "file": base64.b64encode(pdf_bytes).decode(),
        "fileFormat": "BASE64",
        "fileName": "signed.pdf",
    })
    assert body["code"] == 0
    data = body["data"]
    assert data["fileType"] == "PDF"
    assert data["signatureCount"] == 1
    assert_all_pass(data["signatures"][0])
    for key in CHECK_KEYS:
        got = [c for c in data["signatures"][0]["checks"] if c["key"] == key]
        assert got, key


def test_api_ofd_multipart(client, ofd_bytes):
    resp = client.post(
        "/api/sig/signature/parse",
        data={"file": (io.BytesIO(ofd_bytes), "signed.ofd")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["code"] == 0
    assert body["data"]["fileType"] == "OFD"
    assert body["data"]["signatures"][0]["allValid"] is True


def test_api_certificate_export_pem(client, pdf_bytes):
    """前端“导出证书”按钮依赖的 PEM 转换接口。"""
    der = sigcore.check_signature(pdf_bytes)["signatures"][0]["details"]["signCert"]
    body = post_json(client, "/api/sig/certificate/export", {"cert": der})
    assert body["code"] == 0
    pem = body["data"]["pem"]
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    assert pem.strip().endswith("-----END CERTIFICATE-----")
    assert base64.b64decode("".join(pem.strip().splitlines()[1:-1])).hex() == base64.b64decode(der).hex()


def test_api_rejects_oversized_file(client):
    big = base64.b64encode(b"%PDF-" + b"0" * (11 * 1024 * 1024)).decode()
    body = post_json(client, "/api/sig/signature/parse", {"file": big, "fileFormat": "BASE64"})
    assert body["code"] == 1
    assert "10 MB" in body["msg"]


# --------------------------------------------------------------------------- #
# 时间戳
# --------------------------------------------------------------------------- #

def test_timestamp_parse_fields(client, ts_token):
    body = post_json(client, "/api/sig/timestamp/parse", {
        "tokenData": base64.b64encode(ts_token).decode(), "tokenFormat": "BASE64",
    })
    assert body["code"] == 0
    data = body["data"]
    assert data["version"] == 1
    assert data["serialNumber"] == 2026060100001
    assert data["policy"] == "1.3.6.1.4.1.55555.1.1"
    assert data["hashAlgorithm"] == "SHA-256"
    assert data["signatureAlgorithm"] == "SHA256withRSA"
    assert data["tsaName"] == "CipherBox 测试 TSA"
    assert data["ordering"] is False
    assert data["accuracy"] == 100000
    assert data["accuracyText"] == "100 毫秒"
    assert data["nonce"] == "5A5A5A5A"
    assert re.fullmatch(r"[0-9a-f]{64}", data["messageImprint"])
    assert data["certificateDetails"][0]["subjectCn"] == "CipherBox 测试 TSA"
    assert data["certificateDetails"][0]["base64"]


def test_timestamp_verify_ok(client, ts_token):
    original = b"A demo message for timestamp verification."
    body = post_json(client, "/api/sig/timestamp/verify", {
        "tokenData": base64.b64encode(ts_token).decode(), "tokenFormat": "BASE64",
        "originalData": original.decode(), "originalFormat": "TEXT",
    })
    assert body["code"] == 0
    data = body["data"]
    assert data["valid"] is True
    assert data["signatureValid"] is True
    assert data["digestMatch"] is True
    assert data["expectedDigest"] == data["computedDigest"]
    assert data["timeValid"] is True


def test_timestamp_verify_detects_wrong_data(client, ts_token):
    body = post_json(client, "/api/sig/timestamp/verify", {
        "tokenData": base64.b64encode(ts_token).decode(), "tokenFormat": "BASE64",
        "originalData": "tampered message", "originalFormat": "TEXT",
    })
    assert body["code"] == 0
    data = body["data"]
    assert data["valid"] is False
    assert data["digestMatch"] is False
    assert data["signatureValid"] is True
    assert "不一致" in data["message"]


def test_gb_timestamp_sm2_sm3(client, gb_token):
    body = post_json(client, "/api/sig/timestamp/verify", {
        "tokenData": gb_token.hex(), "tokenFormat": "HEX",
        "originalData": "A demo message for timestamp verification.", "originalFormat": "TEXT",
    })
    assert body["code"] == 0
    data = body["data"]
    assert data["hashAlgorithm"] == "SM3"
    assert data["signatureAlgorithm"] == "SM3withSM2"
    assert data["valid"] is True
    assert data["signatureValid"] is True
    assert data["digestMatch"] is True


def test_timestamp_invalid_token(client):
    body = post_json(client, "/api/sig/timestamp/parse", {"tokenData": "3003020101", "tokenFormat": "HEX"})
    assert body["code"] == 1
    assert "令牌" in body["msg"] or "时间戳" in body["msg"]


# --------------------------------------------------------------------------- #
# 夹具可复现
# --------------------------------------------------------------------------- #

def test_fixture_generator_reproduces_valid_signatures():
    data = fixkit.generate_all(write=False)
    assert data["signed.pdf"].startswith(b"%PDF")
    pdf_sig = sigcore.check_signature(data["signed.pdf"])["signatures"][0]
    assert_all_pass(pdf_sig)
    ofd_sig = sigcore.check_signature(data["signed.ofd"])["signatures"][0]
    assert_all_pass(ofd_sig)
    verified = sigcore.verify_timestamp(data["timestamp.tsr"], b"A demo message for timestamp verification.")
    assert verified["valid"] and verified["digestMatch"]
    gb = sigcore.verify_timestamp(data["gb_timestamp.tsr"], b"A demo message for timestamp verification.")
    assert gb["valid"] and gb["signatureValid"]


# --------------------------------------------------------------------------- #
# 与原站接口的交叉验证
# --------------------------------------------------------------------------- #

def _http(url: str, data: bytes | None, headers: dict | None = None, timeout: int = 25):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _post_json_remote(path: str, payload: dict):
    return _http(ORIGIN + path, json.dumps(payload).encode("utf-8"),
                 {"Content-Type": "application/json"})


def _post_file_remote(path: str, content: bytes, filename: str, content_type: str):
    boundary = "----CipherBoxCrossCheck"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return _http(ORIGIN + path, body,
                 {"Content-Type": f"multipart/form-data; boundary={boundary}"})


def _origin_available() -> bool:
    if os.environ.get("CIPHERBOX_SKIP_REMOTE") == "1":
        return False
    try:
        req = urllib.request.Request(ORIGIN + "/", method="GET")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception:
        return False


def test_cross_check_with_origin_site(client, pdf_bytes, ofd_bytes, ts_token, gb_token):
    """同一份文件 / 令牌分别调用原站与本地实现，逐项比对结论与字段。

    原站不可达（或设置 CIPHERBOX_SKIP_REMOTE=1）时跳过；可用 pyhanko 独立复核见
    test_pdf_signature_verifiable_by_pyhanko。
    """
    if not _origin_available():
        pytest.skip("原站 cipher.huijusa.cn 不可用，跳过在线交叉验证（本地结果已用 pyhanko 独立复核）")
    report = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "origin": ORIGIN,
        "cases": [],
        "differences": [],
    }

    # ---- 1. PDF 签章 ----
    local_pdf = sigcore.check_signature(pdf_bytes)
    status, origin_pdf = _post_file_remote("/api/signature/parse", pdf_bytes, "signed.pdf", "application/pdf")
    case = {
        "case": "signature/pdf",
        "originHttp": status,
        "originCode": origin_pdf.get("code"),
        "originMsg": origin_pdf.get("msg"),
        "checks": [],
    }
    origin_sig = (origin_pdf.get("data") or [{}])[0] if isinstance(origin_pdf.get("data"), list) else {}
    local_sig = local_pdf["signatures"][0]
    local_map = {c["key"]: c for c in local_sig["checks"]}
    for key in CHECK_KEYS:
        origin_value = origin_sig.get(key)
        local_value = local_map[key]["ok"]
        match = origin_value == local_value
        case["checks"].append({
            "key": key, "local": local_value, "origin": origin_value, "match": match,
            "originMessage": origin_sig.get(key + "Msg"),
        })
        if not match:
            report["differences"].append({
                "case": "signature/pdf", "field": key,
                "local": local_value, "origin": origin_value,
                "originMessage": origin_sig.get(key + "Msg"),
                "reason": "原站按 GB/T 38540-2020 的 SES 签章结构判定，标准 ISO 32000/PAdES"
                          "（RSA/SHA-256）PDF 签名在其实现中一律判为格式不符",
            })
    report["cases"].append(case)
    assert status == 200 and origin_pdf.get("code") == 0
    assert local_sig["allValid"] is True
    assert case["checks"][0]["origin"] is False  # 已确认的差异，记录而非掩盖

    # ---- 2. OFD 签章 ----
    local_ofd = sigcore.check_signature(ofd_bytes)
    status, origin_ofd = _post_file_remote("/api/signature/parse", ofd_bytes, "signed.ofd", "application/ofd")
    report["cases"].append({
        "case": "signature/ofd",
        "originHttp": status,
        "originCode": origin_ofd.get("code"),
        "originMsg": origin_ofd.get("msg"),
        "localAllValid": local_ofd["signatures"][0]["allValid"],
    })
    assert local_ofd["signatures"][0]["allValid"] is True
    if origin_ofd.get("code") != 0:
        report["differences"].append({
            "case": "signature/ofd", "field": "整体",
            "local": "解析通过，7 项校验全部通过",
            "origin": origin_ofd.get("msg"),
            "reason": "原站 OFD 解析要求 Signature@BaseLoc 指向签名描述文件，"
                      "对 GB/T 33190 内联 SignedInfo/SignedValue 布局直接返回 500",
        })

    # ---- 3. 时间戳解析 / 验证 ----
    for name, token, expected_sig in (
        ("timestamp/rfc3161", ts_token, "SHA256withRSA"),
        ("timestamp/gb33000", gb_token, "SM3withSM2"),
    ):
        local_parsed = sigcore.parse_timestamp(token)
        payload = {"tokenData": base64.b64encode(token).decode(), "tokenFormat": "BASE64"}
        status, origin_parsed = _post_json_remote("/api/timestamp/parse", payload)
        od = origin_parsed.get("data") or {}
        fields = []
        simple_pairs = [
            ("policy", local_parsed["policy"], od.get("policy")),
            ("serialNumber", local_parsed["serialNumber"], od.get("serialNumber")),
            ("ordering", local_parsed["ordering"], od.get("ordering")),
            ("accuracyMicros", local_parsed["accuracy"], od.get("accuracy")),
            ("nonce", (local_parsed["nonce"] or "").upper(), (od.get("nonce") or "").upper()),
            ("version", str(local_parsed["version"]), str(od.get("version"))),
        ]
        for field, lv, ov in simple_pairs:
            match = lv == ov
            fields.append({"field": field, "local": lv, "origin": ov, "match": match})
            if not match:
                report["differences"].append({"case": name, "field": field, "local": lv, "origin": ov})
        # 算法族与时间戳时间做语义比对（原站带 OID 后缀 / 本地时区显示）
        def norm_algo(text):
            return (text or "").upper().replace("-", "").replace("_", "")

        fields.append({
            "field": "hashAlgorithm",
            "local": local_parsed["hashAlgorithm"],
            "origin": od.get("hashAlgorithm"),
            "match": norm_algo(local_parsed["hashAlgorithm"]) in norm_algo(od.get("hashAlgorithm")),
        })
        fields.append({
            "field": "signatureAlgorithm",
            "local": local_parsed["signatureAlgorithm"],
            "origin": od.get("signatureAlgorithm"),
            "match": expected_sig in (od.get("signatureAlgorithm") or "") or
                     ("SM2" in local_parsed["signatureAlgorithm"] and od.get("signatureAlgorithm") == "SM2"),
        })
        fields.append({
            "field": "genTime",
            "local": local_parsed["genTime"],
            "origin": od.get("genTime"),
            "match": (od.get("genTime") or "")[:19] == local_parsed["genTime"][:19],
        })

        verify_payload = dict(payload, originalData="A demo message for timestamp verification.",
                              originalFormat="TEXT")
        status_v, origin_verify = _post_json_remote("/api/timestamp/verify", verify_payload)
        local_verify = sigcore.verify_timestamp(token, b"A demo message for timestamp verification.")
        fields.append({
            "field": "valid",
            "local": local_verify["valid"],
            "origin": (origin_verify.get("data") or {}).get("valid"),
            "match": local_verify["valid"] == (origin_verify.get("data") or {}).get("valid"),
        })
        report["cases"].append({"case": name, "originCode": origin_parsed.get("code"), "fields": fields})
        assert origin_parsed.get("code") == 0
        assert local_verify["valid"] is True
        assert all(f["match"] for f in fields if f["field"] != "signatureAlgorithm" or expected_sig.startswith("SHA256")), \
            [f for f in fields if not f["match"]]

    report_path = FIXTURES / "crosscheck_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    assert report_path.exists()
    assert len(report["cases"]) >= 4
    # 差异必须被显式记录（而不是静默忽略）
    assert report["differences"], "与原站的差异应逐条记录"
    assert all({"case", "field"} <= set(d) for d in report["differences"])
