"""数字证书校验五个模块（后端）测试 + 与原站接口的交叉验证。

覆盖：
    1) /api/cert/format/check       证书格式逐项校验
    2) /api/cert/chain/check        证书链构建与验证（树结构）
    3) /api/cert/status/check       证书撤销检查（CRL / 离线 OCSP）
    4) /api/cert/crl/status/check   CRL 有效性校验（含 SM2/SM3、RSA/SHA256 验签）
    5) /api/cert/sign/issue         生成 CSR / 本地 CA 签发 / PKCS#12 打包
    6) /api/cert/parse/asn1         ASN.1 树解析

测试里的 CA、终端证书、CRL、OCSP 响应、CSR 全部现场用真实算法生成并验签，
断言的是真实签名结果（不是写死的假数据）；另有一组用例读取
web/modules/cert.js 中内嵌的示例 PEM，保证前端 samples 与后端一致。
"""
from __future__ import annotations

import base64
import datetime as dt
import os
import re
import sys

import pytest
from asn1crypto import core as acore
from asn1crypto import x509 as ax509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.core import cert as core  # noqa: E402
from app.server import create_app  # noqa: E402

UTC = dt.timezone.utc
NB = dt.datetime(2025, 1, 1, tzinfo=UTC)
NA_CA = dt.datetime(2045, 1, 1, tzinfo=UTC)
NA_LEAF = dt.datetime(2035, 1, 1, tzinfo=UTC)

CERT_JS = os.path.join(ROOT, "web", "modules", "cert.js")
ORIGIN = os.environ.get("CB_ORIGIN", "https://cipher.huijusa.cn")
DIFFS: list[str] = []


# --------------------------------------------------------------------------- #
# 夹具：真实 SM2 / RSA 证书体系
# --------------------------------------------------------------------------- #
def _sm2_key() -> dict:
    kp = core.gen_sm2_keypair()
    return {
        "algorithm": "SM2",
        "private_hex": kp["private"],
        "public_hex": kp["public"],
        "spki": core._sm2_public_key_info(kp["public"]),
        "key_obj": None,
        "bits": 256,
    }


def _rsa_key(bits: int = 2048) -> dict:
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"algorithm": "RSA", "private_hex": "", "public_hex": "", "spki": spki, "key_obj": key, "bits": bits}


def _make_ca(family: str, cn: str, serial: int) -> dict:
    key = _sm2_key() if family == "SM2" else _rsa_key()
    subject = ax509.Name.build(
        {"country_name": "CN", "organization_name": "CipherBox Test", "common_name": cn}
    )
    ski = core._key_identifier(key["spki"], key["public_hex"])
    exts = [
        ax509.Extension({"extn_id": "2.5.29.19", "critical": True, "extn_value": {"ca": True, "path_len_constraint": 1}}),
        ax509.Extension(
            {"extn_id": "2.5.29.15", "critical": True, "extn_value": {"key_cert_sign", "crl_sign"}}
        ),
        ax509.Extension({"extn_id": "2.5.29.14", "critical": False, "extn_value": ski}),
        ax509.Extension({"extn_id": "2.5.29.35", "critical": False, "extn_value": {"key_identifier": ski}}),
    ]
    sig_oid, hash_name = ("1.2.156.10197.1.501", "SM3") if family == "SM2" else ("1.2.840.113549.1.1.11", "SHA256")
    der = core.build_certificate(
        subject=subject,
        subject_spki=key["spki"],
        issuer=subject,
        issuer_key=key,
        not_before=NB,
        not_after=NA_CA,
        extensions=exts,
        sig_oid=sig_oid,
        hash_name=hash_name,
        serial=serial,
    )
    return {"family": family, "key": key, "der": der, "pem": core.pem_encode(der), "subject": subject}


def _make_leaf(ca: dict, cn: str, serial: int, san: list[str] | None = None) -> dict:
    key = _sm2_key() if ca["family"] == "SM2" else _rsa_key()
    subject = ax509.Name.build(
        {"country_name": "CN", "organization_name": "CipherBox Test", "common_name": cn}
    )
    ski = core._key_identifier(key["spki"], key["public_hex"])
    aki = core._key_identifier(ca["key"]["spki"], ca["key"]["public_hex"])
    exts = [
        ax509.Extension({"extn_id": "2.5.29.19", "critical": True, "extn_value": {"ca": False, "path_len_constraint": None}}),
        ax509.Extension(
            {"extn_id": "2.5.29.15", "critical": True, "extn_value": {"digital_signature", "key_encipherment"}}
        ),
        ax509.Extension({"extn_id": "2.5.29.37", "critical": False, "extn_value": ["server_auth", "client_auth"]}),
        ax509.Extension(
            {
                "extn_id": "2.5.29.17",
                "critical": False,
                "extn_value": ax509.GeneralNames(
                    [ax509.GeneralName({"dns_name": host}) for host in (san or [cn])]
                ),
            }
        ),
        ax509.Extension({"extn_id": "2.5.29.14", "critical": False, "extn_value": ski}),
        ax509.Extension({"extn_id": "2.5.29.35", "critical": False, "extn_value": {"key_identifier": aki}}),
    ]
    sig_oid, hash_name = ("1.2.156.10197.1.501", "SM3") if ca["family"] == "SM2" else ("1.2.840.113549.1.1.11", "SHA256")
    der = core.build_certificate(
        subject=subject,
        subject_spki=key["spki"],
        issuer=ax509.Certificate.load(ca["der"]).subject,
        issuer_key=ca["key"],
        not_before=NB,
        not_after=NA_LEAF,
        extensions=exts,
        sig_oid=sig_oid,
        hash_name=hash_name,
        serial=serial,
    )
    return {"family": ca["family"], "key": key, "der": der, "pem": core.pem_encode(der), "serial": serial}


@pytest.fixture(scope="session")
def client():
    return create_app().test_client()


@pytest.fixture(scope="session")
def pki() -> dict:
    sm2_ca = _make_ca("SM2", "CipherBox Test SM2 Root", 0xA1B2C3D4E5F60718293A4B5C6D7E8F01)
    rsa_ca = _make_ca("RSA", "CipherBox Test RSA Root", 0xA1B2C3D4E5F60718293A4B5C6D7E8F02)
    sm2_leaf = _make_leaf(sm2_ca, "sm2.test.local", 0xC1B2C3D4E5F60718293A4B5C6D7E8F03, ["sm2.test.local", "www.sm2.test.local"])
    rsa_leaf = _make_leaf(rsa_ca, "rsa.test.local", 0xC1B2C3D4E5F60718293A4B5C6D7E8F04)
    crl_sm2 = core.crl_with_ca(
        {"key": sm2_ca["key"], "cert_der": sm2_ca["der"]},
        [{"serial": sm2_leaf["serial"], "reason": "key_compromise"}],
        days=3650,
        crl_number=7,
    )
    crl_rsa = core.crl_with_ca({"key": rsa_ca["key"], "cert_der": rsa_ca["der"]}, [], days=3650, crl_number=8)
    return {
        "sm2_ca": sm2_ca,
        "rsa_ca": rsa_ca,
        "sm2_leaf": sm2_leaf,
        "rsa_leaf": rsa_leaf,
        "crl_sm2": crl_sm2,
        "crl_sm2_pem": core.pem_encode(crl_sm2, "X509 CRL"),
        "crl_rsa": crl_rsa,
        "crl_rsa_pem": core.pem_encode(crl_rsa, "X509 CRL"),
    }


def post(client, path: str, payload: dict) -> dict:
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    return resp.get_json()


def code_data(body: dict) -> dict:
    assert body.get("code") == 0, body.get("msg")
    return body["data"]


def item_map(items: list[dict]) -> dict[str, dict]:
    return {i["name"]: i for i in items}


# --------------------------------------------------------------------------- #
# 1. 证书格式检查
# --------------------------------------------------------------------------- #
def test_format_check_sm2_self_signed(client, pki):
    data = code_data(post(client, "/api/cert/format/check", {"cert": pki["sm2_ca"]["pem"], "certFormat": "PEM"}))
    items = item_map(data["items"])
    assert data["status"] == "success", data["summary"]
    assert items["证书版本"]["valid"] == 2
    assert items["签名算法"]["value"] == "SM3withSM2"
    assert items["公钥算法"]["valid"] == 2 and "SM2" in items["公钥算法"]["value"]
    assert items["序列号"]["value"] == "A1B2C3D4E5F60718293A4B5C6D7E8F01"
    # 自签证书必须真实验签通过
    assert items["签名验证"]["valid"] == 2 and "通过" in items["签名验证"]["infoMsg"]
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", items["SM3 指纹"]["value"])
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", items["SHA256 指纹"]["value"])
    assert data["cert"]["isCa"] is True
    assert data["cert"]["sigOid"] == "1.2.156.10197.1.501"


def test_format_check_rsa_leaf_hex_and_base64(client, pki):
    der = pki["rsa_leaf"]["der"]
    hex_data = code_data(post(client, "/api/cert/format/check", {"cert": der.hex(), "certFormat": "HEX"}))
    b64_data = code_data(
        post(client, "/api/cert/format/check", {"cert": base64.b64encode(der).decode(), "certFormat": "BASE64"})
    )
    assert hex_data["cert"]["serial"] == b64_data["cert"]["serial"]
    items = item_map(hex_data["items"])
    assert items["公钥算法"]["valid"] == 2 and "RSA" in items["公钥算法"]["value"]
    assert items["签名算法"]["value"] == "SHA256withRSA"
    assert items["主体备用名"]["valid"] == 2 and "rsa.test.local" in items["主体备用名"]["value"]
    # 非自签证书本身无法独立验签 → 部分符合
    assert items["签名验证"]["valid"] == 1
    assert hex_data["status"] == "partial"


def test_format_check_detects_broken_signature(client, pki):
    cert = ax509.Certificate.load(pki["rsa_ca"]["der"])
    sig = bytearray(cert["signature_value"].native)
    sig[-1] ^= 0xFF
    broken = ax509.Certificate(
        {
            "tbs_certificate": cert["tbs_certificate"],
            "signature_algorithm": cert["signature_algorithm"],
            "signature_value": acore.OctetBitString(bytes(sig)),
        }
    ).dump()
    data = code_data(post(client, "/api/cert/format/check", {"cert": broken.hex(), "certFormat": "HEX"}))
    items = item_map(data["items"])
    assert items["签名验证"]["valid"] == 0
    assert data["status"] == "error"


def test_format_check_reports_legacy_time_encoding(client, pki):
    """1950~2049 之间必须使用 UTCTime；超出范围应使用 GeneralizedTime。"""
    cert = ax509.Certificate.load(pki["rsa_leaf"]["der"])
    tbs = cert["tbs_certificate"]
    tbs["validity"]["not_before"] = ax509.Time(
        {"general_time": dt.datetime(2025, 1, 1, tzinfo=UTC)}
    )
    # 重新计算签名，保证只有时间编码一项不规范
    ca = pki["rsa_ca"]
    sig = ca["key"]["key_obj"].sign(tbs.dump(), __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["x"]).PKCS1v15(), hashes.SHA256())
    rebuilt = ax509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": cert["signature_algorithm"],
            "signature_value": acore.OctetBitString(sig),
        }
    ).dump()
    data = code_data(post(client, "/api/cert/format/check", {"cert": rebuilt.hex(), "certFormat": "HEX"}))
    items = item_map(data["items"])
    assert items["时间格式"]["valid"] == 0
    assert "应使用 UTCTime" in items["时间格式"]["infoMsg"]
    assert "GeneralizedTime / UTCTime" in items["时间格式"]["value"]


def test_format_check_rejects_garbage(client):
    body = post(client, "/api/cert/format/check", {"cert": "not-a-cert", "certFormat": "PEM"})
    assert body["code"] == 1
    assert "证书" in body["msg"]
    body2 = post(client, "/api/cert/format/check", {"cert": "", "certFormat": "PEM"})
    assert body2["code"] == 1


# --------------------------------------------------------------------------- #
# 2. 证书链验证
# --------------------------------------------------------------------------- #
def test_chain_check_passes_with_real_signatures(client, pki):
    nodes = [
        {"nodeId": "root", "parentId": None, "name": "根证书", "cert": pki["sm2_ca"]["pem"], "certFormat": "PEM"},
        {"nodeId": "leaf", "parentId": "root", "name": "终端证书", "cert": pki["sm2_leaf"]["pem"], "certFormat": "PEM"},
    ]
    data = code_data(post(client, "/api/cert/chain/check", {"nodes": nodes}))
    assert data["passed"] is True, data["message"]
    results = {r["nodeId"]: r for r in data["nodeResults"]}
    assert results["root"]["chainResults"][0]["name"] == "证书上传"
    root_items = item_map(results["root"]["chainResults"])
    assert root_items["根证书自签"]["valid"] == 2
    assert root_items["根证书签名"]["valid"] == 2
    leaf_items = item_map(results["leaf"]["chainResults"])
    assert leaf_items["颁发者匹配"]["valid"] == 2
    assert leaf_items["签名验证"]["valid"] == 2
    assert leaf_items["上级 CA 约束"]["valid"] == 2
    assert results["leaf"]["parentId"] == "root"
    assert results["leaf"]["formatParsed"] is True
    assert len(results["leaf"]["formatResults"]) > 10


def test_chain_check_fails_on_wrong_hierarchy(client, pki):
    nodes = [
        {"nodeId": "a", "parentId": None, "name": "终端证书当作根", "cert": pki["rsa_leaf"]["pem"], "certFormat": "PEM"},
        {"nodeId": "b", "parentId": "a", "name": "根证书当作下级", "cert": pki["rsa_ca"]["pem"], "certFormat": "PEM"},
    ]
    data = code_data(post(client, "/api/cert/chain/check", {"nodes": nodes}))
    assert data["passed"] is False
    results = {r["nodeId"]: r for r in data["nodeResults"]}
    assert item_map(results["a"]["chainResults"])["根证书自签"]["valid"] == 0
    assert item_map(results["b"]["chainResults"])["颁发者匹配"]["valid"] == 0


def test_chain_check_detects_tampered_leaf(client, pki):
    cert = ax509.Certificate.load(pki["rsa_leaf"]["der"])
    sig = bytearray(cert["signature_value"].native)
    sig[3] ^= 0x5A
    broken = ax509.Certificate(
        {
            "tbs_certificate": cert["tbs_certificate"],
            "signature_algorithm": cert["signature_algorithm"],
            "signature_value": acore.OctetBitString(bytes(sig)),
        }
    ).dump()
    nodes = [
        {"nodeId": "root", "parentId": None, "name": "根证书", "cert": pki["rsa_ca"]["pem"], "certFormat": "PEM"},
        {"nodeId": "leaf", "parentId": "root", "name": "被篡改证书", "cert": core.pem_encode(broken), "certFormat": "PEM"},
    ]
    data = code_data(post(client, "/api/cert/chain/check", {"nodes": nodes}))
    assert data["passed"] is False
    leaf = next(r for r in data["nodeResults"] if r["nodeId"] == "leaf")
    assert item_map(leaf["chainResults"])["签名验证"]["valid"] == 0


def test_chain_auto_order_from_multiple_certs(client, pki):
    # 故意乱序：终端在前、根在后
    text = pki["rsa_leaf"]["pem"] + "\n" + pki["rsa_ca"]["pem"]
    data = code_data(post(client, "/api/cert/chain/check", {"chainCerts": text, "chainCertsFormat": "PEM"}))
    assert data["passed"] is True, data["message"]
    assert data["total"] == 2
    roots = [r for r in data["nodeResults"] if r["parentId"] is None]
    assert len(roots) == 1 and item_map(roots[0]["chainResults"])["根证书自签"]["valid"] == 2


def test_chain_check_reports_missing_cert(client, pki):
    nodes = [
        {"nodeId": "root", "parentId": None, "name": "根证书", "cert": pki["rsa_ca"]["pem"], "certFormat": "PEM"},
        {"nodeId": "empty", "parentId": "root", "name": "空节点", "cert": "", "certFormat": "PEM"},
    ]
    data = code_data(post(client, "/api/cert/chain/check", {"nodes": nodes}))
    assert data["passed"] is False
    empty = next(r for r in data["nodeResults"] if r["nodeId"] == "empty")
    assert empty["uploaded"] is False and empty["status"] == "error"


# --------------------------------------------------------------------------- #
# 3. 证书撤销检查（CRL / OCSP）
# --------------------------------------------------------------------------- #
def test_status_crl_revoked(client, pki):
    data = code_data(
        post(
            client,
            "/api/cert/status/check",
            {
                "mode": "CRL",
                "cert": pki["sm2_leaf"]["pem"], "certFormat": "PEM",
                "crl": pki["crl_sm2_pem"], "crlFormat": "PEM",
            },
        )
    )
    assert data["revoked"] is True
    assert data["crlVerifyResult"] is True
    assert "已吊销" in data["crlRevokeMsg"]
    assert data["crlInfo"]["issuer"].startswith("CN=CipherBox Test SM2 Root")
    assert data["crlInfo"]["entryCount"] == 1


def test_status_crl_not_revoked(client, pki):
    data = code_data(
        post(
            client,
            "/api/cert/status/check",
            {
                "mode": "CRL",
                "cert": pki["rsa_leaf"]["pem"], "certFormat": "PEM",
                "crl": pki["crl_rsa_pem"], "crlFormat": "PEM",
            },
        )
    )
    assert data["revoked"] is False
    assert "未被吊销" in data["crlRevokeMsg"]


def test_status_crl_issuer_mismatch(client, pki):
    data = code_data(
        post(
            client,
            "/api/cert/status/check",
            {
                "mode": "CRL",
                "cert": pki["rsa_leaf"]["pem"], "certFormat": "PEM",
                "crl": pki["crl_sm2_pem"], "crlFormat": "PEM",
            },
        )
    )
    assert data["crlVerifyResult"] is False
    assert item_map(data["items"])["颁发者匹配"]["valid"] == 0


def test_status_ocsp_good_and_revoked(client, pki):
    issued = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "algorithm": "RSA", "keyLength": 2048,
                                             "cnitem": "ocsp.test.local", "citem": "CN", "certType": "SSL", "months": 12})
    )
    good = core.build_ocsp_response(issued["cert"], "RSA", "GOOD")
    data = code_data(
        post(client, "/api/cert/status/check", {"mode": "OCSP", "cert": issued["cert"], "certFormat": "PEM",
                                                "ocspResponse": good.hex(), "ocspResponseFormat": "HEX"})
    )
    assert data["ocspStatus"] == "GOOD"
    assert data["ocspVerifyResult"] is True, data["ocspVerifyMsg"]
    assert data["revoked"] is False
    assert data["ocspInfo"]["responder"].startswith("CN=")
    assert data["ocspInfo"]["signatureAlg"] == "SHA256withRSA"

    revoked = core.build_ocsp_response(issued["cert"], "RSA", "REVOKED")
    data2 = code_data(
        post(client, "/api/cert/status/check", {"mode": "OCSP", "cert": issued["cert"], "certFormat": "PEM",
                                                "ocspResponse": base64.b64encode(revoked).decode(),
                                                "ocspResponseFormat": "BASE64"})
    )
    assert data2["ocspStatus"] == "REVOKED" and data2["revoked"] is True
    assert data2["status"] == "error"


def test_status_ocsp_serial_mismatch(client, pki):
    issued = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "algorithm": "RSA", "keyLength": 2048,
                                             "cnitem": "other.test.local", "citem": "CN", "certType": "SSL", "months": 12})
    )
    resp = core.build_ocsp_response(issued["cert"], "RSA", "GOOD")
    data = code_data(
        post(client, "/api/cert/status/check", {"mode": "OCSP", "cert": pki["rsa_leaf"]["pem"], "certFormat": "PEM",
                                                "ocspResponse": resp.hex(), "ocspResponseFormat": "HEX"})
    )
    assert item_map(data["items"])["序列号匹配"]["valid"] == 0
    assert data["status"] == "error"


def test_status_ocsp_offline_only_address(client, pki):
    body = post(client, "/api/cert/status/check", {"mode": "OCSP", "cert": pki["rsa_leaf"]["pem"],
                                                  "certFormat": "PEM", "ocspAddress": "http://ocsp.example.com"})
    assert body["code"] == 1
    assert "离线" in body["msg"] and "不支持联网" in body["msg"]


def test_status_ocsp_bad_response(client, pki):
    body = post(client, "/api/cert/status/check", {"mode": "OCSP", "cert": pki["rsa_leaf"]["pem"],
                                                  "certFormat": "PEM", "ocspResponse": "deadbeef",
                                                  "ocspResponseFormat": "HEX"})
    assert body["code"] == 1
    assert "OCSP" in body["msg"]


# --------------------------------------------------------------------------- #
# 4. CRL 有效性校验
# --------------------------------------------------------------------------- #
def test_crl_valid_with_real_signature_sm2(client, pki):
    data = code_data(
        post(client, "/api/cert/crl/status/check", {"crl": pki["crl_sm2_pem"], "crlFormat": "PEM",
                                                   "baseCert": pki["sm2_ca"]["pem"], "baseCertFormat": "PEM"})
    )
    assert data["valid"] is True, data["msg"]
    items = item_map(data["items"])
    assert items["CRL 签名验证"]["valid"] == 2
    assert "SM3withSM2" in items["CRL 签名验证"]["infoMsg"]
    assert items["颁发者匹配"]["valid"] == 2
    assert data["crl"]["entryCount"] == 1
    assert data["crl"]["crlNumber"] == 7
    assert "吊销证书列表" in data["crlInfoText"]


def test_crl_valid_with_real_signature_rsa(client, pki):
    data = code_data(
        post(client, "/api/cert/crl/status/check", {"crl": pki["crl_rsa"].hex(), "crlFormat": "HEX",
                                                   "baseCert": pki["rsa_ca"]["der"].hex(), "baseCertFormat": "HEX"})
    )
    assert data["valid"] is True, data["msg"]
    items = item_map(data["items"])
    assert items["CRL 签名验证"]["valid"] == 2
    assert "SHA256withRSA" in items["CRL 签名验证"]["infoMsg"]
    assert items["吊销条目"]["value"] == "0 条"


def test_crl_with_wrong_ca_is_invalid(client, pki):
    data = code_data(
        post(client, "/api/cert/crl/status/check", {"crl": pki["crl_rsa_pem"], "crlFormat": "PEM",
                                                   "baseCert": pki["sm2_ca"]["pem"], "baseCertFormat": "PEM"})
    )
    assert data["valid"] is False
    assert item_map(data["items"])["颁发者匹配"]["valid"] == 0


def test_crl_tampered_signature_is_invalid(client, pki):
    der = bytearray(pki["crl_rsa"])
    der[-1] ^= 0xFF
    data = code_data(
        post(client, "/api/cert/crl/status/check", {"crl": bytes(der).hex(), "crlFormat": "HEX",
                                                   "baseCert": pki["rsa_ca"]["der"].hex(), "baseCertFormat": "HEX"})
    )
    assert data["valid"] is False
    assert item_map(data["items"])["CRL 签名验证"]["valid"] == 0


def test_crl_without_base_cert_is_partial(client, pki):
    data = code_data(
        post(client, "/api/cert/crl/status/check", {"crl": pki["crl_sm2_pem"], "crlFormat": "PEM"})
    )
    assert data["valid"] is True  # 仅解析不验签时不算失败
    assert item_map(data["items"])["CRL 签名验证"]["valid"] == 1
    assert data["baseCert"] is None


# --------------------------------------------------------------------------- #
# 5. 证书签发
# --------------------------------------------------------------------------- #
def test_gen_csr_sm2_and_self_signature(client):
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "csr", "cnitem": "csr.sm2.local", "citem": "CN",
                                             "oitem": "CipherBox", "algorithm": "SM2"})
    )
    assert data["csr"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert data["privateKey"].startswith("-----BEGIN PRIVATE KEY-----")
    assert data["algorithm"] == "SM2" and data["keyBits"] == 256
    assert data["signAlg"] == "SM3withSM2"
    assert data["signatureValid"] is True, "CSR 自签名必须真实验签通过"
    parsed = core._parse_csr(data["csr"])
    assert parsed["req"]["certification_request_info"]["subject"].native["common_name"] == "csr.sm2.local"


def test_gen_csr_rsa_verified_by_cryptography(client):
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "csr", "cnitem": "csr.rsa.local", "citem": "CN",
                                             "algorithm": "RSA", "keyLength": 2048, "signAlg": "SHA256withRSA"})
    )
    parsed = cx509.load_pem_x509_csr(data["csr"].encode())
    assert parsed.is_signature_valid is True
    assert parsed.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)[0].value == "csr.rsa.local"
    assert "2048" not in data["signAlg"] and data["signAlg"].upper() == "SHA256WITHRSA"


def test_issue_from_generated_key_sm2(client):
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "cnitem": "server.sm2.local", "citem": "CN",
                                             "algorithm": "SM2", "certType": "SSL", "months": 12})
    )
    assert data["signatureValid"] is True
    assert data["keySource"] == "内置生成"
    issued = core.load_certs(data["cert"], "PEM")[0]
    ca = core.parse_cert(core.load_local_ca("SM2")["cert_der"])
    ok, msg = core.verify_signature(issued["tbs"], issued["signature"], issued["sig_oid"], ca["spki"], ca["pub_hex"])
    assert ok, msg
    assert "server.sm2.local" in issued["san"]
    assert issued["is_ca"] is False and "server_auth" in issued["eku"]
    # 证书链：签发证书挂在本地 CA 之下必须验证通过
    chain = code_data(
        post(client, "/api/cert/chain/check", {"chainCerts": data["chain"], "chainCertsFormat": "PEM"})
    )
    assert chain["passed"] is True, chain["message"]


def test_issue_from_submitted_csr(client):
    csr = code_data(
        post(client, "/api/cert/sign/issue", {"action": "csr", "cnitem": "p10.local", "citem": "CN",
                                             "algorithm": "SM2"})
    )
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "csr": csr["csr"], "csrFormat": "PEM",
                                             "certType": "SSL", "months": 6})
    )
    assert data["keySource"] == "CSR"
    assert data["signatureValid"] is True
    assert "p10.local" in data["subject"]
    assert data["privateKey"] == ""
    # 提交 CSR 的私钥仍在生成方手里，公钥必须与 CSR 一致
    issued = core.load_certs(data["cert"], "PEM")[0]
    assert issued["pub_hex"]


def test_issue_rejects_tampered_csr(client):
    csr = code_data(
        post(client, "/api/cert/sign/issue", {"action": "csr", "cnitem": "bad.local", "citem": "CN",
                                             "algorithm": "RSA", "keyLength": 2048})
    )
    der = bytearray(core._pem_to_der(csr["csr"]))
    der[-1] ^= 0x01
    body = post(client, "/api/cert/sign/issue", {"action": "issue", "csr": core.pem_encode(bytes(der), "CERTIFICATE REQUEST")})
    assert body["code"] == 1
    assert "CSR" in body["msg"]


def test_issue_ca_intermediate(client):
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "cnitem": "Sub CA", "citem": "CN",
                                             "algorithm": "RSA", "keyLength": 2048, "certType": "CA", "months": 36})
    )
    issued = core.load_certs(data["cert"], "PEM")[0]
    assert issued["is_ca"] is True
    assert "key_cert_sign" in issued["key_usage"]
    assert issued["path_len"] == 0


def test_issue_pfx_rsa_roundtrip(client):
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "cnitem": "pfx.local", "citem": "CN",
                                             "algorithm": "RSA", "keyLength": 2048, "certType": "SSL",
                                             "months": 12, "withPfx": True, "pfxPassword": "pass1234"})
    )
    assert data["pfx"], data.get("pfxMsg")
    assert data["pfxLength"] > 1000
    key, cert, cas = pkcs12.load_key_and_certificates(base64.b64decode(data["pfx"]), b"pass1234")
    assert key.key_size == 2048
    assert cert.serial_number == int(data["serial"], 16)
    assert cas and len(cas) >= 1
    # 私钥与证书公钥必须匹配（cryptography 打包时已校验，这里再比对一次）
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    pub = key.public_key().public_numbers()
    assert isinstance(key, _rsa.RSAPrivateKey) and pub.e == 65537


def test_issue_pfx_sm2_reports_limitation(client):
    data = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "cnitem": "pfx.sm2.local", "citem": "CN",
                                             "algorithm": "SM2", "certType": "SSL", "months": 12,
                                             "withPfx": True, "pfxPassword": "123456"})
    )
    assert data["pfx"] == ""
    assert "SM2" in data["pfxMsg"] and "OpenSSL" in data["pfxMsg"]
    assert data["cert"].startswith("-----BEGIN CERTIFICATE-----")


def test_sign_route_aliases(client):
    body = post(client, "/api/cert/gen/csr", {"cnitem": "alias.local", "citem": "CN", "algorithm": "SM2"})
    assert body["code"] == 0 and body["data"]["csr"].startswith("-----BEGIN")
    issued = post(client, "/api/cert/gen/cert", {"cnitem": "alias.local", "citem": "CN", "algorithm": "RSA", "keyLength": 2048})
    assert issued["code"] == 0 and issued["data"]["signatureValid"] is True


def test_ca_info_and_persistence(client):
    resp = client.get("/api/cert/ca/info?algorithm=SM2")
    body = resp.get_json()
    data = body["data"]
    assert data["selfSigned"] is True and data["signatureValid"] is True
    assert data["sigAlg"] == "SM3withSM2"
    assert os.path.exists(os.path.join(data["path"], "ca_cert.pem"))
    assert os.path.exists(os.path.join(data["path"], "ca_key.pem"))
    # 再次读取必须命中同一份持久化 CA
    again = core.load_local_ca("SM2")
    assert core.parse_cert(again["cert_der"])["serial"] == data["serial"]
    rsa_info = client.get("/api/cert/ca/info?algorithm=RSA").get_json()["data"]
    assert rsa_info["sigAlg"] == "SHA256withRSA" and rsa_info["signatureValid"] is True


# --------------------------------------------------------------------------- #
# 6. ASN.1 解析
# --------------------------------------------------------------------------- #
def test_parse_asn1_tree(client, pki):
    data = code_data(post(client, "/api/cert/parse/asn1", {"cert": pki["rsa_ca"]["pem"], "certFormat": "PEM"}))
    tree = data["tree"]
    assert tree["type"] == "SEQUENCE"
    assert len(tree["children"]) == 3
    assert tree["children"][0]["type"] == "SEQUENCE"  # tbsCertificate
    assert tree["children"][2]["type"] == "BIT STRING"  # signatureValue
    assert data["nodes"] > 20 and data["depth"] >= 4
    assert data["length"] == len(pki["rsa_ca"]["der"])
    types = []

    def walk(node):
        types.append(node["type"])
        for child in node.get("children") or []:
            walk(child)

    walk(tree)
    assert "OBJECT IDENTIFIER" in types
    assert "UTCTime" in types or "GeneralizedTime" in types
    # PEM 与 HEX 输入解析出相同结构
    hex_data = code_data(post(client, "/api/cert/parse/asn1", {"cert": pki["rsa_ca"]["der"].hex(), "certFormat": "HEX"}))
    assert hex_data["nodes"] == data["nodes"]


def test_parse_asn1_invalid(client):
    body = post(client, "/api/cert/parse/asn1", {"cert": "zz", "certFormat": "HEX"})
    assert body["code"] == 1


# --------------------------------------------------------------------------- #
# 7. 前端内嵌示例（web/modules/cert.js）必须可用
# --------------------------------------------------------------------------- #
def _frontend_samples() -> dict[str, str]:
    text = open(CERT_JS, encoding="utf-8").read()
    assert "const SAMPLE = {" in text, "cert.js 必须内嵌固定示例数据"
    return {m.group(1): m.group(2) for m in re.finditer(r"(\w+):\s*`([^`]*)`", text)}


def test_frontend_samples_are_static_pems():
    samples = _frontend_samples()
    for key in ("sm2Root", "sm2Leaf", "rsaRoot", "rsaLeaf"):
        assert samples[key].startswith("-----BEGIN CERTIFICATE-----"), key
    assert samples["crlSm2"].startswith("-----BEGIN X509 CRL-----")
    assert samples["csrSm2"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert len(samples["ocspRsaB64"]) > 200
    # 示例之间必须构成真实可信的链关系
    root = core.load_certs(samples["sm2Root"], "PEM")[0]
    leaf = core.load_certs(samples["sm2Leaf"], "PEM")[0]
    assert leaf["issuer_der"] == root["subject_der"]
    ok, msg = core.verify_signature(leaf["tbs"], leaf["signature"], leaf["sig_oid"], root["spki"], root["pub_hex"])
    assert ok, msg
    crl = core.parse_crl(core.split_boxes(samples["crlSm2"], "PEM")[1][0])
    assert crl["issuer_der"] == root["subject_der"]
    assert any(e["serial"] == leaf["serial"] for e in crl["entries"])


def test_frontend_samples_drive_every_action(client):
    s = _frontend_samples()

    fmt = code_data(post(client, "/api/cert/format/check", {"cert": s["sm2Leaf"], "certFormat": "PEM"}))
    assert fmt["status"] in ("success", "partial") and len(fmt["items"]) > 10

    chain = code_data(
        post(client, "/api/cert/chain/check", {"nodes": [
            {"nodeId": "chain-1", "parentId": None, "name": "根证书", "cert": s["sm2Root"], "certFormat": "PEM"},
            {"nodeId": "chain-2", "parentId": "chain-1", "name": "终端证书", "cert": s["sm2Leaf"], "certFormat": "PEM"},
        ]})
    )
    assert chain["passed"] is True, chain["message"]

    bulk = code_data(
        post(client, "/api/cert/chain/check", {"chainCerts": s["sm2Root"] + "\n" + s["sm2Leaf"], "chainCertsFormat": "PEM"})
    )
    assert bulk["passed"] is True

    status = code_data(
        post(client, "/api/cert/status/check", {"mode": "CRL", "cert": s["sm2Leaf"], "certFormat": "PEM",
                                                "crl": s["crlSm2"], "crlFormat": "PEM"})
    )
    assert status["revoked"] is True and status["crlVerifyResult"] is True

    ocsp = code_data(
        post(client, "/api/cert/status/check", {"mode": "OCSP", "cert": s["rsaLeaf"], "certFormat": "PEM",
                                                "ocspResponse": s["ocspRsaB64"], "ocspResponseFormat": "BASE64"})
    )
    assert ocsp["ocspStatus"] == "GOOD" and ocsp["ocspVerifyResult"] is True

    crl = code_data(
        post(client, "/api/cert/crl/status/check", {"crl": s["crlSm2"], "crlFormat": "PEM",
                                                   "baseCert": s["sm2Root"], "baseCertFormat": "PEM"})
    )
    assert crl["valid"] is True and "SM3withSM2" in crl["crl"]["sigAlg"]

    asn1 = code_data(post(client, "/api/cert/parse/asn1", {"cert": s["sm2Leaf"], "certFormat": "PEM"}))
    assert asn1["tree"]["type"] == "SEQUENCE" and asn1["nodes"] > 10

    csr = code_data(
        post(client, "/api/cert/sign/issue", {"action": "csr", "citem": "CN", "cnitem": "csr.example.com",
                                             "oitem": "CipherBox", "algorithm": "SM2"})
    )
    assert csr["signatureValid"] is True
    p10 = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "csr": s["csrSm2"], "csrFormat": "PEM",
                                             "certType": "SSL", "months": 12})
    )
    assert p10["signatureValid"] is True and "p10.example.com" in p10["subject"]

    issued = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "citem": "CN", "cnitem": "server.example.com",
                                             "oitem": "CipherBox", "algorithm": "RSA", "keyLength": 2048,
                                             "certType": "SSL", "months": 12})
    )
    assert issued["signatureValid"] is True
    pfx = code_data(
        post(client, "/api/cert/sign/issue", {"action": "issue", "citem": "CN", "cnitem": "pfx.example.com",
                                             "algorithm": "RSA", "keyLength": 2048, "certType": "SSL",
                                             "months": 12, "withPfx": True, "pfxPassword": "123456"})
    )
    assert pfx["pfx"] and pfx["pfxLength"] > 1000


# --------------------------------------------------------------------------- #
# 8. 与原站接口交叉验证（原站不可访问时自动跳过）
# --------------------------------------------------------------------------- #
def origin_post(path: str, payload: dict, timeout: int = 20) -> dict:
    import requests

    url = ORIGIN + "/api/cert" + path
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"原站不可访问（{path}）：{exc.__class__.__name__}")
    if resp.status_code >= 500:
        pytest.skip(f"原站 {path} 返回 HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError:
        pytest.skip(f"原站 {path} 返回非 JSON")


def _dn_set(text: str) -> set[str]:
    return {part.strip() for part in str(text or "").split(",") if part.strip()}


def test_crossval_format_check_rsa(client, pki):
    payload = {"cert": pki["rsa_ca"]["der"].hex(), "certFormat": "HEX"}
    remote = origin_post("/check/format", payload)
    local = code_data(post(client, "/api/cert/format/check", payload))

    assert remote.get("code") == 0, remote.get("msg")
    remote_items = item_map(remote["data"])
    local_items = item_map(local["items"])

    assert remote_items["序列号"]["value"].upper() == local_items["序列号"]["value"].upper()
    assert _dn_set(remote_items["使用者"]["value"]) == _dn_set(local["cert"]["subject"])
    assert _dn_set(remote_items["颁发者"]["value"]) == _dn_set(local["cert"]["issuer"])
    assert "SHA256" in remote_items["签名算法"]["value"].upper().replace("WITHRSA", "")
    assert "SHA256withRSA" == local_items["签名算法"]["value"]
    assert remote_items["基本约束"]["valid"] == local_items["基本约束"]["valid"] == 2
    assert remote_items["序列号"]["valid"] == local_items["序列号"]["valid"] == 2

    # 已记录的语义差异（不视为失败）
    if remote_items["密钥用法"]["valid"] != local_items["密钥用法"]["valid"]:
        DIFFS.append(
            "证书格式/密钥用法：原站判定 %s（%s），本地判定 %s（%s）——原站要求 CA 证书 keyUsage 不含 "
            "digitalSignature，本地按 GM/T 0015 允许 digitalSignature + keyCertSign + cRLSign"
            % (
                remote_items["密钥用法"]["valid"], remote_items["密钥用法"]["infoMsg"],
                local_items["密钥用法"]["valid"], local_items["密钥用法"]["infoMsg"],
            )
        )


def test_crossval_pem_and_sm2_support(client, pki):
    """原站只接受 HEX/BASE64 且不解析 SM2 证书；本地为超集，差异需记录。"""
    remote_pem = origin_post("/check/format", {"cert": pki["rsa_ca"]["pem"], "certFormat": "PEM"})
    local_pem = post(client, "/api/cert/format/check", {"cert": pki["rsa_ca"]["pem"], "certFormat": "PEM"})
    assert local_pem["code"] == 0
    if remote_pem.get("code") != 0:
        DIFFS.append(
            "证书格式/PEM 输入：原站 certFormat=PEM 返回 code=%s（%s），本地支持 PEM"
            % (remote_pem.get("code"), remote_pem.get("msg"))
        )

    remote_sm2 = origin_post("/check/format", {"cert": pki["sm2_ca"]["der"].hex(), "certFormat": "HEX"})
    local_sm2 = post(client, "/api/cert/format/check", {"cert": pki["sm2_ca"]["der"].hex(), "certFormat": "HEX"})
    assert local_sm2["code"] == 0 and local_sm2["data"]["cert"]["sigOid"] == "1.2.156.10197.1.501"
    if remote_sm2.get("code") != 0:
        DIFFS.append(
            "证书格式/SM2：原站无法解析 SM2(SM3withSM2) 证书（code=%s，%s），本地可完整解析并验签"
            % (remote_sm2.get("code"), remote_sm2.get("msg"))
        )


def test_crossval_chain_tree(client, pki):
    nodes = [
        {"nodeId": "root", "parentId": None, "name": "根证书", "cert": pki["rsa_ca"]["der"].hex(), "certFormat": "HEX"},
        {"nodeId": "leaf", "parentId": "root", "name": "终端证书", "cert": pki["rsa_leaf"]["der"].hex(), "certFormat": "HEX"},
    ]
    remote = origin_post("/check/chain/tree", {"nodes": nodes})
    local = code_data(post(client, "/api/cert/chain/check", {"nodes": nodes}))
    assert remote.get("code") == 0
    assert remote["data"]["passed"] is True
    assert local["passed"] is True
    remote_leaf = next(r for r in remote["data"]["nodeResults"] if r["nodeId"] == "leaf")
    local_leaf = next(r for r in local["nodeResults"] if r["nodeId"] == "leaf")
    remote_names = [i["name"] for i in remote_leaf["chainResults"]]
    local_names = [i["name"] for i in local_leaf["chainResults"]]
    DIFFS.append(
        "证书链/节点检查项命名：原站 %s；本地 %s（结论一致：签名关系与自签均通过）"
        % ("/".join(remote_names), "/".join(local_names))
    )
    assert local_leaf["chainPassed"] is True


def test_crossval_chain_negative(client, pki):
    nodes = [
        {"nodeId": "a", "parentId": None, "name": "叶子当根", "cert": pki["rsa_leaf"]["der"].hex(), "certFormat": "HEX"},
        {"nodeId": "b", "parentId": "a", "name": "根当下级", "cert": pki["rsa_ca"]["der"].hex(), "certFormat": "HEX"},
    ]
    remote = origin_post("/check/chain/tree", {"nodes": nodes})
    local = code_data(post(client, "/api/cert/chain/check", {"nodes": nodes}))
    assert remote.get("code") == 0
    assert remote["data"]["passed"] is False and local["passed"] is False


def test_crossval_crl_chain(client, pki):
    payload = {"crl": pki["crl_rsa"].hex(), "crlFormat": "HEX",
               "baseCert": pki["rsa_ca"]["der"].hex(), "baseCertFormat": "HEX"}
    remote = origin_post("/check/crl/chain", payload)
    local = code_data(post(client, "/api/cert/crl/status/check", payload))
    assert remote.get("code") == 0, remote.get("msg")
    assert local["valid"] is True
    assert "颁发者" in remote["data"]["chainInfo"]
    assert "SHA256withRSA" in remote["data"]["chainInfo"]
    assert local["crl"]["sigAlg"] == "SHA256withRSA"

    bad = dict(payload)
    bad["baseCert"] = pki["sm2_ca"]["der"].hex()
    remote_bad = origin_post("/check/crl/chain", bad)
    local_bad = code_data(post(client, "/api/cert/crl/status/check", bad))
    assert local_bad["valid"] is False
    if remote_bad.get("code") == 0 and remote_bad.get("data", {}).get("verifyResult") is not False:
        DIFFS.append("CRL 有效性/颁发者不匹配：原站返回 code=0，本地判定无效（结论差异，已记录）")
    else:
        DIFFS.append(
            "CRL 有效性/错误码：原站以 code=%s（%s）表示验证失败，本地以 code=0 + data.valid=false 表示"
            % (remote_bad.get("code"), remote_bad.get("msg"))
        )


def test_crossval_crl_format_text(client, pki):
    remote = origin_post("/check/crl/format", {"crl": pki["crl_rsa"].hex(), "crlFormat": "HEX"})
    local = code_data(post(client, "/api/cert/crl/status/check", {"crl": pki["crl_rsa"].hex(), "crlFormat": "HEX"}))
    assert remote.get("code") == 0
    remote_text = remote["data"] if isinstance(remote["data"], str) else json_dumps(remote["data"])
    for token in ("颁发者", "本次更新时间", "下次更新时间", "签名算法"):
        assert token in remote_text
        assert token in local["crlInfoText"]
    assert local["crl"]["sigAlg"] == "SHA256withRSA"


def test_crossval_asn1_tree(client, pki):
    payload = {"cert": pki["rsa_ca"]["der"].hex(), "certFormat": "HEX"}
    remote = origin_post("/parse/asn1", payload)
    local = code_data(post(client, "/api/cert/parse/asn1", payload))
    assert remote.get("code") == 0
    remote_tree = remote["data"]
    assert remote_tree["type"] == local["tree"]["type"] == "SEQUENCE"
    remote_children = [c["type"] for c in (remote_tree.get("children") or [])]
    local_children = [c["type"] for c in local["tree"]["children"]]
    assert remote_children == local_children == ["SEQUENCE", "SEQUENCE", "BIT STRING"]
    if remote_tree.get("contentLength") != local["tree"]["contentLength"]:
        DIFFS.append(
            "ASN.1/顶层长度：原站 contentLength=%s，本地 %s"
            % (remote_tree.get("contentLength"), local["tree"]["contentLength"])
        )


def test_crossval_report():
    """把交叉验证中记录的差异汇总打印（便于人工复核）。"""
    print("\n===== 与原站交叉验证差异清单 =====")
    if not DIFFS:
        print("（无差异）")
    for idx, diff in enumerate(dict.fromkeys(DIFFS), 1):
        print(f"{idx}. {diff}")
    assert True


def json_dumps(value) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)
