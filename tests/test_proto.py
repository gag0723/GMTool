"""协议分析工具（TLS / SSH / IPSec / UKey）后端测试。

测试数据全部由 tests/make_fixtures.py 现场构造：真实 pcap 字节 + 真实握手报文，
证书与签名由 cryptography 生成，因此断言的是"真解析结果"而不是写死的假数据。
"""
from __future__ import annotations

import base64
import json
import os
import struct
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.core import protocols  # noqa: E402
from app.server import create_app  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


NEEDED = ("expectations.json", "tls_session.pcap", "tls_session.pcapng", "ssh_session.pcap",
          "ipsec_ikev2.pcap", "ipsec_ikev1.pcap", "ukey_ccid.pcap")


def _ensure_fixtures() -> None:
    """测试数据缺失时现场生成（tests/make_fixtures.py 可重复执行）。"""
    if all(os.path.exists(os.path.join(FIX, name)) for name in NEEDED):
        return
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import make_fixtures  # noqa: WPS433

    make_fixtures.main()


def _expect() -> dict:
    _ensure_fixtures()
    with open(os.path.join(FIX, "expectations.json"), encoding="utf-8") as fh:
        return json.load(fh)


EXP = _expect()


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _b64(kind: str) -> str:
    with open(EXP[kind]["file"], "rb") as fh:
        return base64.b64encode(fh.read()).decode()


def _post(client, path: str, payload: dict) -> dict:
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    return resp.get_json()


# ---------------------------------------------------------------- TLS
def test_tls_sessions_and_protocol(client):
    body = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls"), "pcapFormat": "BASE64"})
    assert body["code"] == 0, body.get("msg")
    data = body["data"]
    assert data["count"] == 2
    assert data["meta"]["packets"] > 10

    tls12 = next(s for s in data["sessions"] if s["protocol"] == "TLS 1.2")
    tls13 = next(s for s in data["sessions"] if s["protocol"] == "TLS 1.3")
    assert tls12["successHandshake"] is True
    assert tls12["bilateralAuth"] is True
    assert tls12["authMode"] == "双向认证"
    assert "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" in tls12["serverCipherSuite"]
    assert tls12["cipherSuiteCode"] == "0xC02B"
    assert tls12["sni"] == "test.local"
    assert "h2" in tls12["alpn"]
    assert tls13["sni"] == "tls13.local"
    assert any("TLS 1.3" in n for n in tls13["notes"])


def test_tls_certificate_chain(client):
    data = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls")})["data"]
    tls12 = next(s for s in data["sessions"] if s["protocol"] == "TLS 1.2")
    chain = tls12["serverCertList"]
    assert len(chain) == 2, [c["subject"] for c in chain]
    assert chain[0]["subject"] == EXP["tls"]["serverSubject"]
    assert chain[1]["subject"].startswith("CN=CipherBox Test Root CA")
    assert chain[0]["publicKeyAlgorithm"].startswith("ECC")
    assert chain[0]["keyBits"] == 256
    assert tls12["clientCertChain"] == [EXP["tls"]["clientSubject"]]

    # 导出的 PEM 必须能被 cryptography 重新读回，且与 DER 一致
    pem = chain[0]["pem"]
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(pem.encode())
    assert cert.subject.rfc4514_string() == EXP["tls"]["serverSubject"]
    assert base64.b64decode(chain[0]["base64"]) == cert.public_bytes(serialization.Encoding.DER)


def test_tls_signature_verification(client):
    data = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls")})["data"]
    tls12 = next(s for s in data["sessions"] if s["protocol"] == "TLS 1.2")
    ske = tls12["serverKeyExchange"]
    assert ske["present"] is True
    assert ske["checked"] is True
    assert ske["result"] is True, ske["reason"]
    assert ske["curve"] == "secp256r1"
    assert len(ske["signature"]) > 100

    cv = tls12["clientCertVerify"]
    assert cv["present"] is True
    assert cv["checked"] is True
    assert cv["result"] is True, cv["reason"]
    assert cv["signatureAlgorithm"].startswith("ecdsa")
    # 篡改签名后应验签失败（证明验签是真算的）
    pub = x509.load_der_x509_certificate(base64.b64decode(tls12["clientCertList"][0]["base64"])).public_key()
    ok, reason = protocols._verify_with_key(pub, 0x0403, b"tampered", bytes.fromhex(cv["signature"]))
    assert ok is False and "失败" in reason


def test_tls_timeline_and_records(client):
    data = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls")})["data"]
    tls12 = next(s for s in data["sessions"] if s["protocol"] == "TLS 1.2")
    names = [e["message"] for e in tls12["timeline"]]
    for expected in ("ClientHello", "ServerHello", "Certificate", "ServerKeyExchange",
                     "CertificateRequest", "ServerHelloDone", "ClientKeyExchange",
                     "CertificateVerify", "ChangeCipherSpec", "Finished"):
        assert expected in names, (expected, names)
    assert tls12["recordCount"] >= 10
    assert tls12["addressInfo"]["dstPort"] == 443


def test_tls_filters_and_filename(client):
    body = _post(client, "/api/proto/tls/parse", {
        "pcap": _b64("tls"), "srcAddr": "10.10.1.5", "dstAddr": "10.10.2.10",
    })
    assert body["data"]["count"] == 1
    assert body["data"]["sessions"][0]["addressInfo"]["srcAddr"] == "10.10.1.5"

    # 过滤条件不匹配时应报中文错误而不是崩溃
    body = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls"), "dstAddr": "192.0.2.1"})
    assert body["code"] == 1 and "未在网络包中识别到" in body["msg"]

    # 文件名中的 IP 可自动作为过滤条件
    body = _post(client, "/api/proto/tls/parse", {
        "pcap": _b64("tls"), "fileName": "src_10.10.1.6_dst_10.10.2.10.pcap",
    })
    assert body["data"]["count"] == 1
    assert body["data"]["sessions"][0]["sni"] == "tls13.local"


def test_tls_pcapng_and_multipart(client):
    with open(os.path.join(FIX, "tls_session.pcapng"), "rb") as fh:
        raw = fh.read()
    body = _post(client, "/api/proto/tls/parse", {"pcap": base64.b64encode(raw).decode()})
    assert body["code"] == 0
    assert body["data"]["meta"]["format"] == "pcapng"
    assert body["data"]["count"] == 2

    # multipart/form-data（与原站一致的上传方式）
    resp = client.post("/api/proto/tls/parse", data={
        "pcapFile": (open(EXP["tls"]["file"], "rb"), "tls_session.pcap"),
    }, content_type="multipart/form-data")
    payload = resp.get_json()
    assert payload["code"] == 0 and payload["data"]["count"] == 2


def test_tls_invalid_input(client):
    assert _post(client, "/api/proto/tls/parse", {})["code"] == 1
    bad = _post(client, "/api/proto/tls/parse", {"pcap": base64.b64encode(b"not a pcap").decode()})
    assert bad["code"] == 1 and ("pcap" in bad["msg"] or "长度不足" in bad["msg"])
    # 端口非法
    bad_port = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls"), "dstPort": "abc"})
    assert bad_port["code"] == 1 and "端口" in bad_port["msg"]


# ---------------------------------------------------------------- SSH
def test_ssh_negotiation(client):
    body = _post(client, "/api/proto/ssh/parse", {"pcap": _b64("ssh"), "sshPort": 22})
    assert body["code"] == 0, body.get("msg")
    s = body["data"]["sessions"][0]
    assert s["protocolVersion"] == EXP["ssh"]["serverVersion"]
    assert s["clientVersion"] == EXP["ssh"]["clientVersion"]
    assert s["kexAlgorithms"] == "curve25519-sha256"
    assert s["encryptAlgorithm"] == "aes128-ctr"
    assert s["macAlgorithm"] == "hmac-sha2-256"
    assert s["hostKeyType"] == "ssh-ed25519"
    # 服务端/客户端的算法清单必须来自真实 KEXINIT
    assert "aes256-gcm@openssh.com" in s["serverEncryptAlgorithms"]
    assert "aes256-ctr" in s["clientEncryptAlgorithms"]
    assert "hmac-sha1" in s["clientMacAlgorithms"]
    assert "curve25519-sha256" in s["serverKexAlgorithms"]


def test_ssh_dh_params_and_signature(client):
    data = _post(client, "/api/proto/ssh/parse", {"pcap": _b64("ssh")})["data"]
    s = data["sessions"][0]
    assert len(s["clientDHQc"]) == 64          # X25519 公钥 32 字节
    assert len(s["serverDHQc"]) == 64
    assert s["clientDHQc"] != s["serverDHQc"]
    assert s["signature"] and len(s["signature"]) == 128   # Ed25519 签名 64 字节
    assert s["signatureAlgorithm"] == "ssh-ed25519"
    assert s["hostKeyFingerprint"].startswith("SHA256:")
    # 被动抓包拿不到 K，必须明确标注无法验签
    assert s["signVerify"]["checked"] is False
    assert "共享秘密" in s["signVerify"]["reason"]


def test_ssh_signature_verify_with_secret(client):
    good = _post(client, "/api/proto/ssh/parse", {
        "pcap": _b64("ssh"), "kexSecret": EXP["ssh"]["kexSecret"],
    })["data"]["sessions"][0]
    assert good["signVerify"]["checked"] is True
    assert good["signVerify"]["result"] is True, good["signVerify"]["reason"]

    wrong = _post(client, "/api/proto/ssh/parse", {
        "pcap": _b64("ssh"), "kexSecret": "00" * 32,
    })["data"]["sessions"][0]
    assert wrong["signVerify"]["result"] is False
    assert "失败" in wrong["signVerify"]["reason"]

    bad_hex = _post(client, "/api/proto/ssh/parse", {"pcap": _b64("ssh"), "kexSecret": "zz"})
    assert bad_hex["code"] == 1 and "十六进制" in bad_hex["msg"]


def test_ssh_other_protocol_rejected(client):
    body = _post(client, "/api/proto/ssh/parse", {"pcap": _b64("tls")})
    assert body["code"] == 1 and "SSH" in body["msg"]


# ---------------------------------------------------------------- IPSec
def test_ipsec_ikev2(client):
    body = _post(client, "/api/proto/ipsec/parse", {"pcap": _b64("ipsec")})
    assert body["code"] == 0, body.get("msg")
    assert body["data"]["count"] == 1
    s = body["data"]["sessions"][0]
    assert s["protocol"] == "IKEv2"
    assert s["version"] == "2.0"
    assert s["initiatorSPI"] == EXP["ipsec"]["initiatorSPI"]
    assert s["responderSPI"] == EXP["ipsec"]["responderSPI"]
    assert s["encAlgorithm"] == "AES-CBC"
    assert s["encKeyLength"] == 256
    assert s["macAlgorithm"] == "HMAC-SHA2-256-128"
    assert s["prfAlgorithm"] == "HMAC-SHA2-256"
    assert s["dhGroup"] == "MODP-2048"
    assert s["lifeDuration"] == 28800
    assert s["skEncrypted"] is True
    assert len(s["clientNonce"]) == 64 and len(s["serverNonce"]) == 64
    assert s["clientIdentity"].startswith("client@ipsec.test")
    assert s["serverIdentity"].startswith("vpn.ipsec.test")
    assert s["addressInfo"]["srcPort"] == 500


def test_ipsec_cert_payload(client):
    s = _post(client, "/api/proto/ipsec/parse", {"pcap": _b64("ipsec")})["data"]["sessions"][0]
    assert [c["subject"] for c in s["clientCertList"]] == [EXP["ipsec"]["clientSubject"]]
    assert [c["subject"] for c in s["serverCertList"]] == [EXP["ipsec"]["serverSubject"]]
    cert = s["serverCertList"][0]
    assert cert["pem"].startswith("-----BEGIN CERTIFICATE-----")
    # base64 与 PEM 必须是同一份 DER
    pem_body = "".join(cert["pem"].splitlines()[1:-1])
    assert pem_body == cert["base64"]
    assert s["proposals"] and s["proposals"][0]["encLen"] == 256
    assert [m["exchange"] for m in s["messages"]] == ["IKE_SA_INIT", "IKE_SA_INIT", "IKE_AUTH", "IKE_AUTH"]


def test_ipsec_ikev1(client):
    body = _post(client, "/api/proto/ipsec/parse", {"pcap": _b64("ipsecV1")})
    assert body["code"] == 0, body.get("msg")
    s = body["data"]["sessions"][0]
    assert s["protocol"] == "IKEv1"
    assert s["version"] == "1.0"
    assert s["initiatorSPI"] == EXP["ipsecV1"]["initiatorSPI"]
    assert s["responderSPI"] == EXP["ipsecV1"]["responderSPI"]
    assert s["encAlgorithm"] == "3DES"
    assert s["encKeyLength"] == 168
    assert s["clientNonce"] == EXP["ipsecV1"]["clientNonce"]


def test_ipsec_reject_other_traffic(client):
    body = _post(client, "/api/proto/ipsec/parse", {"pcap": _b64("tls")})
    assert body["code"] == 1 and "IPSec" in body["msg"]


# ---------------------------------------------------------------- UKey
def test_ukey_apdu_parsing(client):
    body = _post(client, "/api/proto/ukey/parse", {"pcap": _b64("ukey")})
    assert body["code"] == 0, body.get("msg")
    data = body["data"]
    assert data["atr"] == EXP["ukey"]["atr"]
    names = [a.get("name") for a in data["apdus"] if a["direction"] == "命令"]
    assert names == EXP["ukey"]["apduCommands"], names
    commands = [a for a in data["apdus"] if a["direction"] == "命令"]
    assert commands[0]["cla"] == "00" and commands[0]["ins"] == "A4"
    assert commands[0]["p1"] == "04"
    assert commands[0]["lc"] == 8
    assert all(c["sw"] == "9000" for c in commands)
    assert all(c["swText"] for c in commands)
    assert data["apduCount"] == 3


def test_ukey_vendor_and_cert(client):
    data = _post(client, "/api/proto/ukey/parse", {"pcap": _b64("ukey")})["data"]
    assert data["vendor"] == EXP["ukey"]["vendor"]
    assert data["vendorConfidence"] == "high"
    assert [c["subject"] for c in data["certificates"]] == [EXP["ukey"]["subject"]]
    cert = data["certificates"][0]
    assert x509.load_pem_x509_certificate(cert["pem"].encode()).subject.rfc4514_string() == EXP["ukey"]["subject"]
    # 手动指定厂商时以用户选择为准
    manual = _post(client, "/api/proto/ukey/parse", {"pcap": _b64("ukey"), "factory": "三未信安"})["data"]
    assert manual["vendor"] == "三未信安" and manual["vendorConfidence"] == "manual"


def test_ukey_rejects_non_usb(client):
    body = _post(client, "/api/proto/ukey/parse", {"pcap": _b64("tls")})
    assert body["code"] == 1 and "APDU" in body["msg"]


# ---------------------------------------------------------------- 内部函数 / 覆盖
def test_rsa_signature_helper():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data = b"cipherbox-protocol-test"
    sig = key.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())
    ok, reason = protocols._verify_with_key(key.public_key(), 0x0401, data, sig)
    assert ok is True and "通过" in reason
    bad, _ = protocols._verify_with_key(key.public_key(), 0x0401, data + b"x", sig)
    assert bad is False


def test_cipher_suite_and_filename_helpers():
    assert "0xC02F" in protocols._suite_name(0xC02F)
    assert protocols._suite_name(0x1301).startswith("TLS_AES_128_GCM_SHA256")
    assert "未知" in protocols._suite_name(0x9999) or "UNKNOWN" in protocols._suite_name(0x9999)
    assert protocols.parse_ips_from_filename("src_192.168.1.1_dst_10.0.0.2.pcap") == ["192.168.1.1", "10.0.0.2"]
    assert protocols.parse_ips_from_filename("capture.pcap") == []


def test_frontend_samples_match_fixtures():
    """前端 samples 中的 base64 pcap 必须能被后端真实解析。"""
    js = open(os.path.join(ROOT, "web", "modules", "proto.js"), encoding="utf-8").read()
    import re

    samples = dict(re.findall(r"const ([A-Z0-9]+)_PCAP\s*=\s*'([A-Za-z0-9+/=]+)'", js))
    assert set(samples) >= {"TLS", "SSH", "IPSEC", "UKEY"}, samples.keys()
    app = create_app()
    client = app.test_client()
    for kind, b64 in samples.items():
        path = "/api/proto/%s/parse" % kind.lower()
        body = client.post(path, json={"pcap": b64, "pcapFormat": "BASE64"}).get_json()
        assert body["code"] == 0, (kind, body.get("msg"))


def test_all_endpoints_registered():
    app = create_app()
    rules = {r.rule for r in app.url_map.iter_rules()}
    for path in ("/api/proto/tls/parse", "/api/proto/ssh/parse",
                 "/api/proto/ipsec/parse", "/api/proto/ukey/parse"):
        assert path in rules


def test_packet_count_matches_dpkt(client):
    """用 dpkt 独立读包，核对本地 pcap 解析的报文数。"""
    dpkt = pytest.importorskip("dpkt")
    for kind in ("tls", "ssh", "ipsec", "ipsecV1"):
        count = 0
        with open(EXP[kind]["file"], "rb") as fh:
            for _ts, _buf in dpkt.pcap.Reader(fh):
                count += 1
        endpoint = "ipsec" if kind.startswith("ipsec") else kind
        body = _post(client, "/api/proto/%s/parse" % endpoint, {"pcap": _b64(kind)})
        assert body["data"]["meta"]["packets"] == count, kind


def test_tls_exported_chain_is_valid(client):
    """导出的 PEM 证书链必须能通过 CA 签名验证（与解析结果自洽）。"""
    data = _post(client, "/api/proto/tls/parse", {"pcap": _b64("tls")})["data"]
    tls12 = next(s for s in data["sessions"] if s["protocol"] == "TLS 1.2")
    leaf_pem, ca_pem = tls12["serverCertList"][0]["pem"], tls12["serverCertList"][1]["pem"]
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    ca = x509.load_pem_x509_certificate(ca_pem.encode())
    assert leaf.issuer == ca.subject
    ca.public_key().verify(
        leaf.signature, leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )


def test_tls_midcapture_server_only(client):
    """中途抓包（只有服务端方向）仍应解析出协议版本与证书链。"""
    raw = open(EXP["tls"]["file"], "rb").read()
    header, pos, keep = raw[:24], 24, []
    while pos + 16 <= len(raw):
        ts, frac, incl, _orig = struct.unpack("<IIII", raw[pos:pos + 16])
        pos += 16
        data = raw[pos:pos + incl]
        pos += incl
        if len(data) > 34 and data[26:30] == bytes([10, 10, 2, 10]):    # 源 IP = 服务端
            keep.append((ts, frac, data))
    assert keep
    out = [header]
    for ts, frac, data in keep:
        out.append(struct.pack("<IIII", ts, frac, len(data), len(data)) + data)
    body = _post(client, "/api/proto/tls/parse",
                 {"pcap": base64.b64encode(b"".join(out)).decode()})
    assert body["code"] == 0, body.get("msg")
    sessions = body["data"]["sessions"]
    assert len(sessions) == 2
    tls12 = next(s for s in sessions if s["protocol"] == "TLS 1.2")
    assert [c["subject"] for c in tls12["serverCertList"]] == [
        EXP["tls"]["serverSubject"], "CN=CipherBox Test Root CA,O=CipherBox Test,C=CN"]
    assert any("未捕获 ClientHello" in n for n in tls12["notes"])
