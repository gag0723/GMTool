"""非对称算法模块测试：SM2 / RSA / ECDSA / 附件 / 点压缩。

包含两类用例：
1. 本地向量与往返（标准向量、openssl / gmssl 互操作、篡改检测）
2. 与原站 https://cipher.huijusa.cn 的在线交叉验证（相同输入比对结果；
   随机输出用「原站加密→本地解密」「本地签名→原站验签」双向验证）

运行：
    cd /opt/cipherbox && .venv/bin/python -m pytest tests/test_asym.py -q
"""
from __future__ import annotations

import datetime
import json
import os
import time

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as _crsa
from cryptography.x509.oid import NameOID

from app.core import asym as A
from app.server import app

REMOTE_BASE = os.environ.get("CB_REMOTE_API", "https://cipher.huijusa.cn/api")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 Safari/537.36",
    "Content-Type": "application/json",
    "Origin": "https://cipher.huijusa.cn",
    "Referer": "https://cipher.huijusa.cn/",
}
UID_HEX = "31323334353637383132333435363738"  # "1234567812345678"
UID = b"1234567812345678"


# ---------------------------------------------------------------------------
# 夹具与工具
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(scope="module")
def remote():
    return Remote()


class RemoteUnavailable(Exception):
    pass


class Remote:
    """原站接口客户端：带重试（原站偶发 502），不可用时整体跳过。"""

    def __init__(self):
        self.calls = 0
        self.down = False

    def call(self, path, payload):
        if self.down:
            pytest.skip("原站不可用，跳过交叉验证")
        last = None
        for _ in range(4):
            try:
                resp = requests.post(REMOTE_BASE + path, json=payload, headers=HEADERS, timeout=20)
                self.calls += 1
                if resp.status_code >= 500 and "openresty" in resp.text:
                    last = RuntimeError("HTTP %s" % resp.status_code)
                    time.sleep(1.5)
                    continue
                return resp.json()
            except Exception as exc:  # 网络/JSON 异常
                last = exc
                time.sleep(1.5)
        self.down = True
        pytest.skip("原站不可用（%s），跳过交叉验证" % last)

    def ok(self, path, payload):
        data = self.call(path, payload)
        assert data.get("code") == 0, "原站返回失败 %s: %s" % (path, json.dumps(data, ensure_ascii=False))
        return data["data"]


def local(client, path, payload):
    resp = client.post("/api/asym" + path, json=payload)
    return resp.get_json()


def local_ok(client, path, payload):
    data = local(client, path, payload)
    assert data.get("code") == 0, "本地失败 %s: %s" % (path, json.dumps(data, ensure_ascii=False))
    return data["data"]


def cmp(remote_value, local_value, label, payload=None):
    if remote_value != local_value:
        raise AssertionError(
            "%s 不一致\n  输入: %s\n  原站: %s\n  本地: %s"
            % (label, json.dumps(payload, ensure_ascii=False), remote_value, local_value)
        )


def strip0(text: str) -> str:
    value = (text or "").upper()
    return value.lstrip("0") or "0"


def norm_point(hexstr: str, size: int) -> str:
    """把原站的裸公钥（可能带 BigInteger 符号 0 字节）规范成 04||X||Y。"""
    raw = bytes.fromhex(hexstr)
    if len(raw) == 2 * size:
        return raw.hex().upper()
    if len(raw) == 2 * size + 1 and raw[0] == 0:
        return raw[1:].hex().upper()
    if len(raw) == 2 * size + 2 and raw[0] == 0 and raw[size + 1] == 0:
        return raw[1:size + 1].hex().upper() + raw[size + 2:].hex().upper()
    raise AssertionError("无法解析原站公钥长度 %d（期望 %d）: %s" % (len(raw), 2 * size, hexstr))


# ---------------------------------------------------------------------------
# 标准 / 互操作向量
# ---------------------------------------------------------------------------

# GB/T 32918.2 示例密钥（d 与 P 均已校验 P = dG 且在曲线上）
SM2_D = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
SM2_PX = 0x09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020
SM2_PY = 0xCCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13
SM2_K = 0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
SM2_E = "F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640"
SM2_R = 0xF5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3
SM2_S = 0xB1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA

# openssl 3.5 用 SM2 私钥 + SM3 + distid=1234567812345678 生成的真实签名（外部实现交叉验证）
OPENSSL_SM2_D = "7BE4427C19BB38E62B01B3C4FE30926EAF37AE21461F148E65AFA8F6813F458B"
OPENSSL_SM2_PUB = (
    "C81F0D1A205EE11E23DF42EBB51B47642178330792328413FA62F1FC5ABC46BC"
    "CE5516684D2012B75F24D14C420C5D0D4FB52D7F34E38C6FBB90A60639E6E22B"
)
OPENSSL_SM2_MSG = b"message digest"
OPENSSL_SM2_SIG = (
    "30450221008337DADDA69D1BD19458EE05F89505088784BD1E28C1FFFC6783CEAD03666FC9"
    "02205545CC6EBF13FDA36AA1F40E4841D8E092E8EC90957CC7F995C915F6932C9CF6"
)

# 原站 /sm2/calculate/evalue 的真实输出（固定密钥，用于 Z/e 值已知答案测试）
EVAL_PUB = (
    "8B7BB0DB391CC418264B0B12FBF7EF48294546504EA2D02AB5D4F89A3D40AEAC"
    "91FE220CB94E5AE9FEB887B7D48F272A0DF1F41DF4BDD47D96C2B55D57DA951F"
)
EVAL_Z = "14777C717759AD7027317D4F730EFDC3C61346BEC9075673F0BCB6CB8128F94A"
EVAL_E = "B615DF8CAFDF4E9A7D3F1D2BF55CECFAE48BAF3A803D295D3E57948B258D7870"

# SM9 曲线（GM/T 0044）G1 生成元
SM9_G1 = (
    "04"
    "93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD"
    "21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616"
)


# ---------------------------------------------------------------------------
# SM2 本地
# ---------------------------------------------------------------------------


def test_sm2_curve_and_standard_vector():
    pub = (SM2_PX, SM2_PY)
    assert A.on_curve(A.SM2_CURVE, pub)
    assert A.point_mul(A.SM2_CURVE, SM2_D, A.SM2_CURVE.g) == pub
    z, e = A.sm2_e(pub, b"message digest", UID)
    assert len(z) == 32 and len(e) == 32
    assert e.hex().upper() == SM2_E
    r, s = A.sm2_sign_digest(SM2_D, e, k=SM2_K)
    assert r == SM2_R, "r 与 GB/T 32918 示例不一致"
    assert s == SM2_S, "s 与 GB/T 32918 示例不一致"
    assert A.sm2_verify_digest(pub, e, r, s) is True
    assert A.sm2_verify_digest(pub, e, r, (s + 1) % A.SM2_CURVE.n) is False


def test_sm2_openssl_signature_interop():
    """openssl 生成的 SM2/SM3 签名必须能通过本地验签。"""
    pub = A.parse_sm2_public(OPENSSL_SM2_PUB, "HEX")
    _z, e = A.sm2_e(pub, OPENSSL_SM2_MSG, UID)
    sig = bytes.fromhex(OPENSSL_SM2_SIG)
    r, s = A.der_to_rs(sig)
    assert A.sm2_verify_digest(pub, e, r, s) is True
    wrong = A.sm2_e(pub, b"message digesT", UID)[1]
    assert A.sm2_verify_digest(pub, wrong, r, s) is False
    # 本地签名 → DER/R||S 互转 → 仍可验签
    r2, s2 = A.sm2_sign_digest(A.parse_sm2_private(OPENSSL_SM2_D, "HEX"), e)
    der = A.rs_to_der(r2, s2)
    assert A.der_to_rs(der) == (r2, s2)
    assert A.sm2_verify_digest(pub, e, *A.parse_signature(der)) is True


def test_sm2_evalue_known_answer(client):
    data = local_ok(client, "/sm2/calculate/evalue", {
        "publicKey": EVAL_PUB, "publicKeyFormat": "HEX",
        "message": "abc", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "resultFormat": "HEX", "zzFormat": "HEX",
    })
    assert data["zHash"] == EVAL_Z
    assert data["eHash"] == EVAL_E
    assert data["userId"] == UID_HEX
    assert data["entl"] == "0080"


def test_sm2_encrypt_decrypt_roundtrip(client):
    kp = local_ok(client, "/sm2/keypair", {"publicKeyFormat": "HEX", "privateKeyFormat": "HEX"})
    pub, d = kp["publicKey"], kp["privateKey"]
    assert len(pub) == 128 and len(d) == 64
    for mode in ("C1C3C2", "C1C2C3"):
        cipher = local_ok(client, "/sm2/encrypt", {
            "message": "中文测试 abc", "messageFormat": "TEXT",
            "publicKey": pub, "publicKeyFormat": "HEX",
            "encryptMode": mode, "cipherFormat": "HEX",
        })
        assert len(bytes.fromhex(cipher)) == 64 + 32 + len("中文测试 abc".encode())
        plain = local_ok(client, "/sm2/decrypt", {
            "cipher": cipher, "cipherFormat": "HEX",
            "privateKey": d, "privateKeyFormat": "HEX",
            "encryptMode": mode, "messageFormat": "TEXT",
        })
        assert plain == "中文测试 abc"
    # 密文次序错配必须失败
    cipher = local_ok(client, "/sm2/encrypt", {
        "message": "abc", "messageFormat": "TEXT", "publicKey": pub,
        "publicKeyFormat": "HEX", "encryptMode": "C1C3C2", "cipherFormat": "HEX",
    })
    bad = local(client, "/sm2/decrypt", {
        "cipher": cipher, "cipherFormat": "HEX", "privateKey": d,
        "privateKeyFormat": "HEX", "encryptMode": "C1C2C3", "messageFormat": "TEXT",
    })
    assert bad["code"] == 1 and "失败" in bad["msg"]


def test_sm2_gmssl_interop():
    """与 gmssl 实现双向互操作（C1C3C2）。

    gmssl 3.2.2 在坐标存在前导零时（约 2% 的密钥）会生成自相矛盾的密文，
    因此先挑一对 gmssl 自己能往返的密钥，再做双向互操作。
    """
    from gmssl import sm2 as gsm2

    message = b"gmssl interop 123"
    gm = None
    d = pub = None
    for _ in range(40):
        d, pub = A.sm2_keypair()
        candidate = gsm2.CryptSM2(private_key=format(d, "064X"),
                                  public_key=A.encode_point(pub).hex(), mode=1)
        try:
            probe = candidate.encrypt(message)
            if probe and candidate.decrypt(probe) == message:
                gm = candidate
                break
        except Exception:
            continue
    assert gm is not None, "gmssl 无法自洽（未找到可用密钥）"
    # 本地加密（去掉 04 前缀）→ gmssl 解密
    cipher = A.sm2_encrypt(pub, message, "C1C3C2")
    assert gm.decrypt(cipher[1:]) == message
    # gmssl 加密（C1 无 04 前缀）→ 本地解密
    raw = gm.encrypt(message)
    assert A.sm2_decrypt(d, raw, "C1C3C2") == message


def test_sm2_keypair_pubkey_and_validation(client):
    kp = local_ok(client, "/sm2/keypair", {})
    pub, d = kp["publicKey"], kp["privateKey"]
    calc = local_ok(client, "/sm2/pubkey/calculate", {
        "privateKey": d, "privateKeyFormat": "HEX", "publicKeyFormat": "HEX",
    })
    assert calc == pub
    ok = local_ok(client, "/sm2/publickey/verify", {"publicKey": pub, "publicKeyFormat": "HEX"})
    assert ok["onCurve"] is True
    bad = local(client, "/sm2/publickey/verify", {"publicKey": "00" * 64, "publicKeyFormat": "HEX"})
    assert bad["code"] == 1 and "曲线" in bad["msg"]
    # 04 前缀与压缩点都能解析
    assert A.parse_sm2_public("04" + pub, "HEX") == A.parse_sm2_public(pub, "HEX")
    compressed = A.compress_point(A.SM2_CURVE, bytes.fromhex("04" + pub))
    assert A.parse_sm2_public(compressed.hex(), "HEX") == A.parse_sm2_public(pub, "HEX")


def test_sm2_sign_verify_and_convert(client):
    kp = local_ok(client, "/sm2/keypair", {})
    pub, d = kp["publicKey"], kp["privateKey"]
    payload = {
        "privateKey": d, "privateKeyFormat": "HEX", "hashMode": "noHash",
        "message": "abc", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX", "signatureFormat": "HEX",
    }
    sig = local_ok(client, "/sm2/sign", payload)
    assert len(sig["signature"]) == 128
    assert sig["publicKey"] == pub
    verified = local_ok(client, "/sm2/verify", {
        "publicKey": pub, "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "noHash", "message": "abc", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": sig["signature"], "signatureFormat": "HEX",
    })
    assert verified["valid"] is True
    failed = local(client, "/sm2/verify", {
        "publicKey": pub, "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "noHash", "message": "abd", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": sig["signature"], "signatureFormat": "HEX",
    })
    assert failed["code"] == 1 and failed["msg"] == "验签失败"
    # DER 互转
    der = local_ok(client, "/sm2/signature/convert", {
        "signature": sig["signature"], "signatureFormat": "HEX", "targetFormat": "DER",
    })
    raw = local_ok(client, "/sm2/signature/convert", {
        "signature": der, "signatureFormat": "HEX", "targetFormat": "RAW",
    })
    assert raw == sig["signature"]
    # DER 签名同样可验签
    assert local_ok(client, "/sm2/verify", {
        "publicKey": pub, "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "noHash", "message": "abc", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": der, "signatureFormat": "HEX",
    })["valid"] is True
    # 基于 e 值
    e_hash = local_ok(client, "/sm2/calculate/evalue", {
        "publicKey": pub, "publicKeyFormat": "HEX", "message": "abc",
        "messageFormat": "TEXT", "userId": UID_HEX, "userIdFormat": "HEX",
    })["eHash"]
    sig_e = local_ok(client, "/sm2/sign", {
        "privateKey": d, "privateKeyFormat": "HEX", "hashMode": "withHash",
        "hash": e_hash, "hashFormat": "HEX", "signatureFormat": "HEX",
        "message": "abc", "messageFormat": "TEXT",
    })
    assert local_ok(client, "/sm2/verify", {
        "publicKey": pub, "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "withHash", "hash": e_hash, "hashFormat": "HEX",
        "signature": sig_e["signature"], "signatureFormat": "HEX",
    })["valid"] is True


def test_sm2_k_reuse_attack(client):
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    pub = A.point_mul(A.SM2_CURVE, d, A.SM2_CURVE.g)
    k = 0x99887766554433221100FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA
    sigs = []
    for msg in (b"first message", b"second message"):
        _z, e = A.sm2_e(pub, msg, UID)
        r, s = A.sm2_sign_digest(d, e, k=k)
        sigs.append("%064X%064X" % (r, s))
    data = local_ok(client, "/sm2/verifyAndAttack", {
        "publicKey": A.encode_point(pub)[1:].hex().upper(), "publicKeyFormat": "HEX",
        "publicType": "PUB", "hashMode": "noHash",
        "message": "first message", "messageFormat": "TEXT",
        "messageTwo": "second message", "messageTwoFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": sigs[0], "signatureFormat": "HEX",
        "signatureTwo": sigs[1], "signatureTwoFormat": "HEX",
    })
    assert data["privateKeyHex"] == "%064X" % d
    # 不同 k 的两条签名必须明确报错
    other = []
    for msg in (b"first message", b"second message"):
        _z, e = A.sm2_e(pub, msg, UID)
        r, s = A.sm2_sign_digest(d, e)
        other.append("%064X%064X" % (r, s))
    bad = local(client, "/sm2/verifyAndAttack", {
        "publicKey": A.encode_point(pub)[1:].hex().upper(), "publicKeyFormat": "HEX",
        "publicType": "PUB", "hashMode": "noHash",
        "message": "first message", "messageFormat": "TEXT",
        "messageTwo": "second message", "messageTwoFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": other[0], "signatureFormat": "HEX",
        "signatureTwo": other[1], "signatureTwoFormat": "HEX",
    })
    assert bad["code"] == 1
    assert "随机数" in bad["msg"] or "反推" in bad["msg"]


def test_sm2_pem_roundtrip(client):
    kp = local_ok(client, "/sm2/keypair", {})
    parsed = local_ok(client, "/sm2/private/pem/parse", {
        "privateKeyPem": kp["privateKeyPem"], "publicKeyFormat": "HEX", "privateKeyFormat": "HEX",
    })
    assert parsed["privateKey"] == kp["privateKey"]
    assert parsed["publicKey"] == kp["publicKey"]
    # PEM 公钥可直接用于加密
    cipher = local_ok(client, "/sm2/encrypt", {
        "message": "pem", "messageFormat": "TEXT",
        "publicKey": kp["publicKeyPem"], "publicKeyFormat": "PEM", "cipherFormat": "HEX",
    })
    assert local_ok(client, "/sm2/decrypt", {
        "cipher": cipher, "cipherFormat": "HEX", "privateKey": kp["privateKeyPem"],
        "privateKeyFormat": "PEM", "messageFormat": "TEXT",
    }) == "pem"


def test_sm2_cipher_convert(client):
    kp = local_ok(client, "/sm2/keypair", {})
    for mode in ("C1C3C2", "C1C2C3"):
        cipher = local_ok(client, "/sm2/encrypt", {
            "message": "convert", "messageFormat": "TEXT", "publicKey": kp["publicKey"],
            "publicKeyFormat": "HEX", "encryptMode": mode, "cipherFormat": "HEX",
        })
        der = local_ok(client, "/sm2/cipher/convert", {
            "cipher": cipher, "cipherFormat": "HEX", "targetFormat": "DER", "encryptMode": mode,
        })
        back = local_ok(client, "/sm2/cipher/convert", {
            "cipher": der, "cipherFormat": "HEX", "targetFormat": "RAW", "encryptMode": mode,
        })
        assert back == cipher
        # DER 密文也能直接解密
        assert local_ok(client, "/sm2/decrypt", {
            "cipher": der, "cipherFormat": "HEX", "privateKey": kp["privateKey"],
            "privateKeyFormat": "HEX", "encryptMode": mode, "messageFormat": "TEXT",
        }) == "convert"


# ---------------------------------------------------------------------------
# RSA 本地
# ---------------------------------------------------------------------------


def test_rsa_keypair_roundtrip(client):
    kp = local_ok(client, "/rsa/keypair", {"keySize": 1024})
    pub, priv = kp["publicKey"], kp["privateKey"]
    assert kp["bits"] == 1024 and kp["e"] == 65537
    calc = local_ok(client, "/rsa/pubkey/calculate", {
        "privateKey": priv, "privateKeyFormat": "HEX", "publicKeyFormat": "HEX",
    })
    assert calc == pub
    for fill in ("RSA/ECB/PKCS1Padding", "RSA/ECB/NoPadding", "RSA/ECB/OAEPPadding"):
        cipher = local_ok(client, "/rsa/encrypt", {
            "message": "abc", "messageFormat": "TEXT", "publicKey": pub,
            "publicKeyFormat": "HEX", "fillMethod": fill, "cipherFormat": "HEX",
        })
        assert len(bytes.fromhex(cipher)) == 128
        plain = local_ok(client, "/rsa/decrypt", {
            "cipher": cipher, "cipherFormat": "HEX", "privateKey": priv,
            "privateKeyFormat": "HEX", "fillMethod": fill, "messageFormat": "TEXT",
        })
        assert plain == "abc"


def test_rsa_sign_verify_hashes(client):
    kp = local_ok(client, "/rsa/keypair", {"keySize": 1024})
    pub, priv = kp["publicKey"], kp["privateKey"]
    for algo in ("SHA1withRSA", "SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"):
        sig = local_ok(client, "/rsa/sign", {
            "message": "abc", "messageFormat": "TEXT", "privateKey": priv,
            "privateKeyFormat": "HEX", "signHash": algo, "signatureFormat": "HEX",
        })
        assert local_ok(client, "/rsa/verify", {
            "message": "abc", "messageFormat": "TEXT", "publicKey": pub,
            "publicKeyFormat": "HEX", "signHash": algo, "signature": sig,
            "signatureFormat": "HEX",
        })["valid"] is True
        bad = local(client, "/rsa/verify", {
            "message": "abd", "messageFormat": "TEXT", "publicKey": pub,
            "publicKeyFormat": "HEX", "signHash": algo, "signature": sig,
            "signatureFormat": "HEX",
        })
        assert bad["code"] == 1 and bad["msg"] == "验签失败"
    unsupported = local(client, "/rsa/sign", {
        "message": "abc", "privateKey": priv, "privateKeyFormat": "HEX",
        "signHash": "SHA256withRSASSA-PSS",
    })
    assert unsupported["code"] == 1 and "PSS" in unsupported["msg"]


def test_rsa_pem_and_cert_extract(client):
    kp = local_ok(client, "/rsa/keypair", {
        "keySize": 1024, "publicKeyFormat": "PEM", "privateKeyFormat": "PEM"})
    assert "BEGIN PUBLIC KEY" in kp["publicKey"]
    assert "BEGIN PRIVATE KEY" in kp["privateKey"]
    sign = local_ok(client, "/rsa/sign", {
        "message": "pem", "messageFormat": "TEXT", "privateKey": kp["privateKey"],
        "privateKeyFormat": "PEM", "signHash": "SHA256withRSA", "signatureFormat": "HEX",
    })
    assert local_ok(client, "/rsa/verify", {
        "message": "pem", "messageFormat": "TEXT", "publicKey": kp["publicKey"],
        "publicKeyFormat": "PEM", "signHash": "SHA256withRSA", "signature": sign,
        "signatureFormat": "HEX",
    })["valid"] is True
    cert_pem = make_rsa_cert()
    extracted = local_ok(client, "/rsa/extract/publicKey", {
        "cert": cert_pem, "certFormat": "TEXT", "publicKeyFormat": "HEX",
    })
    expected = RSA_TEST_KEY.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ).hex().upper()
    assert extracted == expected, "从证书提取的 RSA 公钥与证书实际公钥不一致"
    # 非 RSA 证书必须给出明确提示
    bad = local(client, "/rsa/extract/publicKey", {
        "cert": SM2_CERT_PEM, "certFormat": "TEXT", "publicKeyFormat": "HEX",
    })
    assert bad["code"] == 1 and "RSA" in bad["msg"]


def make_rsa_cert():
    key = RSA_TEST_KEY
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cipherbox rsa test")])
    now = datetime.datetime(2026, 1, 1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1001)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


RSA_TEST_KEY = _crsa.generate_private_key(public_exponent=65537, key_size=2048)


# ---------------------------------------------------------------------------
# ECDSA 本地
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "secp521r1", "secp256k1", "SM2"])
def test_ecdsa_sign_verify(client, curve):
    kp = local_ok(client, "/ecdsa/keypair", {"curveType": curve})
    pub, priv = kp["publicKey"], kp["privateKey"]
    for algo in ("SHA1", "SHA256", "SHA512"):
        sig = local_ok(client, "/ecdsa/sign", {
            "message": "abc", "messageFormat": "TEXT", "privateKey": priv,
            "privateKeyFormat": "HEX", "signHash": algo, "signatureFormat": "HEX",
            "curveType": curve,
        })
        assert sig.startswith("30"), "签名应为 DER 编码"
        assert local_ok(client, "/ecdsa/verify", {
            "message": "abc", "messageFormat": "TEXT", "publicKey": pub,
            "publicKeyFormat": "HEX", "signHash": algo, "signature": sig,
            "signatureFormat": "HEX", "curveType": curve,
        })["valid"] is True
        bad = local(client, "/ecdsa/verify", {
            "message": "abc!", "messageFormat": "TEXT", "publicKey": pub,
            "publicKeyFormat": "HEX", "signHash": algo, "signature": sig,
            "signatureFormat": "HEX", "curveType": curve,
        })
        assert bad["code"] == 1


def test_ecdsa_encrypt_only_sm2(client):
    for curve in ("secp256r1", "secp384r1", "secp521r1", "secp256k1"):
        kp = local_ok(client, "/ecdsa/keypair", {"curveType": curve})
        bad = local(client, "/ecdsa/encrypt", {
            "message": "abc", "messageFormat": "TEXT", "publicKey": kp["publicKey"],
            "publicKeyFormat": "HEX", "curveType": curve, "cipherFormat": "HEX",
        })
        assert bad["code"] == 1 and "SM2" in bad["msg"]
    kp = local_ok(client, "/ecdsa/keypair", {"curveType": "SM2"})
    cipher = local_ok(client, "/ecdsa/encrypt", {
        "message": "sm2 ecies", "messageFormat": "TEXT", "publicKey": kp["publicKey"],
        "publicKeyFormat": "HEX", "curveType": "SM2", "cipherFormat": "HEX",
    })
    assert local_ok(client, "/ecdsa/decrypt", {
        "cipher": cipher, "cipherFormat": "HEX", "privateKey": kp["privateKey"],
        "privateKeyFormat": "HEX", "messageFormat": "TEXT", "curveType": "SM2",
    }) == "sm2 ecies"


# ---------------------------------------------------------------------------
# Attach & Detach 本地
# ---------------------------------------------------------------------------


def test_attach_build_parse_sign_verify(client):
    kp = local_ok(client, "/sm2/keypair", {})
    built = local_ok(client, "/attach/attach", {
        "publicKey": kp["publicKey"], "publicKeyFormat": "HEX",
        "userId": UID_HEX, "userIdFormat": "HEX",
    })
    attachment = built["attachment"]
    assert attachment.upper().startswith("04")
    assert built["size"] == 65 + 16
    parsed = local_ok(client, "/attach/detach", {
        "attachData": attachment, "attachFormat": "HEX",
        "publicKeyFormat": "HEX", "userIdFormat": "HEX",
    })
    assert parsed["publicKey"] == kp["publicKey"].upper()
    assert parsed["userId"] == UID_HEX
    assert parsed["userIdText"] == "1234567812345678"

    signed = local_ok(client, "/attach/sign", {
        "privateKey": kp["privateKey"], "privateKeyFormat": "HEX",
        "message": "attach message", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX", "signatureFormat": "HEX",
    })
    assert len(signed["signature"]) == 128
    assert len(bytes.fromhex(signed["package"])) == 65 + 16 + 64
    assert local_ok(client, "/attach/verify", {
        "package": signed["package"], "signatureFormat": "HEX",
        "message": "attach message", "messageFormat": "TEXT",
    })["valid"] is True
    assert local_ok(client, "/attach/verify", {
        "publicKey": kp["publicKey"], "publicKeyFormat": "HEX",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": signed["signature"], "signatureFormat": "HEX",
        "message": "attach message", "messageFormat": "TEXT",
    })["valid"] is True
    tampered = local(client, "/attach/verify", {
        "package": signed["package"], "signatureFormat": "HEX",
        "message": "attach messagf", "messageFormat": "TEXT",
    })
    assert tampered["code"] == 1
    # 用户标识与签名不匹配时必须失败（换一对密钥的附件包）
    other = local_ok(client, "/sm2/keypair", {})
    other_pkg = local_ok(client, "/attach/sign", {
        "privateKey": other["privateKey"], "privateKeyFormat": "HEX",
        "message": "attach message", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
    })["package"]
    assert local(client, "/attach/verify", {
        "publicKey": kp["publicKey"], "publicKeyFormat": "HEX",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": other_pkg[-128:], "signatureFormat": "HEX",
        "message": "attach message", "messageFormat": "TEXT",
    })["code"] == 1


# ---------------------------------------------------------------------------
# 点压缩 / 解压 本地
# ---------------------------------------------------------------------------


def test_compress_sm2(client):
    kp = local_ok(client, "/sm2/keypair", {})
    full = "04" + kp["publicKey"]
    compressed = local_ok(client, "/compress/parse", {
        "type": "SM2", "compressType": "compress", "decompressPubkey": full,
    })
    assert len(bytes.fromhex(compressed)) == 33
    assert compressed[:2] in ("02", "03")
    restored = local_ok(client, "/compress/parse", {
        "type": "SM2", "compressType": "decompress", "compressPubkey": compressed,
    })
    assert restored == kp["publicKey"]  # 原站约定：解压输出不带 04 前缀
    assert A.encode_point(A.parse_sm2_public(restored, "HEX")).hex().upper() == full
    # 不带 04 前缀也能压缩
    assert local_ok(client, "/compress/parse", {
        "type": "SM2", "compressType": "compress", "decompressPubkey": kp["publicKey"],
    }) == compressed
    # 非法输入
    bad = local(client, "/compress/parse", {
        "type": "SM2", "compressType": "decompress", "compressPubkey": "02" + "FF" * 32,
    })
    assert bad["code"] == 1
    bad2 = local(client, "/compress/parse", {
        "type": "SM2", "compressType": "compress", "decompressPubkey": "04" + "00" * 64,
    })
    assert bad2["code"] == 1 and "曲线" in bad2["msg"]


def test_compress_sm9(client):
    compressed = local_ok(client, "/compress/parse", {
        "type": "SM9", "compressType": "compress", "decompressPubkey": SM9_G1,
    })
    assert len(bytes.fromhex(compressed)) == 33
    assert compressed.upper() == "02" + SM9_G1[2:66].upper()
    restored = local_ok(client, "/compress/parse", {
        "type": "SM9", "compressType": "decompress", "compressPubkey": compressed,
    })
    assert restored == SM9_G1[2:]  # 原站约定：解压输出不带 04 前缀
    assert A.on_curve(A.SM9_CURVE, A.decompress_point(A.SM9_CURVE, bytes.fromhex(compressed)))
    # SM9 曲线上不属于该曲线的点必须报错（SM2 生成元不在 SM9 曲线上）
    bad = local(client, "/compress/parse", {
        "type": "SM9", "compressType": "compress",
        "decompressPubkey": "04" + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
                                 "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
    })
    assert bad["code"] == 1


# ---------------------------------------------------------------------------
# 与原站交叉验证：SM2
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def x_sm2(remote):
    """原站生成一对 SM2 密钥，供后续交叉验证复用。"""
    kp = remote.ok("/sm2/keypair", {"publicKeyFormat": "HEX", "privateKeyFormat": "HEX"})
    return {"pub": kp["publicKey"], "priv": kp["privateKey"]}


def test_x_sm2_pubkey_and_evalue(client, remote, x_sm2):
    payload = {"privateKey": x_sm2["priv"], "privateKeyFormat": "HEX", "publicKeyFormat": "HEX"}
    remote_pub = remote.ok("/sm2/pubkey/calculate", payload)
    local_pub = local_ok(client, "/sm2/pubkey/calculate", payload)
    cmp(remote_pub, local_pub, "SM2 公钥计算", payload)
    cmp(remote_pub, x_sm2["pub"], "原站公钥计算自洽", payload)

    # 公钥合法性
    assert remote.call("/sm2/publickey/verify", {"publicKey": x_sm2["pub"], "publicKeyFormat": "HEX"})["code"] == 0
    assert local_ok(client, "/sm2/publickey/verify", {"publicKey": x_sm2["pub"], "publicKeyFormat": "HEX"})["onCurve"]
    bad_pub = {"publicKey": "00" * 64, "publicKeyFormat": "HEX"}
    assert remote.call("/sm2/publickey/verify", bad_pub)["code"] != 0
    assert local(client, "/sm2/publickey/verify", bad_pub)["code"] != 0

    for message, msg_fmt, uid, uid_fmt in (
        ("abc", "TEXT", UID_HEX, "HEX"),
        ("中文消息测试", "TEXT", UID_HEX, "HEX"),
        ("1234567812345678", "TEXT", "1234567812345678", "TEXT"),
        ("00FF10", "HEX", UID_HEX, "HEX"),
    ):
        payload = {
            "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX",
            "message": message, "messageFormat": msg_fmt,
            "userId": uid, "userIdFormat": uid_fmt,
            "resultFormat": "HEX", "zzFormat": "HEX",
        }
        remote_e = remote.ok("/sm2/calculate/evalue", payload)
        local_e = local_ok(client, "/sm2/calculate/evalue", payload)
        cmp(remote_e["zHash"], local_e["zHash"], "SM2 Z 值", payload)
        cmp(remote_e["eHash"], local_e["eHash"], "SM2 e 值", payload)


def test_x_sm2_encrypt_decrypt(client, remote, x_sm2):
    for mode in ("C1C3C2", "C1C2C3"):
        payload = {
            "message": "交叉验证 abc", "messageFormat": "TEXT",
            "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX",
            "encryptMode": mode, "cipherFormat": "HEX",
        }
        # 原站加密 → 本地解密
        remote_cipher = remote.ok("/sm2/encrypt", payload)
        plain = local_ok(client, "/sm2/decrypt", {
            "cipher": remote_cipher, "cipherFormat": "HEX",
            "privateKey": x_sm2["priv"], "privateKeyFormat": "HEX",
            "encryptMode": mode, "messageFormat": "TEXT",
        })
        cmp("交叉验证 abc", plain, "原站加密→本地解密(%s)" % mode, payload)
        # 本地加密 → 原站解密
        local_cipher = local_ok(client, "/sm2/encrypt", payload)
        remote_plain = remote.ok("/sm2/decrypt", {
            "cipher": local_cipher, "cipherFormat": "HEX",
            "privateKey": x_sm2["priv"], "privateKeyFormat": "HEX",
            "encryptMode": mode, "messageFormat": "TEXT",
        })
        cmp("交叉验证 abc", remote_plain, "本地加密→原站解密(%s)" % mode, payload)
        # 密文长度一致（C1 不带 04 前缀，64+32+len）
        cmp(len(remote_cipher), len(local_cipher), "SM2 密文长度(%s)" % mode, payload)
        # DER 转换结果逐字节一致
        for source, label in ((remote_cipher, "原站密文"), (local_cipher, "本地密文")):
            conv = {"cipher": source, "cipherFormat": "HEX", "targetFormat": "DER", "encryptMode": mode}
            cmp(remote.ok("/sm2/cipher/convert", conv),
                local_ok(client, "/sm2/cipher/convert", conv),
                "SM2 密文转 DER(%s)" % label, conv)
            conv_back = {"cipher": local_ok(client, "/sm2/cipher/convert", conv),
                         "cipherFormat": "HEX", "targetFormat": "RAW", "encryptMode": mode}
            cmp(remote.ok("/sm2/cipher/convert", conv_back),
                local_ok(client, "/sm2/cipher/convert", conv_back),
                "SM2 DER 转裸密文(%s)" % label, conv_back)


def test_x_sm2_sign_verify(client, remote, x_sm2):
    payload = {
        "privateKey": x_sm2["priv"], "privateKeyFormat": "HEX",
        "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX",
        "hashMode": "noHash", "message": "交叉验证签名", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX", "signatureFormat": "HEX",
    }
    # 原站签名 → 本地验签
    remote_sig = remote.ok("/sm2/sign", payload)["signature"]
    assert local_ok(client, "/sm2/verify", {
        "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "noHash", "message": "交叉验证签名", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": remote_sig, "signatureFormat": "HEX",
    })["valid"] is True
    # 本地签名 → 原站验签
    local_sig = local_ok(client, "/sm2/sign", payload)["signature"]
    assert remote.call("/sm2/verify", {
        "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "noHash", "message": "交叉验证签名", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": local_sig, "signatureFormat": "HEX",
    })["code"] == 0
    # 签名格式互转逐字节一致
    for source in (remote_sig, local_sig):
        conv = {"signature": source, "signatureFormat": "HEX", "targetFormat": "DER"}
        cmp(remote.ok("/sm2/signature/convert", conv),
            local_ok(client, "/sm2/signature/convert", conv), "SM2 签名转 DER", conv)
        der = local_ok(client, "/sm2/signature/convert", conv)
        back = {"signature": der, "signatureFormat": "HEX", "targetFormat": "RAW"}
        cmp(remote.ok("/sm2/signature/convert", back),
            local_ok(client, "/sm2/signature/convert", back), "SM2 DER 转 R||S", back)
        cmp(source, local_ok(client, "/sm2/signature/convert", back), "SM2 签名往返", back)
    # 基于 e 值签名 → 互相验签
    e_hash = remote.ok("/sm2/calculate/evalue", {
        "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX", "message": "交叉验证签名",
        "messageFormat": "TEXT", "userId": UID_HEX, "userIdFormat": "HEX",
        "resultFormat": "HEX", "zzFormat": "HEX",
    })["eHash"]
    local_e_sig = local_ok(client, "/sm2/sign", {
        "privateKey": x_sm2["priv"], "privateKeyFormat": "HEX", "hashMode": "withHash",
        "hash": e_hash, "hashFormat": "HEX", "signatureFormat": "HEX",
        "message": "交叉验证签名", "messageFormat": "TEXT",
    })["signature"]
    # 原站在 withHash 模式下仍要求 message/userId 字段存在（否则内部 NPE）
    result = remote.call("/sm2/verify", {
        "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "withHash", "hash": e_hash, "hashFormat": "HEX",
        "message": "交叉验证签名", "messageFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": local_e_sig, "signatureFormat": "HEX",
    })
    assert result["code"] == 0, "原站无法验证本地 withHash 签名: %s" % json.dumps(
        result, ensure_ascii=False)


def test_x_sm2_attack(client, remote, x_sm2):
    """本地构造同 k 的两条签名 → 原站攻击结果应与本地一致。"""
    d = int(x_sm2["priv"], 16)
    pub = A.parse_sm2_public(x_sm2["pub"], "HEX")
    k = 0x99887766554433221100FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA
    sigs = []
    for msg in ("attack one", "attack two"):
        _z, e = A.sm2_e(pub, msg.encode(), UID)
        r, s = A.sm2_sign_digest(d, e, k=k)
        sigs.append("%064X%064X" % (r, s))
    payload = {
        "publicKey": x_sm2["pub"], "publicKeyFormat": "HEX", "publicType": "PUB",
        "hashMode": "noHash",
        "message": "attack one", "messageFormat": "TEXT",
        "messageTwo": "attack two", "messageTwoFormat": "TEXT",
        "userId": UID_HEX, "userIdFormat": "HEX",
        "signature": sigs[0], "signatureFormat": "HEX",
        "signatureTwo": sigs[1], "signatureTwoFormat": "HEX",
    }
    remote_result = remote.call("/sm2/verifyAndAttack", payload)
    # 原站在攻击成功时用 code=500 承载消息，这里只取其中的私钥文本比对
    remote_msg = remote_result.get("msg") or ""
    assert x_sm2["priv"].upper() in remote_msg.upper(), (
        "原站未反推出预期私钥\n  返回: %s" % json.dumps(remote_result, ensure_ascii=False)
    )
    local_data = local_ok(client, "/sm2/verifyAndAttack", payload)
    cmp(x_sm2["priv"].upper(), local_data["privateKey"], "SM2 同 k 攻击私钥", payload)


def test_x_sm2_pem_and_cert(client, remote, x_sm2):
    kp = local_ok(client, "/sm2/keypair", {})
    # 本地导出的 PKCS#8 PEM → 原站解析
    remote_parsed = remote.ok("/sm2/private/pem/parse", {
        "privateKeyPem": kp["privateKeyPem"], "publicKeyFormat": "HEX", "privateKeyFormat": "HEX",
    })
    cmp(kp["privateKey"], remote_parsed["privateKey"].upper(), "SM2 PEM 私钥解析", {"pem": "local"})
    cmp(kp["publicKey"], remote_parsed["publicKey"].upper(), "SM2 PEM 公钥推导", {"pem": "local"})
    # 本地从 SM2 证书提取公钥 → 与原站一致
    payload = {"cert": SM2_CERT_PEM, "certFormat": "TEXT", "publicKeyFormat": "HEX"}
    cmp(remote.ok("/sm2/cert/extract-pubkey", payload),
        local_ok(client, "/sm2/cert/extract-pubkey", payload),
        "SM2 证书提取公钥", {"cert": "SM2_CERT_PEM"})


SM2_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBfDCCASGgAwIBAgIUTLN3kNpqMN4mZ8ZK51hMET8YhH0wCgYIKoEcz1UBg3Uw
EzERMA8GA1UEAwwIU00yIFRlc3QwHhcNMjYxMTAxMDM1MjI0WhcNMjYxMjAxMDM1
MjI0WjATMREwDwYDVQQDDAhTTTIgVGVzdDBZMBMGByqGSM49AgEGCCqBHM9VAYIt
A0IABMgfDRogXuEeI99C67UbR2QheDMHkjKEE/pi8fxavEa8zlUWaE0gErdfJNFM
QgxdDU+1LX8044xvu5CmBjnm4iujUzBRMB0GA1UdDgQWBBR6tIMScVVrl6vOeSSG
iLu1AjoPVzAfBgNVHSMEGDAWgBR6tIMScVVrl6vOeSSGiLu1AjoPVzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqBHM9VAYN1A0kAMEYCIQDK/iUL605pH8l0Gb/n/P575Lfc
rKslNmSzHiyeLSJc1AIhAPn+VxWbUey0Qd4jtEN4R2UFKB7La8Lw8ncyzpjW6GHJ
-----END CERTIFICATE-----"""


# ---------------------------------------------------------------------------
# 与原站交叉验证：RSA
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def x_rsa(remote):
    return remote.ok("/rsa/keypair", {"publicKeyFormat": "HEX", "privateKeyFormat": "HEX", "keySize": 2048})


def test_x_rsa_keypair_and_pubkey(client, remote, x_rsa):
    payload = {"privateKey": x_rsa["privateKey"], "privateKeyFormat": "HEX", "publicKeyFormat": "HEX"}
    cmp(remote.ok("/rsa/pubkey/calculate", payload),
        local_ok(client, "/rsa/pubkey/calculate", payload), "RSA 公钥计算", {"step": "calculate"})
    cmp(x_rsa["publicKey"], local_ok(client, "/rsa/pubkey/calculate", payload),
        "RSA 公钥与原站一致", {"step": "compare"})


def test_x_rsa_encrypt_decrypt(client, remote, x_rsa):
    for fill in ("RSA/ECB/PKCS1Padding", "RSA/ECB/NoPadding", "RSA/ECB/OAEPPadding"):
        payload = {
            "message": "rsa 交叉验证", "messageFormat": "TEXT",
            "publicKey": x_rsa["publicKey"], "publicKeyFormat": "HEX",
            "fillMethod": fill, "cipherFormat": "HEX",
        }
        remote_cipher = remote.ok("/rsa/encrypt", payload)
        local_cipher = local_ok(client, "/rsa/encrypt", payload)
        cmp(len(remote_cipher), len(local_cipher), "RSA 密文长度(%s)" % fill, {"fill": fill})
        cmp("rsa 交叉验证", local_ok(client, "/rsa/decrypt", {
            "cipher": remote_cipher, "cipherFormat": "HEX", "privateKey": x_rsa["privateKey"],
            "privateKeyFormat": "HEX", "fillMethod": fill, "messageFormat": "TEXT",
        }), "原站加密→本地解密(%s)" % fill, {"fill": fill})
        cmp("rsa 交叉验证", remote.ok("/rsa/decrypt", {
            "cipher": local_cipher, "cipherFormat": "HEX", "privateKey": x_rsa["privateKey"],
            "privateKeyFormat": "HEX", "fillMethod": fill, "messageFormat": "TEXT",
        }), "本地加密→原站解密(%s)" % fill, {"fill": fill})


def test_x_rsa_sign_verify(client, remote, x_rsa):
    for algo in ("SHA1withRSA", "SHA256withRSA", "SHA512withRSA"):
        base = {
            "message": "rsa sign cross check", "messageFormat": "TEXT",
            "signHash": algo, "signatureFormat": "HEX",
        }
        remote_sig = remote.ok("/rsa/sign", dict(base, privateKey=x_rsa["privateKey"],
                                                 privateKeyFormat="HEX"))
        local_sig = local_ok(client, "/rsa/sign", dict(base, privateKey=x_rsa["privateKey"],
                                                       privateKeyFormat="HEX"))
        cmp(len(remote_sig), len(local_sig), "RSA 签名长度(%s)" % algo, {"algo": algo})
        # 原站签名 → 本地验签
        assert local_ok(client, "/rsa/verify", dict(base, publicKey=x_rsa["publicKey"],
                                                    publicKeyFormat="HEX", signature=remote_sig))["valid"] is True, (
            "本地无法验证原站 RSA 签名 %s: %s" % (algo, remote_sig[:64])
        )
        # 本地签名 → 原站验签
        result = remote.call("/rsa/verify", dict(base, publicKey=x_rsa["publicKey"],
                                                 publicKeyFormat="HEX", signature=local_sig))
        assert result["code"] == 0, "原站无法验证本地 RSA 签名 %s: %s" % (
            algo, json.dumps(result, ensure_ascii=False))
        # PKCS#1 v1.5 是确定性签名：同一密钥、同一消息、同一算法应逐字节一致
        cmp(remote_sig, local_sig, "RSA 签名值(%s)" % algo, {"algo": algo})


def test_x_rsa_cert_extract(client, remote):
    payload = {"cert": make_rsa_cert(), "certFormat": "TEXT", "publicKeyFormat": "HEX"}
    cmp(remote.ok("/rsa/extract/publicKey", payload),
        local_ok(client, "/rsa/extract/publicKey", payload), "RSA 证书提取公钥", {"cert": "generated"})


# ---------------------------------------------------------------------------
# 与原站交叉验证：ECDSA
# ---------------------------------------------------------------------------

EC_SIZE = {"secp256r1": 32, "secp384r1": 48, "secp521r1": 66, "secp256k1": 32}


@pytest.mark.parametrize("curve", ["secp256r1", "secp384r1", "secp521r1", "secp256k1"])
def test_x_ecdsa(client, remote, curve):
    kp = None
    for _ in range(3):
        try:
            kp = remote.ok("/ecdsa/keypair", {
                "publicKeyFormat": "HEX", "privateKeyFormat": "HEX", "curveType": curve})
            break
        except AssertionError:
            time.sleep(1)
    assert kp, "原站 ECDSA 密钥生成失败"
    size = EC_SIZE[curve]
    pub_raw = norm_point(kp["publicKey"], size)
    priv_hex = kp["privateKey"].upper().lstrip("0").rjust(size * 2, "0")

    # 本地由原站私钥推导公钥，必须与原站公钥点一致
    derived = A.parse_ecdsa_private(priv_hex, "HEX", curve).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )[1:].hex().upper()
    cmp(pub_raw, derived, "ECDSA 公钥点（%s）" % curve, {"curve": curve})

    message = "ecdsa cross"
    # 本地签名 → 原站验签
    local_sig = local_ok(client, "/ecdsa/sign", {
        "message": message, "messageFormat": "TEXT", "privateKey": priv_hex,
        "privateKeyFormat": "HEX", "signHash": "SHA256", "signatureFormat": "HEX",
        "curveType": curve,
    })
    result = remote.call("/ecdsa/verify", {
        "message": message, "messageFormat": "TEXT", "publicKey": pub_raw,
        "publicKeyFormat": "HEX", "signHash": "SHA256",
        "signature": local_sig, "signatureFormat": "HEX", "curveType": curve,
    })
    assert result.get("code") == 0, "原站无法验证本地 ECDSA 签名（%s）: %s" % (
        curve, json.dumps(result, ensure_ascii=False))
    # 原站签名 → 本地验签
    remote_sig = remote.ok("/ecdsa/sign", {
        "message": message, "messageFormat": "TEXT", "privateKey": kp["privateKey"],
        "privateKeyFormat": "HEX", "signHash": "SHA256", "signatureFormat": "HEX",
        "curveType": curve,
    })
    assert local_ok(client, "/ecdsa/verify", {
        "message": message, "messageFormat": "TEXT", "publicKey": pub_raw,
        "publicKeyFormat": "HEX", "signHash": "SHA256", "signature": remote_sig,
        "signatureFormat": "HEX", "curveType": curve,
    })["valid"] is True, "本地无法验证原站 ECDSA 签名（%s）: %s" % (curve, remote_sig[:80])
    # DER 结构一致
    assert remote_sig[:2] == "30" and local_sig[:2] == "30"


# ---------------------------------------------------------------------------
# 与原站交叉验证：点压缩
# ---------------------------------------------------------------------------


def test_x_compress(client, remote, x_sm2):
    full = "04" + x_sm2["pub"]
    payload = {"type": "SM2", "compressType": "compress", "decompressPubkey": full, "compressPubkey": ""}
    remote_c = remote.ok("/compress/parse", payload)
    local_c = local_ok(client, "/compress/parse", payload)
    cmp(remote_c, local_c, "SM2 点压缩", {"pub": "x_sm2"})
    payload = {"type": "SM2", "compressType": "decompress", "decompressPubkey": "", "compressPubkey": remote_c}
    cmp(remote.ok("/compress/parse", payload), local_ok(client, "/compress/parse", payload),
        "SM2 点解压", {"compressed": remote_c})
