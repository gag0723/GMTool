"""能力验证必备模块测试：PRF / KDF / TLCP / SM2K / 签名攻击 / 点运算 / PBKDF2 / 工作模式检测。

覆盖三类验证：
1. 标准向量（TLS 1.2 PRF、RFC 5869 HKDF、RFC 6070 PBKDF2、SM2 曲线参数）
2. 接口往返（Flask test_client 打 /api/ops/*，含错误分支）
3. 原站交叉验证（https://cipher.huijusa.cn/api/operation/*，无网络时自动跳过）
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

import pytest

from app.core import ops
from app.server import create_app

SM2_G = ops.point_encode(ops.get_curve("sm2p256v1"), ops.get_curve("sm2p256v1").g)
D_SAMPLE = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
K_SAMPLE = 0x1F2E3D4C5B6A79880F1E2D3C4B5A69780F1E2D3C4B5A69780F1E2D3C4B5A6978
E1 = 0x1111111111111111111111111111111111111111111111111111111111111111
E2 = 0x2222222222222222222222222222222222222222222222222222222222222222


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def api(client, path, payload):
    resp = client.post("/api/ops" + path, json=payload)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body is not None, resp.data
    return body


def ok_data(client, path, payload):
    body = api(client, path, payload)
    assert body["code"] == 0, body
    return body["data"]


# --------------------------------------------------------------- PRF

def test_prf_tls12_reference_vector():
    """BoringSSL 公开的 TLS 1.2 PRF(SHA256, label, seed, 100) 参考值。"""
    secret = bytes.fromhex("9bbe436ba940f017b17652849a71db35")
    seed = bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c")
    expected = (
        "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af"
        "0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff7018"
        "7347b66"
    )
    out = ops.prf("SHA256", secret, seed, b"test label", 4)[:100]
    assert out.hex() == expected


def test_prf_structure_matches_manual_hmac():
    """PRF(rounds=1) 必须等于 HMAC(K, HMAC(K,msg)||msg)，且更长输出是前缀。"""
    key, seed, label = b"key-1234", b"seed-5678", b"lbl"
    msg = label + seed
    manual = hmac.new(key, hmac.new(key, msg, "sm3").digest() + msg, "sm3").digest()
    assert ops.prf("SM3", key, seed, label, 1) == manual
    one = ops.prf("SM3", key, seed, label, 2)
    assert len(one) == 64
    assert ops.prf("SM3", key, seed, label, 3)[:64] == one


def test_prf_label_position_matches_origin_site_rule():
    """原站 /operation/prf 把 Label 放在 Seed 之后。"""
    key, seed, label = bytes.fromhex("000102030405060708090a0b0c0d0e0f"), bytes.fromhex("1112131415161718"), b"master secret"
    after = ops.prf("SM3", key, seed, label, 4, label_after=True)
    before = ops.prf("SM3", key, seed, label, 4, label_after=False)
    assert after != before
    msg = seed + label
    a = hmac.new(key, msg, "sm3").digest()
    assert after[:32] == hmac.new(key, a + msg, "sm3").digest()


def test_prf_direct_sm3_iteration(client):
    """直接 SM3 迭代 PRF：SM3(K||Label||Seed||CT||prev)，与 HMAC 构造结果不同。"""
    key, seed, label = b"key", b"seed", b"lbl"
    out = ops.prf_sm3_direct(key, seed, label, 2)
    first = hashlib.new("sm3", key + label + seed + (1).to_bytes(4, "big")).digest()
    second = hashlib.new("sm3", key + label + seed + (2).to_bytes(4, "big") + first).digest()
    assert out == first + second
    assert out != ops.prf("SM3", key, seed, label, 2)
    api_out = ok_data(client, "/prf", {
        "type": "SM3", "key": key.hex(), "keyFormat": "HEX", "seed": seed.hex(),
        "seedFormat": "HEX", "lable": "lbl", "prfMode": "ITER", "rounds": 2,
        "resultFormat": "HEX"
    })
    assert api_out == out.hex()


def test_prf_api(client):
    data = ok_data(client, "/prf", {
        "type": "SM3", "key": "6b6579", "keyFormat": "HEX", "seed": "abc", "seedFormat": "TEXT",
        "lable": "", "rounds": 2, "resultFormat": "HEX"
    })
    assert len(data) == 128
    assert data == ops.prf("SM3", b"key", b"abc", b"", 2).hex()

    base64_out = ok_data(client, "/prf", {
        "type": "SM3", "key": "6b6579", "keyFormat": "HEX", "seed": "abc",
        "seedFormat": "TEXT", "rounds": 1, "resultFormat": "BASE64"
    })
    assert len(base64_out) > 0


def test_prf_api_errors(client):
    assert api(client, "/prf", {"key": "", "seed": "ab"})["code"] == 1
    assert api(client, "/prf", {"key": "6b", "seed": "ab", "rounds": 0})["code"] == 1
    assert api(client, "/prf", {"key": "6b", "seed": "ab", "rounds": 999})["code"] == 1
    assert api(client, "/prf", {"key": "zz", "seed": "ab", "keyFormat": "HEX"})["code"] == 1


# --------------------------------------------------------------- KDF

def test_sm3_kdf_counter_structure():
    z = bytes.fromhex("0102030405060708")
    out = ops.sm3_kdf(z, 48)
    assert out[:32] == hashlib.new("sm3", z + (1).to_bytes(4, "big")).digest()
    assert out[32:] == hashlib.new("sm3", z + (2).to_bytes(4, "big")).digest()[:16]
    # SharedInfo 追加在计数器之后
    info = b"shared"
    assert ops.sm3_kdf(z, 32, info) == hashlib.new(
        "sm3", z + (1).to_bytes(4, "big") + info).digest()


def test_hkdf_rfc5869_vector():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = ops.hkdf_sha256(ikm, 42, salt, info)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_x963_kdf_equals_sha256_iteration():
    z = bytes.fromhex("11" * 24)
    assert ops.x963_kdf(z, 64) == ops.hash_kdf("SHA256", z, 64)


def test_kdf_api(client):
    data = ok_data(client, "/kdf", {
        "type": "SM3", "message": "0102030405060708", "messageFormat": "HEX",
        "length": 32, "resultFormat": "HEX"
    })
    assert data == ops.sm3_kdf(bytes.fromhex("0102030405060708"), 32).hex()

    sha = ok_data(client, "/kdf", {
        "type": "SHA256", "message": "0102030405060708", "messageFormat": "HEX",
        "length": 32, "resultFormat": "HEX"
    })
    assert sha == hashlib.sha256(bytes.fromhex("0102030405060708") + b"\x00\x00\x00\x01").hexdigest()

    hkdf = ok_data(client, "/kdf", {
        "type": "HKDF", "message": "0b" * 22, "messageFormat": "HEX",
        "sharedInfo": "f0f1f2f3", "length": 16, "resultFormat": "HEX"
    })
    assert len(hkdf) == 32

    assert api(client, "/kdf", {"type": "SM3", "message": "", "length": 32})["code"] == 1
    assert api(client, "/kdf", {"type": "XXX", "message": "00", "length": 32})["code"] == 1


# --------------------------------------------------------------- TLCP

def test_tlcp_master_and_keyblock_vectors():
    cr, sr, pms = b"\x00" * 32, b"\x11" * 32, b"\x22" * 32
    master = ops.tlcp_master_secret(pms, cr, sr)
    assert master.hex() == (
        "2e60036cab78c77e9557d5f13c1446c0f8c972049f65f22d2d5b99f10d6bf1c3"
        "462d7fa3ab0dd5bf344aa57dd50eb28f"
    )
    block = ops.tlcp_key_block(master, cr, sr, suite_type=1)
    assert len(block["clientWriteMacSecret"]) == 64
    assert len(block["clientWritekey"]) == 32
    assert len(block["clientWriteIv"]) == 32
    assert block["length"] == 128
    # 密钥块前 32 字节就是 client_write_mac_secret
    assert block["keyBlock"].startswith(block["clientWriteMacSecret"])

    gcm = ops.tlcp_key_block(master, cr, sr, suite_type=2)
    assert gcm["clientWriteMacSecret"] == ""
    assert len(gcm["clientWritekey"]) == 32
    assert len(gcm["clientWriteIv"]) == 8
    assert gcm["length"] == 40


def test_tlcp_api(client):
    master = ok_data(client, "/tlcp/master", {
        "type": "SM3", "clientRandom": "00" * 32, "serverRandom": "11" * 32,
        "preMasterKey": "22" * 32, "str1": "master secret"
    })
    assert len(master) == 96

    keys = ok_data(client, "/tlcp/keys", {
        "type": "SM3", "masterKey": master, "clientRandom": "00" * 32,
        "serverRandom": "11" * 32, "str2": "key expansion", "cipherSuiteType": 1
    })
    for field in ("clientWriteMacSecret", "serverWriteMacSecret", "clientWritekey",
                  "serverWritekey", "clientWriteIv", "serverWriteIv"):
        assert keys[field], field
    assert keys["masterKey"] == master

    gcm = ok_data(client, "/tlcp/keys", {
        "type": "SM3", "masterKey": master, "clientRandom": "00" * 32,
        "serverRandom": "11" * 32, "str2": "key expansion", "cipherSuiteType": 2
    })
    assert gcm["clientWriteMacSecret"] == ""
    assert len(gcm["clientWriteIv"]) == 8

    assert api(client, "/tlcp/keys", {
        "type": "SM3", "masterKey": "", "clientRandom": "00", "serverRandom": "11"
    })["code"] == 1


# --------------------------------------------------------------- SM2 基础

def test_sm2_curve_parameters():
    for name in ops.CURVE_NAMES:
        c = ops.get_curve(name)
        assert ops.point_on_curve(c, c.g), name
        assert ops.point_mul(c, c.n, c.g) is None, name


def test_sm2_encrypt_decrypt_roundtrip():
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    msg = "SM2 加解密往返".encode()
    ct = ops.sm2_encrypt(pub, msg, k=12345)
    assert ops.sm2_decrypt(D_SAMPLE, ct) == msg
    # C1 为 04||X||Y
    assert ct[0] == 0x04 and len(ct) == 65 + 32 + len(msg)


def test_sm2_sign_matches_curve_equation():
    """用 kG 的 x 坐标验证签名等式：sG + (r+s)P == kG。"""
    c = ops.get_curve("sm2p256v1")
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    r, s = ops.sm2_sign(D_SAMPLE, E1, K_SAMPLE)
    assert ops.sm2_verify(pub, E1, r, s)
    left = ops.point_add(c, ops.point_mul(c, s, c.g), ops.point_mul(c, (r + s) % c.n, pub))
    right = ops.point_mul(c, K_SAMPLE, c.g)
    assert left == right
    assert (E1 + left[0]) % c.n == r


# --------------------------------------------------------------- SM2K

def test_sm2k_collision_and_recover_api(client):
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    pub_hex = ops.point_encode(ops.get_curve("sm2p256v1"), pub).hex()
    msg = b"hello sm2k"
    ct = ops.sm2_encrypt(pub, msg, k=1234)

    data = ok_data(client, "/sm2k/collision", {
        "cipher": ct[:65].hex(), "cipherFormat": "HEX",
        "publicKey": pub_hex, "publicKeyFormat": "HEX", "maxK": 2000
    })
    assert int(data["k"], 16) == 1234
    assert data["sharedPoint"]

    rec = ok_data(client, "/sm2k/recover", {
        "cipher": ct.hex(), "cipherFormat": "HEX",
        "publicKey": pub_hex, "publicKeyFormat": "HEX", "maxK": 2000, "resultFormat": "TEXT"
    })
    assert rec["plainHex"] == msg.hex()
    assert rec["result"] == msg.decode()

    # 未碰撞到应当报错
    fail = api(client, "/sm2k/collision", {
        "cipher": ct[:65].hex(), "cipherFormat": "HEX", "maxK": 10
    })
    assert fail["code"] == 1 and "碰撞" in fail["msg"]


def test_sm2k_reuse_detection(client):
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    pub_hex = ops.point_encode(ops.get_curve("sm2p256v1"), pub).hex()
    ct_a = ops.sm2_encrypt(pub, b"first", k=777)
    ct_b = ops.sm2_encrypt(pub, b"second", k=777)
    ct_c = ops.sm2_encrypt(pub, b"third", k=778)

    same = ok_data(client, "/sm2k/reuse", {
        "cipher": ct_a.hex(), "cipher2": ct_b.hex(),
        "publicKey": pub_hex, "publicKeyFormat": "HEX"
    })
    assert same["reuse"] is True
    assert same["c1A"] == same["c1B"]

    diff = ok_data(client, "/sm2k/reuse", {
        "cipher": ct_a.hex(), "cipher2": ct_c.hex()
    })
    assert diff["reuse"] is False
    assert diff["sameX"] is False


def test_sm2k_accepts_c1_without_prefix():
    c = ops.get_curve("sm2p256v1")
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    ct = ops.sm2_encrypt(pub, b"x", k=91)
    assert ops.sm2_find_k(ct[1:65], 200) == 91
    found = ops.sm2_find_k(ct[:65], 200)
    assert found == 91


# --------------------------------------------------------------- 签名攻击

def test_unravel_recovers_private_key_api(client):
    """自造样本：同一 k 签两组签名，必须能反推真实私钥。"""
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    r1, s1 = ops.sm2_sign(D_SAMPLE, E1, K_SAMPLE)
    r2, s2 = ops.sm2_sign(D_SAMPLE, E2, K_SAMPLE)
    assert ops.sm2_verify(pub, E1, r1, s1) and ops.sm2_verify(pub, E2, r2, s2)
    sig1 = f"{r1:064x}{s1:064x}"
    sig2 = f"{r2:064x}{s2:064x}"

    data = ok_data(client, "/unravel/rrss", {
        "signOne": sig1, "signTwo": sig2,
        "macOne": f"{E1:064x}", "macTwo": f"{E2:064x}"
    })
    assert int(data["d"], 16) == D_SAMPLE
    assert int(data["k"], 16) == K_SAMPLE
    assert data["verified"] is True
    assert data["publicKey"] == ops.point_encode(ops.get_curve("sm2p256v1"), pub).hex()

    # EESS 布局：R||S||E
    eess1 = sig1 + f"{E1:064x}"
    eess2 = sig2 + f"{E2:064x}"
    e = ok_data(client, "/unravel/eess", {"signOne": eess1, "signTwo": eess2})
    assert int(e["d"], 16) == D_SAMPLE

    # rsk → d
    rsk = ok_data(client, "/unravel/rsk", {"signOne": sig1, "random": f"{K_SAMPLE:064x}"})
    assert int(rsk["d"], 16) == D_SAMPLE
    assert rsk["verified"] is True

    # rsd → k
    rsd = ok_data(client, "/unravel/rsd", {"signOne": sig1, "key": f"{D_SAMPLE:064x}"})
    assert int(rsd["k"], 16) == K_SAMPLE

    # rsd1 → d2（两组同 k，第二组私钥相同）
    d2 = ok_data(client, "/unravel/rsd1", {
        "signOne": sig1, "key": f"{D_SAMPLE:064x}", "signTwo": sig2
    })
    assert int(d2["d2"], 16) == D_SAMPLE

    # 验签接口
    v = ok_data(client, "/unravel/verify", {
        "signOne": sig1, "macOne": f"{E1:064x}",
        "publicKey": ops.point_encode(ops.get_curve("sm2p256v1"), pub).hex()
    })
    assert v["valid"] is True


def test_unravel_rsd1_different_second_key():
    """第二组使用不同私钥但相同 k，rsd1 必须推出 d2。"""
    d2 = 0x0E5C1A7B3D9F2468ACE013579BDF2468ACE013579BDF2468ACE013579BDF2468
    r1, s1 = ops.sm2_sign(D_SAMPLE, E1, K_SAMPLE)
    r2, s2 = ops.sm2_sign(d2, E2, K_SAMPLE)
    assert ops.d2_from_rsd1(r1, s1, D_SAMPLE, r2, s2) == d2


def test_unravel_der_roundtrip(client):
    r1, s1 = ops.sm2_sign(D_SAMPLE, E1, K_SAMPLE)
    sig1 = f"{r1:064x}{s1:064x}"
    der = ok_data(client, "/unravel/rs2der", {"signOne": sig1, "resultFormat": "HEX"})
    assert der.startswith("30")
    assert ops.der_to_rs(bytes.fromhex(der)) == (r1, s1)

    back = ok_data(client, "/unravel/der2rs", {"signOne": der})
    assert back["rs"] == sig1

    eess = ok_data(client, "/unravel/eess2der", {"signOne": sig1 + f"{E1:064x}", "resultFormat": "HEX"})
    assert eess == der

    again = ok_data(client, "/unravel/der2eess", {"signOne": der, "macOne": f"{E1:064x}", "resultFormat": "HEX"})
    assert again == sig1 + f"{E1:064x}"


def test_unravel_error_cases(client):
    assert api(client, "/unravel/rrss", {"signOne": "00", "signTwo": "00"})["code"] == 1
    # 两组完全相同 → 分母为 0
    sig = f"{0x11:064x}{0x22:064x}"
    body = api(client, "/unravel/rrss", {
        "signOne": sig, "signTwo": sig, "macOne": "11" * 4, "macTwo": "22" * 4
    })
    assert body["code"] == 1


# --------------------------------------------------------------- 点运算

def test_point_operations_api(client):
    c = ops.get_curve("sm2p256v1")
    g_hex = SM2_G.hex()
    two_g = ops.point_encode(c, ops.point_mul(c, 2, c.g)).hex()

    add = ok_data(client, "/point", {
        "type": 1, "curveName": "sm2p256v1", "pointOne": g_hex, "pointOneFormat": "HEX",
        "pointTwo": g_hex, "pointTwoFormat": "HEX", "resultFormat": "HEX"
    })
    assert add == two_g

    mul = ok_data(client, "/point", {
        "type": 3, "curveName": "sm2p256v1", "pointOne": g_hex, "pointOneFormat": "HEX",
        "pointTwo": "02", "pointTwoFormat": "HEX", "resultFormat": "HEX"
    })
    assert mul == two_g

    sub = ok_data(client, "/point", {
        "type": 2, "curveName": "sm2p256v1", "pointOne": g_hex, "pointOneFormat": "HEX",
        "pointTwo": g_hex, "pointTwoFormat": "HEX", "resultFormat": "HEX"
    })
    assert sub == "00"

    neg = ok_data(client, "/point", {
        "type": "neg", "curveName": "sm2p256v1", "pointOne": two_g, "resultFormat": "HEX"
    })
    back = ok_data(client, "/point", {
        "type": "add", "curveName": "sm2p256v1", "pointOne": two_g, "pointTwo": neg,
        "resultFormat": "HEX"
    })
    assert back == "00"

    compressed = ok_data(client, "/point", {
        "type": "compress", "curveName": "sm2p256v1", "pointOne": g_hex, "resultFormat": "HEX"
    })
    assert len(compressed) == 66 and compressed[:2] in ("02", "03")
    restored = ok_data(client, "/point", {
        "type": "decompress", "curveName": "sm2p256v1", "pointOne": compressed, "resultFormat": "HEX"
    })
    assert restored == g_hex


def test_point_other_curves_and_sm9():
    # NIST P-256 的 2G 已知值
    p256 = ops.get_curve("prime256v1")
    two_g = ops.point_encode(p256, ops.point_mul(p256, 2, p256.g)).hex()
    assert two_g == (
        "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
    )
    # SM9 G1 / G2 数乘后仍在群上
    for name in ("sm9g1", "sm9g2"):
        c = ops.get_curve(name)
        p = ops.point_mul(c, 0x1234, c.g)
        assert ops.point_on_curve(c, p), name
        assert ops.point_mul(c, c.n, c.g) is None
    # SM9 G2 编解码往返（含压缩）
    g2 = ops.get_curve("sm9g2")
    p = ops.point_mul(g2, 7, g2.g)
    assert ops.point_decode(g2, ops.point_encode(g2, p)) == p
    assert ops.point_decode(g2, ops.point_encode(g2, p, True)) == p


def test_point_invalid_input(client):
    body = api(client, "/point", {
        "type": 1, "curveName": "sm2p256v1",
        "pointOne": "04" + "11" * 64, "pointTwo": SM2_G.hex()
    })
    assert body["code"] == 1
    assert api(client, "/point", {"type": "xxx", "pointOne": SM2_G.hex()})["code"] == 1
    assert api(client, "/point", {"type": 1, "curveName": "nope", "pointOne": SM2_G.hex()})["code"] == 1


# --------------------------------------------------------------- PBKDF2

def test_pbkdf2_rfc6070_vector(client):
    assert ops.pbkdf2(b"password", b"salt", 1, 20, "SHA").hex() == "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    assert ops.pbkdf2(b"password", b"salt", 2, 20, "SHA").hex() == "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
    data = ok_data(client, "/pbkdf2", {
        "type": "SHA", "password": "password", "passwordFormat": "TEXT",
        "salt": "salt", "saltFormat": "TEXT", "times": 4096,
        "length": 32, "resultFormat": "HEX"
    })
    assert data == hashlib.pbkdf2_hmac("sha1", b"password", b"salt", 4096, 32).hex()


@pytest.mark.parametrize("algo", ["SM3", "SHA256", "SHA512"])
def test_pbkdf2_matches_hashlib(algo):
    name = {"SM3": "sm3", "SHA256": "sha256", "SHA512": "sha512"}[algo]
    mine = ops.pbkdf2(b"p@ss", b"NaCl", 5, 48, algo)
    assert mine == hashlib.pbkdf2_hmac(name, b"p@ss", b"NaCl", 5, 48)


def test_pbkdf2_api_and_errors(client):
    data = ok_data(client, "/pbkdf2", {
        "type": "SM3", "password": "password", "passwordFormat": "TEXT",
        "salt": "salt", "saltFormat": "TEXT", "times": 2, "length": 32, "resultFormat": "HEX"
    })
    assert data == ops.pbkdf2(b"password", b"salt", 2, 32, "SM3").hex()
    assert api(client, "/pbkdf2", {"type": "SM3", "password": "", "salt": "s", "times": 1, "length": 8})["code"] == 1
    assert api(client, "/pbkdf2", {"type": "SM3", "password": "p", "salt": "s", "times": 0, "length": 8})["code"] == 1
    assert api(client, "/pbkdf2", {"type": "NOPE", "password": "p", "salt": "s", "times": 1, "length": 8})["code"] == 1


# --------------------------------------------------------------- 工作模式检测

def test_detect_ecb(client):
    block = bytes.fromhex("11223344556677889900aabbccddeeff")
    ct1 = block * 4
    ct2 = block * 3 + bytes.fromhex("ffeeddccbbaa99887766554433221100")
    data = ok_data(client, "/mode/detect", {
        "ciphertext1": ct1.hex(), "ciphertext1Format": "HEX",
        "ciphertext2": ct2.hex(), "ciphertext2Format": "HEX"
    })
    assert data["top"] == "ECB"
    assert data["guesses"][0]["confidence"] > 0.5
    assert data["dupBlocks"] >= 1
    assert "ECB" in data["detailedAnalysis"]
    assert data["analysisData"]["identicalBlocks"] == 3


def test_detect_stream_mode(client):
    ct1 = bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344")
    ct2 = bytes([ct1[0] ^ 0x01]) + ct1[1:]
    data = ok_data(client, "/mode/detect", {
        "ciphertext1": ct1.hex(), "ciphertext2": ct2.hex()
    })
    assert data["top"] in ("CTR", "OFB", "CFB")
    assert data["aligned"] is False


def test_detect_same_ciphertext(client):
    x = bytes(range(48))
    data = ok_data(client, "/mode/detect", {"ciphertext1": x.hex(), "ciphertext2": x.hex()})
    assert data["top"] in ("ECB", "BC")


def test_detect_errors(client):
    assert api(client, "/mode/detect", {"ciphertext1": "00", "ciphertext2": "00"})["code"] == 1
    assert api(client, "/mode/detect", {"ciphertext1": "00" * 16, "ciphertext2": "00" * 20})["code"] == 1


# ===============================================================
# 原站交叉验证（网络不可用时自动跳过）
# ===============================================================

REMOTE = os.environ.get("CIPHERBOX_REMOTE", "https://cipher.huijusa.cn/api")
TIMEOUT = 20
_HEADERS = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (compatible; cipherbox-test)"}


def _post(path: str, payload: dict):
    import requests
    import time

    last = None
    server_down = False
    for i in range(6):
        try:
            resp = requests.post(REMOTE + path, json=payload, headers=_HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
            last = f"HTTP {resp.status_code}"
            if resp.status_code >= 500:
                server_down = True
        except Exception as exc:  # pragma: no cover - 网络异常
            last = str(exc)
        time.sleep(1.5 * (i + 1))
    if server_down:
        pytest.skip(f"原站持续 5xx（{last}），跳过本轮交叉验证：{path}")
    raise AssertionError(f"原站接口请求失败：{path}（{last}）")


@pytest.fixture(scope="module")
def remote_available():
    try:
        _post("/operation/prf", {
            "type": "SM3", "key": "6b6579", "keyFormat": "HEX", "seed": "616263",
            "seedFormat": "HEX", "lable": "", "rounds": 1, "resultFormat": "HEX"
        })
        return True
    except Exception:
        return False


needs_remote = pytest.mark.skipif(
    os.environ.get("CIPHERBOX_SKIP_REMOTE") == "1",
    reason="显式跳过原站交叉验证"
)


def _remote_cmp(remote_value, mine):
    assert str(remote_value).upper() == str(mine).upper()


@needs_remote
def test_cross_prf(remote_available):
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    cases = [
        ("SM3", "6b6579", "616263", "", 2),
        ("SM3", "000102030405060708090a0b0c0d0e0f", "1112131415161718", "master secret", 4),
        ("SHA256", "6b6579", "616263", "key expansion", 3),
        ("SHA512", "aabbccdd", "0102030405060708", "", 1),
    ]
    for algo, key, seed, label, rounds in cases:
        body = _post("/operation/prf", {
            "type": algo, "key": key, "keyFormat": "HEX", "seed": seed, "seedFormat": "HEX",
            "lable": label, "rounds": rounds, "resultFormat": "HEX"
        })
        assert body["code"] == 0, body
        mine = ops.prf(algo, bytes.fromhex(key), bytes.fromhex(seed), label.encode(),
                       rounds, label_after=True)
        _remote_cmp(body["data"], mine.hex())


@needs_remote
def test_cross_kdf(remote_available):
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    for typ, z, length in (("SM3", "0102030405060708", 32), ("SM3", "00" * 32, 48),
                           ("SHA256", "0102030405060708", 32), ("SHA256", "11" * 24, 64)):
        body = _post("/operation/kdf", {
            "type": typ, "message": z, "messageFormat": "HEX",
            "length": length, "resultFormat": "HEX"
        })
        assert body["code"] == 0, body
        mine = ops.sm3_kdf(bytes.fromhex(z), length) if typ == "SM3" \
            else ops.hash_kdf("SHA256", bytes.fromhex(z), length)
        _remote_cmp(body["data"], mine.hex())


@needs_remote
def test_cross_pbkdf2(remote_available):
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    cases = [("SM3", "password", "salt", 2, 32), ("SHA", "password", "salt", 1, 20),
             ("SHA256", "password", "salt", 4096, 32), ("SM3", "p@ss word", "NaCl", 100, 48)]
    for typ, pw, salt, times, length in cases:
        body = _post("/operation/pbkdf", {
            "type": typ, "password": pw, "passwordFormat": "TEXT",
            "salt": salt, "saltFormat": "TEXT", "times": times,
            "length": length, "resultFormat": "HEX"
        })
        assert body["code"] == 0, body
        _remote_cmp(body["data"], ops.pbkdf2(pw.encode(), salt.encode(), times, length, typ).hex())


@needs_remote
def test_cross_tlcp(remote_available):
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    for typ in ("SM3", "SHA256"):
        payload = {
            "type": typ,
            "clientRandom": "00112233445566778899aabbccddeeff" * 2,
            "serverRandom": "ffeeddccbbaa99887766554433221100" * 2,
            "preMasterKey": "ab" * 32,
            "str1": "master secret",
        }
        body = _post("/operation/tlcpMasterKey", payload)
        assert body["code"] == 0, body
        mine = ops.tlcp_master_secret(bytes.fromhex(payload["preMasterKey"]),
                                      bytes.fromhex(payload["clientRandom"]),
                                      bytes.fromhex(payload["serverRandom"]), b"master secret", typ)
        _remote_cmp(body["data"], mine.hex())

        for suite in (1, 2):
            payload2 = dict(payload, masterKey="cd" * 48, str2="key expansion", cipherSuiteType=suite)
            res = _post("/operation/tlcp", payload2)
            assert res["code"] == 0, res
            block = ops.tlcp_key_block(bytes.fromhex("cd" * 48),
                                       bytes.fromhex(payload["clientRandom"]),
                                       bytes.fromhex(payload["serverRandom"]),
                                       b"key expansion", typ, suite)
            for field in ("clientWriteMacSecret", "clientWritekey", "clientWriteIv",
                          "serverWritekey", "serverWriteIv"):
                _remote_cmp(res["data"].get(field) or "", block.get(field) or "")


@needs_remote
def test_cross_point(remote_available):
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    curves = {
        "sm2p256v1": "04" + "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
                            "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
        "prime256v1": "04" + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "secp256k1": "04" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        "prime192v1": "04" + "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"
                             "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
    }
    for name, g in curves.items():
        c = ops.get_curve(name)
        p = ops.point_decode(c, bytes.fromhex(g))
        for k in (2, 3):
            body = _post("/operation/point", {
                "type": 3, "curveName": name, "pointOne": g, "pointOneFormat": "HEX",
                "pointTwo": f"{k:02x}", "pointTwoFormat": "HEX", "resultFormat": "HEX"
            })
            assert body["code"] == 0, body
            _remote_cmp(body["data"], ops.point_encode(c, ops.point_mul(c, k, p)).hex())
        body = _post("/operation/point", {
            "type": 1, "curveName": name, "pointOne": g, "pointOneFormat": "HEX",
            "pointTwo": g, "pointTwoFormat": "HEX", "resultFormat": "HEX"
        })
        _remote_cmp(body["data"], ops.point_encode(c, ops.point_add(c, p, p)).hex())


@needs_remote
def test_cross_sm2k_and_signature_attack(remote_available):
    """SM2 密文 C1 碰撞（原站仅支持 k ≤ 100）与签名攻击反推私钥。"""
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    c = ops.get_curve("sm2p256v1")
    pub = ops.sm2_pubkey_from_priv(D_SAMPLE)
    pub_hex = ops.point_encode(c, pub).hex()

    # 原站返回的 k 为十六进制字符串，且碰撞范围有限（k 过大时直接报错）
    for k in (2, 5, 36, 100):
        ct = ops.sm2_encrypt(pub, b"hi", k=k)
        body = _post("/operation/sm2k", {
            "type": 2, "cipher": ct[1:65].hex(), "cipherFormat": "HEX",
            "publicKey": pub_hex, "publicKeyFormat": "HEX"
        })
        assert body["code"] == 0, body
        assert int(str(body["data"]), 16) == k

    r1, s1 = ops.sm2_sign(D_SAMPLE, E1, K_SAMPLE)
    r2, s2 = ops.sm2_sign(D_SAMPLE, E2, K_SAMPLE)
    sig1 = f"{r1:064x}{s1:064x}"
    sig2 = f"{r2:064x}{s2:064x}"

    body = _post("/unravel/sm2/rrssToD", {
        "signOne": sig1, "signTwo": sig2,
        "macOne": f"{E1:064x}", "macTwo": f"{E2:064x}"
    })
    assert body["code"] == 0, body
    assert int(body["data"], 16) == D_SAMPLE

    body = _post("/unravel/sm2/rskToD", {"signOne": sig1, "random": f"{K_SAMPLE:064x}"})
    assert body["code"] == 0, body
    assert int(body["data"], 16) == D_SAMPLE

    body = _post("/unravel/sm2/rsdToK", {"signOne": sig1, "key": f"{D_SAMPLE:064x}"})
    assert body["code"] == 0, body
    assert int(body["data"], 16) == K_SAMPLE

    body = _post("/unravel/sm2/eessToD", {
        "signOne": sig1 + f"{E1:064x}", "signTwo": sig2 + f"{E2:064x}",
        "macOne": f"{E1:064x}", "macTwo": f"{E2:064x}"
    })
    assert body["code"] == 0, body
    assert int(body["data"], 16) == D_SAMPLE


@needs_remote
def test_cross_mode_detector(remote_available):
    """原站检测接口的返回结构与本地一致（guesses / detailedAnalysis / analysisData）。"""
    if not remote_available:
        pytest.skip("原站不可达，跳过交叉验证")
    payload = {
        "ciphertext1": ("aa" * 16) * 3, "ciphertext1Format": "HEX",
        "ciphertext2": ("bb" * 16) * 3, "ciphertext2Format": "HEX",
    }
    body = _post("/cipher-mode-detector/detect", payload)
    assert body["code"] == 0, body
    remote_modes = [g["mode"] for g in body["data"]["guesses"]]
    assert remote_modes, body

    local = ops.detect_mode(bytes.fromhex(payload["ciphertext1"]), bytes.fromhex(payload["ciphertext2"]))
    assert set(local["guesses"][0]) >= {"mode", "reasoning", "confidence", "description"}
    assert local["analysisData"]["totalBlocks"] == body["data"]["analysisData"]["totalBlocks"]
    assert "detailedAnalysis" in local

    # ECB 重复分组样本：本地必须判定为 ECB
    ecb_payload = {
        "ciphertext1": ("11" * 16) * 4, "ciphertext1Format": "HEX",
        "ciphertext2": ("11" * 16) * 3 + ("22" * 16), "ciphertext2Format": "HEX",
    }
    ecb_local = ops.detect_mode(bytes.fromhex(ecb_payload["ciphertext1"]),
                                bytes.fromhex(ecb_payload["ciphertext2"]))
    assert ecb_local["top"] == "ECB"


# --------------------------------------------------------------- 前端样例一致性

def test_js_samples_present():
    """每个 action 必须有 samples（E2E 依赖）。"""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "web", "modules", "ops.js")
    src = open(path, encoding="utf-8").read()
    for key in ("prf", "kdf", "tlcp", "sm2k", "unravelSm2", "multiply", "pbkdf2", "cipher/mode/detector"):
        assert f"key: '{key}'" in src, key
    assert src.count("samples:") >= 8
    assert "/api/ops/" in src
