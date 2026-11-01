"""对称密码模块测试：分组密码 / ZUC / GCM。

包含标准测试向量（GB/T 32907、FIPS-197、NIST SP 800-38A、SP 800-38D、GM/T 0001、
ZUC-256 草案）以及 Flask 接口的往返、错误路径校验。
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import sym  # noqa: E402

SM4_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
IV16 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
IV8 = bytes.fromhex("0001020304050607")
PT16 = bytes.fromhex("6162636465666768696a6b6c6d6e6f70")


# ---------------------------------------------------------------------------
# 分组算法标准向量
# ---------------------------------------------------------------------------


def test_sm4_single_block_vector():
    """GB/T 32907-2016 附录 A.1：单次加密。"""
    out = sym.sm4_encrypt_block_with_key(SM4_KEY, SM4_KEY)
    assert out.hex() == "681edf34d206965e86b3e94f536e4246"
    rk = sym.sm4_round_keys(SM4_KEY)
    assert sym.sm4_decrypt_block(rk, out) == SM4_KEY


def test_sm4_million_iterations():
    """GB/T 32907-2016 附录 A.2：100 万次迭代。"""
    rk = sym.sm4_round_keys(SM4_KEY)
    block = SM4_KEY
    for _ in range(1000000):
        block = sym.sm4_encrypt_block(rk, block)
    assert block.hex() == "595298c7c6fd271f0402f804c33d3f66"


@pytest.mark.parametrize(
    "algo,key,cipher",
    [
        ("AES128", "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("AES192", "000102030405060708090a0b0c0d0e0f1011121314151617",
         "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("AES256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    ],
)
def test_aes_fips197(algo, key, cipher):
    """FIPS-197 附录 C 单分组向量。"""
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    got = sym.get_cipher(algo, bytes.fromhex(key)).encrypt_block(block)
    assert got.hex() == cipher


def test_des_and_tripledes_vectors():
    """经典 DES 向量 + 3DES 的 EDE 结构一致性。"""
    des = sym.get_cipher("DES", bytes.fromhex("133457799bbcdff1"))
    assert des.encrypt_block(bytes.fromhex("0123456789abcdef")).hex() == "85e813540f0ab405"

    k2 = bytes.fromhex("0123456789abcdeffedcba9876543210")
    c2 = sym.get_cipher("DESEDE16", k2)
    c3 = sym.get_cipher("DESEDE24", k2 + k2[:8])  # K3 = K1 时与 2KEY 等价
    block = bytes.fromhex("0123456789abcdef")
    assert c2.encrypt_block(block) == c3.encrypt_block(block)
    assert c2.decrypt_block(c2.encrypt_block(block)) == block

    # 3DES-2KEY = DES 的 EDE 结构：E_K1(D_K2(E_K1(P)))
    d1 = sym.get_cipher("DES", k2[:8])
    d2 = sym.get_cipher("DES", k2[8:])
    expect = d1.encrypt_block(d2.decrypt_block(d1.encrypt_block(block)))
    assert c2.encrypt_block(block) == expect


# ---------------------------------------------------------------------------
# 工作模式标准向量
# ---------------------------------------------------------------------------


def test_aes_modes_nist_vectors():
    """NIST SP 800-38A F.1 / F.2 / F.5（AES-128，单分组）。"""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    cbc_iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ctr_iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    assert sym.block_crypt("AES128", key, "ECB", "NOPADDING", pt, b"").hex() == \
        "3ad77bb40d7a3660a89ecaf32466ef97"
    assert sym.block_crypt("AES128", key, "CBC", "NOPADDING", pt, cbc_iv).hex() == \
        "7649abac8119b246cee98e9b12e9197d"
    assert sym.block_crypt("AES128", key, "CTR", "NOPADDING", pt, ctr_iv).hex() == \
        "874d6191b620e3261bef6864990db6ce"
    assert sym.block_crypt("AES128", key, "OFB", "NOPADDING", pt, cbc_iv).hex() == \
        "3b3fd92eb72dad20333449f8e83cfb4a"
    assert sym.block_crypt("AES128", key, "CFB", "NOPADDING", pt, cbc_iv).hex() == \
        "3b3fd92eb72dad20333449f8e83cfb4a"


def test_sm4_modes_known_vectors():
    """SM4 各模式的已知密文（与原站一致，可作 KAT 固定）。"""
    assert sym.block_crypt("SM4", SM4_KEY, "ECB", "PKCS7", b"abc", b"").hex() == \
        "1055435b9ece612344f8e10016c4943b"
    assert sym.block_crypt("SM4", SM4_KEY, "CBC", "PKCS7", b"abc", IV16).hex() == \
        "4301693c448c7da7cff13f84690f7dea"
    assert sym.block_crypt("SM4", SM4_KEY, "CTR", "PKCS7", b"abc", IV16).hex() == \
        "67faff6c30ab65a02780fa8feca5f467"
    assert sym.block_crypt("SM4", SM4_KEY, "OFB", "PKCS7", b"abc", IV16).hex() == \
        "67faff6c30ab65a02780fa8feca5f467"
    assert sym.block_crypt("SM4", SM4_KEY, "CFB", "PKCS7", b"abc", IV16).hex() == \
        "67faff6c30ab65a02780fa8feca5f467"


@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR", "OFB", "CFB"])
@pytest.mark.parametrize("algo,key,iv", [
    ("SM4", SM4_KEY, IV16),
    ("AES128", bytes(range(16)), IV16),
    ("AES192", bytes(range(24)), IV16),
    ("AES256", bytes(range(32)), IV16),
    ("DES", bytes(range(8)), IV8),
    ("DESEDE16", bytes(range(16)), IV8),
    ("DESEDE24", bytes(range(24)), IV8),
])
def test_modes_roundtrip(algo, key, iv, mode):
    data = b"cipherbox \xe5\xaf\x86\xe7\xa0\x81\xe5\xb7\xa5\xe5\x85\xb7 0123456789"
    for pad in ("PKCS7", "ISO7816_4", "ANSIX923", "ZERO", "M2", "M3"):
        c = sym.block_crypt(algo, key, mode, pad, data, iv, encrypt=True)
        p = sym.block_crypt(algo, key, mode, pad, c, iv, encrypt=False)
        assert p == data or p.rstrip(b"\x00") == data.rstrip(b"\x00")


def test_no_padding_requires_block_multiple():
    with pytest.raises(Exception):
        sym.block_crypt("SM4", SM4_KEY, "ECB", "NOPADDING", b"abc", b"")


# ---------------------------------------------------------------------------
# 填充
# ---------------------------------------------------------------------------


def test_padding_layouts():
    """PKCS7 / ISO7816-4(M2) / ANSI X9.23(M3) 的具体填充字节。"""
    assert sym.pad(b"\x01\x02", 8, "PKCS7") == b"\x01\x02" + b"\x06" * 6
    assert sym.pad(b"\x01\x02", 8, "ISO7816_4") == b"\x01\x02\x80" + b"\x00" * 5
    assert sym.pad(b"\x01\x02", 8, "M2") == b"\x01\x02\x80" + b"\x00" * 5
    assert sym.pad(b"\x01\x02", 8, "ANSIX923") == b"\x01\x02" + b"\x00" * 5 + b"\x06"
    assert sym.pad(b"\x01\x02", 8, "M3") == b"\x01\x02" + b"\x00" * 5 + b"\x06"
    # ZERO 总是至少补一个分组
    assert sym.pad(b"\x01" * 8, 8, "ZERO") == b"\x01" * 8 + b"\x00" * 8
    # 对齐时 PKCS7 追加整块
    assert sym.pad(b"\x01" * 8, 8, "PKCS7") == b"\x01" * 8 + b"\x08" * 8
    assert sym.unpad(b"\x01\x02" + b"\x06" * 6, 8, "PKCS7") == b"\x01\x02"
    assert sym.unpad(b"\x01\x02\x80" + b"\x00" * 5, 8, "M2") == b"\x01\x02"
    assert sym.unpad(b"\x01\x02" + b"\x00" * 5 + b"\x06", 8, "M3") == b"\x01\x02"


def test_padding_error_paths():
    with pytest.raises(sym.ToolError):
        sym.unpad(b"\x01\x02\x03", 8, "PKCS7")            # 长度非法
    with pytest.raises(sym.ToolError):
        sym.unpad(b"\x00" * 7 + b"\x09", 8, "PKCS7")       # 填充值超出分组
    with pytest.raises(sym.ToolError):
        sym.normalize_padding("XXXX")


# ---------------------------------------------------------------------------
# XTS
# ---------------------------------------------------------------------------


def test_xts_gb_and_ieee_vectors():
    key = SM4_KEY + bytes.fromhex("fedcba98765432100123456789abcdef")
    tweak = IV16
    gb = sym.block_crypt("SM4", key, "XTS", "NOPADDING", PT16 * 2, b"", tweak=tweak, is_gb=True)
    ieee = sym.block_crypt("SM4", key, "XTS", "NOPADDING", PT16 * 2, b"", tweak=tweak, is_gb=False)
    assert gb.hex() == "b34c73ae5b249ae0a8c36a39076ab3f5e8115cbc e6ee51a66ed114c2ee1f0bf2".replace(" ", "")
    assert ieee.hex() == "b34c73ae5b249ae0a8c36a39076ab3f545c5aea7ef1486ce515581f0090f3daa"
    assert gb != ieee


def test_xts_ciphertext_stealing_roundtrip():
    key = SM4_KEY + bytes.fromhex("fedcba98765432100123456789abcdef")
    for length in (16, 17, 31, 32, 33, 48, 63, 100):
        data = (PT16 * 8)[:length]
        for is_gb in (True, False):
            c = sym.block_crypt("SM4", key, "XTS", "NOPADDING", data, b"", tweak=IV16, is_gb=is_gb)
            assert len(c) == len(data)
            assert sym.block_crypt("SM4", key, "XTS", "NOPADDING", c, b"",
                                   encrypt=False, tweak=IV16, is_gb=is_gb) == data


def test_xts_length_checks():
    key = SM4_KEY + bytes.fromhex("fedcba98765432100123456789abcdef")
    with pytest.raises(sym.ToolError):  # 密钥非双倍长度
        sym.block_crypt("SM4", SM4_KEY, "XTS", "NOPADDING", PT16, b"", tweak=IV16)
    with pytest.raises(sym.ToolError):  # tweak 非 16 字节
        sym.block_crypt("SM4", key, "XTS", "NOPADDING", PT16, b"", tweak=b"\x00" * 8)
    with pytest.raises(sym.ToolError):  # DES 不支持 XTS
        sym.block_crypt("DES", bytes(16), "XTS", "NOPADDING", PT16, b"", tweak=IV16)


# ---------------------------------------------------------------------------
# ZUC
# ---------------------------------------------------------------------------


def test_zuc128_keystream_vector():
    """ZUC 规范示例 1：key / IV 全 0。"""
    words = sym.ZUC(bytes(16), bytes(16)).keystream(8)
    assert words.hex() == "27bede74018082da"


def test_zuc128_keystream_all_ff():
    """ZUC 规范示例 2：key / IV 全 FF。"""
    assert sym.ZUC(b"\xff" * 16, b"\xff" * 16).keystream(8).hex() == "0657cfa07096398b"


def test_zuc256_keystream_vector():
    """ZUC-256 标准示例：key 32 × 00、IV 25 × 00。"""
    assert sym.ZUC(bytes(32), bytes(25)).keystream(8).hex() == "58d03ad62e032ce2"


def test_zuc_crypt_roundtrip():
    key, iv = bytes(range(16)), bytes(range(16, 32))
    data = b"ZUC \xe5\xba\x8f\xe5\x88\x97\xe5\xaf\x86\xe7\xa0\x81!" * 3
    c = sym.zuc_crypt(key, iv, data)
    assert len(c) == len(data)
    assert sym.zuc_crypt(key, iv, c) == data

    k256, iv256 = bytes(range(32)), bytes(range(25))
    c2 = sym.zuc_crypt(k256, iv256, data)
    assert sym.zuc_crypt(k256, iv256, c2) == data


def test_zuc128_mac_eia3():
    """ZUC-128 MAC（128-EIA3 结构）已知值。"""
    assert sym.zuc_mac(bytes(16), bytes(16), bytes.fromhex("00000000"), 32).hex() == "8654676c"
    assert sym.zuc_mac(bytes(16), bytes(16), bytes.fromhex("0000000000"), 32).hex() == "1f9a65e1"
    with pytest.raises(sym.ToolError):
        sym.zuc_mac(bytes(16), bytes(16), b"abc", 128)


@pytest.mark.parametrize("bits,expect", [
    (32, "02caca36"), (64, "22974e1b443ec23b"), (128, "733ac26dd1c6a555bc4dae31f91d8206"),
])
def test_zuc256_mac(bits, expect):
    """ZUC-256 MAC（256-NIA6），三种标签长度。"""
    got = sym.zuc_mac(bytes(32), bytes(25), bytes.fromhex("00000000"), bits)
    assert got.hex() == expect
    assert len(got) == bits // 8


def test_zuc_length_checks():
    with pytest.raises(sym.ToolError):
        sym.ZUC(bytes(15), bytes(16))
    with pytest.raises(sym.ToolError):
        sym.ZUC(bytes(32), bytes(23))


# ---------------------------------------------------------------------------
# GCM
# ---------------------------------------------------------------------------


def test_gcm_nist_vectors():
    """NIST GCM 规范 Test Case 2 / 4（AES-128）。"""
    c, t = sym.GCM("AES128", bytes(16)).encrypt(bytes(12), bytes(16), b"", 16)
    assert c.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert t.hex() == "ab6e47d42cec13bdf53a67b21257bddf"

    key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    iv = bytes.fromhex("cafebabefacedbaddecaf888")
    pt = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    c, t = sym.GCM("AES128", key).encrypt(iv, pt, aad, 16)
    assert c.hex() == (
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
    )
    assert t.hex() == "5bc94fbc3221a5db94fae95ae7121a47"


def test_gcm_matches_pycryptodome():
    """AES-GCM 与 pycryptodome 交叉校验（12 字节与 16 字节 IV）。"""
    from Crypto.Cipher import AES as PAES

    gcm_key = bytes(range(16))
    for iv in (bytes(range(12)), bytes(range(16))):
        plain = b"cipherbox gcm cross check payload"
        aad = b"aad-data"
        c, t = sym.GCM("AES128", gcm_key).encrypt(iv, plain, aad, 16)
        ref = PAES.new(gcm_key, PAES.MODE_GCM, nonce=iv, mac_len=16)
        ref.update(aad)
        rc, rt = ref.encrypt_and_digest(plain)
        assert c == rc and t == rt


def test_sm4_gcm_known_vector_and_roundtrip():
    gcm = sym.GCM("SM4", SM4_KEY)
    c, t = gcm.encrypt(IV16, b"abc", b"", 16)
    assert c.hex() == "cb66ab"
    assert t.hex() == "738be013adb5f09f040ebee6f9dcb8ed"

    for tag_len in (4, 8, 16):
        c, t = gcm.encrypt(IV16, b"sm4 gcm payload", b"aad", tag_len)
        assert len(t) == tag_len
        assert gcm.decrypt(IV16, c, b"aad", t, tag_len) == b"sm4 gcm payload"
    # 截断标签为完整标签前缀
    full = gcm.encrypt(IV16, b"x", b"", 16)[1]
    assert gcm.encrypt(IV16, b"x", b"", 8)[1] == full[:8]


def test_gcm_tag_mismatch_rejected():
    gcm = sym.GCM("SM4", SM4_KEY)
    c, t = gcm.encrypt(IV16, b"abc", b"", 16)
    bad = bytes([t[0] ^ 1]) + t[1:]
    with pytest.raises(sym.ToolError) as err:
        gcm.decrypt(IV16, c, b"", bad, 16)
    assert "认证标签校验不通过" in str(err.value)
    with pytest.raises(sym.ToolError):
        gcm.decrypt(IV16, c, b"", t[:8], 16)


# ---------------------------------------------------------------------------
# Flask 接口
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    from app.server import create_app

    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def _post(client, path, payload):
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    return resp.get_json()


def test_api_encrypt_decrypt(client):
    body = {
        "type": "SM4", "mode": "CBC", "padding": "PKCS7", "message": "abc",
        "messageFormat": "TEXT", "cipherFormat": "HEX", "key": SM4_KEY.hex(),
        "keyFormat": "HEX", "iv": IV16.hex(), "ivFormat": "HEX",
    }
    r = _post(client, "/api/sym/encrypt", body)
    assert r["code"] == 0 and r["data"] == "4301693c448c7da7cff13f84690f7dea"
    r2 = _post(client, "/api/sym/decrypt", {
        "type": "SM4", "mode": "CBC", "padding": "PKCS7", "cipher": r["data"],
        "cipherFormat": "HEX", "messageFormat": "TEXT", "key": SM4_KEY.hex(),
        "keyFormat": "HEX", "iv": IV16.hex(), "ivFormat": "HEX",
    })
    assert r2["code"] == 0 and r2["data"] == "abc"


def test_api_encrypt_all_algos(client):
    for algo, key, iv in [
        ("AES128", bytes(range(16)), IV16), ("AES192", bytes(range(24)), IV16),
        ("AES256", bytes(range(32)), IV16), ("DES", bytes(range(8)), IV8),
        ("DESEDE16", bytes(range(16)), IV8), ("DESEDE24", bytes(range(24)), IV8),
    ]:
        payload = {"type": algo, "mode": "CBC", "padding": "PKCS7", "message": "616263",
                   "messageFormat": "HEX", "cipherFormat": "HEX", "key": key.hex(),
                   "keyFormat": "HEX", "iv": iv.hex(), "ivFormat": "HEX"}
        r = _post(client, "/api/sym/encrypt", payload)
        assert r["code"] == 0, r
        back = _post(client, "/api/sym/decrypt", {
            **{k: v for k, v in payload.items() if k not in ("message", "cipherFormat")},
            "cipher": r["data"], "cipherFormat": "HEX", "messageFormat": "HEX",
        })
        assert back["code"] == 0 and back["data"] == "616263"


def test_api_padding_options(client):
    for pad in ("PKCS7", "ISO_10126", "ISO7816_4", "ANSIX923", "ZERO", "M2", "M3"):
        r = _post(client, "/api/sym/encrypt", {
            "type": "SM4", "mode": "ECB", "padding": pad, "message": "616263",
            "messageFormat": "HEX", "cipherFormat": "HEX", "key": SM4_KEY.hex(), "keyFormat": "HEX",
        })
        assert r["code"] == 0, (pad, r)
        back = _post(client, "/api/sym/decrypt", {
            "type": "SM4", "mode": "ECB", "padding": pad, "cipher": r["data"],
            "cipherFormat": "HEX", "messageFormat": "HEX", "key": SM4_KEY.hex(), "keyFormat": "HEX",
        })
        assert back["code"] == 0 and back["data"] == "616263", (pad, back)


def test_api_xts(client):
    key = SM4_KEY + bytes.fromhex("fedcba98765432100123456789abcdef")
    payload = {"type": "SM4", "message": PT16.hex(), "messageFormat": "HEX",
               "cipherFormat": "HEX", "key": key.hex(), "keyFormat": "HEX",
               "tweak": IV16.hex(), "tweakFormat": "HEX", "isGB": True}
    r = _post(client, "/api/sym/xts/encrypt", payload)
    assert r["code"] == 0 and r["data"] == "b34c73ae5b249ae0a8c36a39076ab3f5"
    back = _post(client, "/api/sym/xts/decrypt", {
        **{k: v for k, v in payload.items() if k not in ("message", "cipherFormat")},
        "cipher": r["data"], "cipherFormat": "HEX", "messageFormat": "HEX",
    })
    assert back["code"] == 0 and back["data"] == PT16.hex()


def test_api_zuc(client):
    zkey = "0123456789abcdeffedcba9876543210"
    ziv = "000102030405060708090a0b0c0d0e0f"
    r = _post(client, "/api/sym/zuc/encrypt", {
        "type": "ZUC128", "message": "abc", "messageFormat": "TEXT", "resultFormat": "HEX",
        "key": zkey, "keyFormat": "HEX", "iv": ziv, "ivFormat": "HEX"})
    assert r["code"] == 0 and r["data"] == "f5ca4c"
    back = _post(client, "/api/sym/zuc/decrypt", {
        "type": "ZUC128", "result": r["data"], "resultFormat": "HEX", "messageFormat": "TEXT",
        "key": zkey, "keyFormat": "HEX", "iv": ziv, "ivFormat": "HEX"})
    assert back["code"] == 0 and back["data"] == "abc"

    mac = _post(client, "/api/sym/zuc/mac", {
        "type": "ZUC128", "message": "00000000", "messageFormat": "HEX", "resultFormat": "HEX",
        "key": "00" * 16, "keyFormat": "HEX", "iv": "00" * 16, "ivFormat": "HEX"})
    assert mac["code"] == 0 and mac["data"] == "8654676c"

    mac256 = _post(client, "/api/sym/zuc/mac", {
        "type": "ZUC256", "message": "00000000", "messageFormat": "HEX", "resultFormat": "HEX",
        "key": "00" * 32, "keyFormat": "HEX", "iv": "00" * 25, "ivFormat": "HEX",
        "macLength": 16})
    assert mac256["code"] == 0 and mac256["data"] == "733ac26dd1c6a555bc4dae31f91d8206"


def test_api_zuc_errors(client):
    r = _post(client, "/api/sym/zuc/encrypt", {
        "type": "ZUC256", "message": "00", "messageFormat": "HEX", "resultFormat": "HEX",
        "key": "00" * 32, "keyFormat": "HEX", "iv": "00" * 16, "ivFormat": "HEX"})
    assert r["code"] == 1 and "25" in r["msg"]
    r = _post(client, "/api/sym/zuc/encrypt", {
        "type": "ZUC128", "message": "00", "messageFormat": "HEX", "resultFormat": "HEX",
        "key": "00" * 15, "keyFormat": "HEX", "iv": "00" * 16, "ivFormat": "HEX"})
    assert r["code"] == 1


def test_api_gcm(client):
    base = {"type": "SM4", "message": "abc", "messageFormat": "TEXT", "resultFormat": "HEX",
            "key": SM4_KEY.hex(), "keyFormat": "HEX", "iv": IV16.hex(), "ivFormat": "HEX",
            "aad": "", "aadFormat": "TEXT", "tagLength": 16, "tagFormat": "HEX"}
    r = _post(client, "/api/sym/gcm/encrypt", base)
    assert r["code"] == 0
    assert r["data"]["cipher"] == "cb66ab"
    assert r["data"]["tag"] == "738be013adb5f09f040ebee6f9dcb8ed"

    back = _post(client, "/api/sym/gcm/decrypt", {
        **{k: v for k, v in base.items() if k != "message"},
        "result": r["data"]["cipher"], "tag": r["data"]["tag"], "messageFormat": "TEXT",
    })
    assert back["code"] == 0 and back["data"] == "abc"

    bad = _post(client, "/api/sym/gcm/decrypt", {
        **{k: v for k, v in base.items() if k != "message"},
        "result": r["data"]["cipher"], "tag": "00" * 16, "messageFormat": "TEXT",
    })
    assert bad["code"] == 1 and "认证标签校验不通过" in bad["msg"]


@pytest.mark.parametrize("algo,key", [
    ("SM4", SM4_KEY), ("AES128", bytes(range(16))), ("AES192", bytes(range(24))),
    ("AES256", bytes(range(32))),
])
def test_api_gcm_all_algos(client, algo, key):
    r = _post(client, "/api/sym/gcm/encrypt", {
        "type": algo, "message": "aad and tag", "messageFormat": "TEXT", "resultFormat": "HEX",
        "key": key.hex(), "keyFormat": "HEX", "iv": IV16.hex(), "ivFormat": "HEX",
        "aad": "additional", "aadFormat": "TEXT", "tagLength": 8, "tagFormat": "HEX",
    })
    assert r["code"] == 0, r
    assert len(r["data"]["tag"]) == 16
    back = _post(client, "/api/sym/gcm/decrypt", {
        "type": algo, "result": r["data"]["cipher"], "resultFormat": "HEX", "messageFormat": "TEXT",
        "key": key.hex(), "keyFormat": "HEX", "iv": IV16.hex(), "ivFormat": "HEX",
        "aad": "additional", "aadFormat": "TEXT", "tag": r["data"]["tag"], "tagFormat": "HEX",
        "tagLength": 8,
    })
    assert back["code"] == 0 and back["data"] == "aad and tag"


def test_api_error_messages(client):
    r = _post(client, "/api/sym/encrypt", {
        "type": "SM4", "mode": "ECB", "padding": "PKCS7", "message": "61",
        "messageFormat": "HEX", "cipherFormat": "HEX", "key": "00112233", "keyFormat": "HEX"})
    assert r["code"] == 1 and "密钥长度" in r["msg"]

    r = _post(client, "/api/sym/encrypt", {
        "type": "SM4", "mode": "CBC", "padding": "PKCS7", "message": "61",
        "messageFormat": "HEX", "cipherFormat": "HEX", "key": SM4_KEY.hex(),
        "keyFormat": "HEX", "iv": "00112233", "ivFormat": "HEX"})
    assert r["code"] == 1 and "IV 长度" in r["msg"]

    r = _post(client, "/api/sym/encrypt", {
        "type": "XXTEA", "mode": "ECB", "message": "61", "messageFormat": "HEX",
        "key": SM4_KEY.hex(), "keyFormat": "HEX"})
    assert r["code"] == 1 and "不支持的算法" in r["msg"]

    r = _post(client, "/api/sym/decrypt", {
        "type": "SM4", "mode": "ECB", "padding": "PKCS7", "cipher": "ff" * 16,
        "cipherFormat": "HEX", "messageFormat": "HEX", "key": SM4_KEY.hex(), "keyFormat": "HEX"})
    assert r["code"] == 1 and r["msg"].startswith("解密失败")

    r = _post(client, "/api/sym/encrypt", {
        "type": "SM4", "mode": "ECB", "padding": "PKCS7", "message": "zz",
        "messageFormat": "HEX", "key": SM4_KEY.hex(), "keyFormat": "HEX"})
    assert r["code"] == 1
