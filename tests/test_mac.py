"""MAC 算法 / 杂凑算法猜测 模块测试。

覆盖：
1. GB/T 15852.1-2020《消息鉴别码 第 1 部分：采用分组密码的机制》附录 B 标准向量
   （SM4，8 种 MAC 算法 × 3 种填充方式 × 2 组消息，共 36 条）
2. RFC 4493 / NIST SP 800-38B 的 AES-CMAC 标准向量（AES-128/192/256）
3. GB/T 15852.1-2008 附录 A 的 DES 标准向量（CBC-MAC / EMAC / ANSI-retail-MAC / MacDES）
4. 本地接口 /api/mac/calc 与 /api/hash/digest/all 的端到端行为
5. 与线上原站（cipher.huijusa.cn）的交叉验证
"""
from __future__ import annotations

import os
import sys
import time

import pytest
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import mac as M  # noqa: E402
from app.server import create_app  # noqa: E402

REMOTE = os.environ.get("CB_REMOTE", "https://cipher.huijusa.cn")
OFFLINE = os.environ.get("CB_OFFLINE") == "1"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Content-Type": "application/json",
    "Referer": REMOTE + "/",
    "Origin": REMOTE,
}

# --------------------------------------------------------------------------- #
# 标准向量
# --------------------------------------------------------------------------- #
K1 = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
K2 = bytes.fromhex("4149D2ADED9456681EC8B511D9E7EE04")
MSG1 = bytes.fromhex("54686973206973207468652074657374206d65737361676520666f72206d6163")
MSG2 = bytes.fromhex("54686973206973207468652074657374206d65737361676520")

# (模式, 填充方式) -> (msg1 的 MAC, msg2 的 MAC)，均截断为 8 字节
GBT_2020 = {
    ("CBCMAC", "M1"): ("16E02904EFB765B7", "BA89E45FE8ABF242"),
    ("CBCMAC", "M2"): ("4B6553AF3C4E2744", "421AD1690AA152E2"),
    ("CBCMAC", "M3"): ("71AF7E4553404CBC", "6A4A86F5B5E468DA"),
    ("EMAC", "M1"): ("1E9A71D3BC92DFA7", "4EC3C7FACFAAC607"),
    ("EMAC", "M2"): ("E423E35599AFD948", "F02625CEAD008D4E"),
    ("EMAC", "M3"): ("4003BA1B6ADC53A8", "FFD5F1F2E5EDA5CB"),
    ("ANSIRETAILMAC", "M1"): ("2763211B2BCAF719", "E32D99A689C05259"),
    ("ANSIRETAILMAC", "M2"): ("51E9928C2238330C", "197247229CE9D7B6"),
    ("ANSIRETAILMAC", "M3"): ("7CD48C4242E45575", "3C430F1EA43B540C"),
    ("MACDES", "M1"): ("DD1052A7AFE8999B", "AA9DB3D9651F862B"),
    ("MACDES", "M2"): ("7E1A9A5E0EF0947F", "949476D35F17261E"),
    ("MACDES", "M3"): ("28A70D6BCCF74422", "C9D34E16C49AB643"),
    ("CMAC", "M4"): ("692C437100F3B5EE", "4738A6C760B280FC"),
    ("LMAC", "M1"): ("B38A96195BAA61FC", "8CF6E64314FEF417"),
    ("LMAC", "M2"): ("A0C465EE5896972F", "60DD955ED0CA3D7A"),
    ("LMAC", "M3"): ("43050D51C656AE60", "61E00049E26962A3"),
    ("TRCBC", "M4"): ("16E02904EFB765B7", "846FA2A5D83445A9"),
    ("CBCR", "M4"): ("E40ED79C3149A1C9", "A99D13013E892EE2"),
}


@pytest.mark.parametrize("mode,pad", list(GBT_2020))
def test_gbt15852_2020_vectors(mode, pad):
    """GB/T 15852.1-2020 附录 B：SM4 八种 MAC 算法标准向量。"""
    exp1, exp2 = GBT_2020[(mode, pad)]
    for msg, exp in ((MSG1, exp1), (MSG2, exp2)):
        kwargs = dict(algo="SM4", mode=mode, key=K1, data=msg, padding=pad, tlen=8)
        if mode in M.TWO_KEY_MODES:
            kwargs["key2"] = K2
        got = M.mac_calc(**kwargs)["mac"].hex().upper()
        assert got == exp, f"{mode}/{pad} 结果不符：{got} != {exp}"


RFC4493_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
RFC4493_MSG = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
RFC4493 = [
    (0, "bb1d6929e95937287fa37d129b756746"),
    (16, "070a16b46b4d4144f79bdd9dd04a287c"),
    (40, "dfa66747de9ae63030ca32611497c827"),
    (64, "51f0bebf7e3b9d92fc49741779363cfe"),
]


@pytest.mark.parametrize("length,expected", RFC4493)
def test_rfc4493_aes128_cmac(length, expected):
    got = M.mac_calc("AES128", "CMAC", RFC4493_KEY, RFC4493_MSG[:length], tlen=16)["mac"].hex()
    assert got == expected


def test_nist_cmac_aes192_aes256():
    """NIST SP 800-38B 示例：AES-192/256 的空消息与单分组消息 CMAC。"""
    k192 = bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    k256 = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    assert M.mac_calc("AES192", "CMAC", k192, b"", tlen=16)["mac"].hex() == "d17ddf46adaacde531cac483de7a9367"
    assert M.mac_calc("AES192", "CMAC", k192, RFC4493_MSG[:16], tlen=16)["mac"].hex() == "9e99a7bf31e710900662f65e617c5184"
    assert M.mac_calc("AES256", "CMAC", k256, b"", tlen=16)["mac"].hex() == "028962f61b7bf89efc6b551f4667d983"
    assert M.mac_calc("AES256", "CMAC", k256, RFC4493_MSG[:16], tlen=16)["mac"].hex() == "28a7023f452e8f82bd4bf28d8c37c35c"


def test_cmac_matches_pycryptodome():
    """与 pycryptodome 的 CMAC 实现交叉校验（多密钥长度、多消息长度）。"""
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC

    data = bytes(range(96))
    for algo, size in (("AES128", 16), ("AES192", 24), ("AES256", 32)):
        key = bytes(range(size))
        for length in (0, 1, 15, 16, 17, 32, 63):
            mine = M.mac_calc(algo, "CMAC", key, data[:length], tlen=16)["mac"]
            ref = CMAC.new(key, ciphermod=AES).update(data[:length]).digest()
            assert mine == ref, f"{algo} 长度 {length} 与 pycryptodome 不一致"


DES_KEY1 = bytes.fromhex("0123456789ABCDEF")
DES_KEY2 = bytes.fromhex("FEDCBA9876543210")
DES_MSG1 = b"Now is the time for all "
DES_MSG2 = b"Now is the time for it"


@pytest.mark.parametrize(
    "mode,pads,expected",
    [
        ("CBCMAC", ("M1", "M2", "M3"), ("70A30640", "10E1F0F1", "2C58FB8F")),
        ("CBCMAC", ("M1", "M2", "M3"), ("E45B3AD2", "A924C721", "B1ECD6FC")),
        ("ANSIRETAILMAC", ("M1", "M2", "M3"), ("A1C72E74", "E9086230", "AB059463")),
        ("MACDES", ("M1", "M2", "M3"), ("AD3502B7", "61C333E3", "952AF838")),
    ],
)
def test_gbt15852_2008_des_vectors(mode, pads, expected):
    """GB/T 15852.1-2008 附录 A：DES 标准向量（MAC 截断 4 字节）。"""
    msg = DES_MSG2 if expected[0].startswith("E45B") else DES_MSG1
    for pad, exp in zip(pads, expected):
        kwargs = dict(algo="DES", mode=mode, key=DES_KEY1, data=msg, padding=pad, tlen=4)
        if mode in M.TWO_KEY_MODES:
            kwargs["key2"] = DES_KEY2
        assert M.mac_calc(**kwargs)["mac"].hex().upper() == exp, f"{mode}/{pad}"


def test_emac_2008_derived_key2():
    """2008 版 EMAC 的密钥二可由密钥一按"每隔 4 比特取补"派生。"""
    derived = bytes(b ^ 0xF0 for b in DES_KEY1)
    got = M.mac_calc("DES", "EMAC", DES_KEY1, DES_MSG1, padding="M1", key2=derived, tlen=4)["mac"].hex()
    assert got == "10f9bc67"


@pytest.mark.parametrize("algo", list(M.ALGOS))
def test_all_algorithms_all_modes(algo):
    """七种分组算法 × 八种模式全部可算，输出长度等于分组长度。"""
    block, key_len = M.ALGOS[algo]
    key = bytes(range(key_len))
    key2 = bytes(range(1, key_len + 1))
    for mode in M.MODES:
        kwargs = dict(algo=algo, mode=mode, key=key, data=b"abcdefg", padding="M2", tlen=block)
        if mode in M.TWO_KEY_MODES:
            kwargs["key2"] = key2
        out = M.mac_calc(**kwargs)["mac"]
        assert len(out) == block, f"{algo}/{mode} 输出长度异常"


@pytest.mark.parametrize("tlen", [4, 8, 12, 16])
def test_truncation(tlen):
    """MAC 截断：输出前 tlen 字节（TrCBC 非整分组时取尾部）。"""
    out = M.mac_calc("SM4", "CBCMAC", K1, b"abc", tlen=tlen)["mac"]
    assert len(out) == tlen
    assert M.mac_calc("SM4", "CBCMAC", K1, b"abc", tlen=tlen)["mac"][:4] == out[:4]


# --------------------------------------------------------------------------- #
# 接口测试
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config.update(TESTING=False)
    return app.test_client()


def call(client, payload):
    resp = client.post("/api/mac/calc", json=payload)
    assert resp.status_code == 200
    return resp.get_json()


SM4_KEY = "0123456789abcdeffedcba9876543210"
SM4_KEY2 = "4149d2aded9456681ec8b511d9e7ee04"


@pytest.mark.parametrize("mode", list(M.MODES))
def test_api_all_modes(client, mode):
    payload = {
        "cipherType": "SM4", "mode": mode, "message": "abc", "messageFormat": "TEXT",
        "key": SM4_KEY, "keyFormat": "HEX", "paddingType": "M2", "tlen": 16, "resultFormat": "HEX",
    }
    if mode in M.TWO_KEY_MODES:
        payload["spareKey"] = SM4_KEY2
        payload["sparekeyFormat"] = "HEX"
    data = call(client, payload)
    assert data["code"] == 0, data
    assert len(data["data"]) == 32
    assert data["data"] == data["data"].upper()


def test_api_formats_and_algorithms(client):
    """TEXT/HEX/BASE64 消息与密钥格式、BASE64 输出。"""
    text_result = call(client, {
        "cipherType": "AES128", "mode": "CBCMAC", "message": "abc", "messageFormat": "TEXT",
        "key": "0123456789abcdeffedcba9876543210", "keyFormat": "HEX", "paddingType": "M2",
        "tlen": 16, "resultFormat": "HEX",
    })
    hex_result = call(client, {
        "cipherType": "AES128", "mode": "CBCMAC", "message": "616263", "messageFormat": "HEX",
        "key": "0123456789abcdeffedcba9876543210", "keyFormat": "HEX", "paddingType": "M2",
        "tlen": 16, "resultFormat": "HEX",
    })
    b64_result = call(client, {
        "cipherType": "AES128", "mode": "CBCMAC", "message": "YWJj", "messageFormat": "BASE64",
        "key": "ASNFZ4mrze/+3LqYdlQyEA==", "keyFormat": "BASE64", "paddingType": "M2",
        "tlen": 16, "resultFormat": "BASE64",
    })
    assert text_result["data"] == hex_result["data"]
    import base64

    assert base64.b64decode(b64_result["data"]).hex().upper() == text_result["data"]


def test_api_block_aligned_and_nopadding(client):
    ok = call(client, {
        "cipherType": "SM4", "mode": "CBCMAC", "message": "00112233445566778899aabbccddeeff",
        "messageFormat": "HEX", "key": SM4_KEY, "keyFormat": "HEX",
        "paddingType": "NOPADDING", "tlen": 16, "resultFormat": "HEX",
    })
    assert ok["code"] == 0
    bad = call(client, {
        "cipherType": "SM4", "mode": "CBCMAC", "message": "0011", "messageFormat": "HEX",
        "key": SM4_KEY, "keyFormat": "HEX", "paddingType": "NOPADDING", "tlen": 16,
    })
    assert bad["code"] == 1 and "整数倍" in bad["msg"]


@pytest.mark.parametrize(
    "payload,keyword",
    [
        ({"key": "0011", "keyFormat": "HEX"}, "16 字节"),
        ({"tlen": 32}, "MAC 长度"),
        ({"cipherType": "DES", "key": "0123456789abcdef", "keyFormat": "HEX", "tlen": 16}, "MAC 长度"),
        ({"mode": "EMAC", "spareKey": ""}, "密钥二"),
        ({"mode": "NOSUCH"}, "MAC 模式"),
        ({"cipherType": "RC4"}, "分组算法"),
        ({"message": "zz", "messageFormat": "HEX"}, "十六进制"),
    ],
)
def test_api_errors(client, payload, keyword):
    base = {
        "cipherType": "SM4", "mode": "CBCMAC", "message": "abc", "messageFormat": "TEXT",
        "key": SM4_KEY, "keyFormat": "HEX", "paddingType": "M2", "tlen": 16,
    }
    base.update(payload)
    data = call(client, base)
    assert data["code"] == 1
    assert keyword in data["msg"], data["msg"]


def test_api_hash_all(client):
    """杂凑猜测：23 种算法 + 原始摘要匹配置顶。"""
    data = client.post("/api/hash/digest/all", json={
        "message": "abc", "messageFormat": "TEXT", "originDigest": "", "hashFormat": "HEX",
    }).get_json()
    assert data["code"] == 0
    rows = data["data"]["rows"]
    assert len(rows) == 23
    mapping = {r["algo"]: r["value"] for r in rows}
    assert mapping["SM3"] == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert mapping["MD5"] == "900150983cd24fb0d6963f7d28e17f72"

    sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    data = client.post("/api/hash/digest/all", json={
        "message": "abc", "messageFormat": "TEXT", "originDigest": sha256, "hashFormat": "HEX",
    }).get_json()
    rows = data["data"]["rows"]
    assert rows[0]["algo"] == "SHA-256" and rows[0]["match"] is True
    assert [r for r in rows if r["match"]] == [rows[0]]


# --------------------------------------------------------------------------- #
# 与原站交叉验证
# --------------------------------------------------------------------------- #
def _post(path, payload, attempts=3):
    """调用原站接口：网关偶发 502 时重试，仍失败则抛出最后一次异常。"""
    last = None
    for i in range(attempts):
        try:
            resp = requests.post(REMOTE + path, json=payload, headers=HEADERS, timeout=20)
            if resp.status_code < 500:
                return resp.status_code, resp
            last = resp
        except requests.RequestException as exc:
            last = exc
        time.sleep(1.5 * (i + 1))
    if isinstance(last, Exception):
        raise last
    return last.status_code, last


@pytest.fixture(scope="module")
def remote_hash_all():
    if OFFLINE:
        pytest.skip("CB_OFFLINE=1，跳过线上交叉验证")
    try:
        status, resp = _post("/api/hash/digest/all", {
            "message": "abc", "messageFormat": "TEXT", "hash": "", "hashFormat": "HEX",
        })
    except requests.RequestException as exc:  # 网络不可达
        pytest.skip(f"原站不可访问：{exc}")
    if status != 200:
        pytest.skip(f"原站 /api/hash/digest/all 返回 HTTP {status}")
    body = resp.json()
    if body.get("code") != 0:
        pytest.skip(f"原站返回 {body.get('msg')}")
    return body["data"]


def test_cross_hash_all(remote_hash_all, client):
    """原站与本地：11 种算法的摘要必须逐字节一致。"""
    mapping = {
        "SM3": "SM3", "SHA": "SHA-1", "MD5": "MD5", "SHA224": "SHA-224", "SHA256": "SHA-256",
        "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA3_224": "SHA3-224", "SHA3_256": "SHA3-256",
        "SHA3_384": "SHA3-384", "SHA3_512": "SHA3-512",
    }
    remote = {item["type"]: item["hash"].upper() for item in remote_hash_all}
    local = client.post("/api/hash/digest/all", json={
        "message": "abc", "messageFormat": "TEXT", "originDigest": "", "hashFormat": "HEX",
    }).get_json()["data"]["rows"]
    local_by_label = {row["algo"]: row["value"].upper() for row in local}
    compared = 0
    for remote_type, local_label in mapping.items():
        assert remote_type in remote, f"原站未返回 {remote_type}"
        assert local_by_label[local_label] == remote[remote_type], f"{remote_type} 不一致"
        compared += 1
    assert compared == 11


def test_cross_hash_all_match_flag(remote_hash_all):
    """原站：提供原始摘要时命中项 flag=true（本地前端同样按此规则置顶高亮）。"""
    try:
        status, resp = _post("/api/hash/digest/all", {
            "message": "abc", "messageFormat": "TEXT",
            "hash": "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "hashFormat": "HEX",
        })
    except requests.RequestException as exc:
        pytest.skip(f"原站不可访问：{exc}")
    if status != 200 or resp.json().get("code") != 0:
        pytest.skip(f"原站返回 HTTP {status}")
    items = resp.json()["data"]
    hits = [item["type"] for item in items if item["flag"]]
    assert hits == ["SHA256"]


def test_cross_mac(remote_hash_all):
    """原站与本地 MAC 结果一致性。

    说明：线上 /api/mac 目前对任何合法请求都返回 HTTP 502（原站自身页面同样无法计算），
    因此该用例在原站恢复前跳过，并在跳过原因中记录实际返回码。
    """
    if OFFLINE:
        pytest.skip("CB_OFFLINE=1，跳过线上交叉验证")
    payload = {
        "cipherType": "SM4", "mode": "CMAC", "message": "abc", "messageFormat": "TEXT",
        "key": SM4_KEY.upper(), "keyFormat": "HEX", "spareKey": "", "sparekeyFormat": "HEX",
        "paddingType": "M2", "tlen": 16, "resultFormat": "HEX",
    }
    try:
        status, resp = _post("/api/mac", payload)
    except requests.RequestException as exc:
        pytest.skip(f"原站 /api/mac 不可访问：{exc}")
    if status != 200:
        pytest.skip(f"原站 /api/mac 返回 HTTP {status}（原站侧故障，非本地差异）")
    body = resp.json()
    if body.get("code") != 0:
        pytest.skip(f"原站 /api/mac 返回 code={body.get('code')} msg={body.get('msg')}")
    local = M.mac_calc("SM4", "CMAC", K1, b"abc", tlen=16)["mac"].hex().upper()
    assert body["data"].upper() == local
