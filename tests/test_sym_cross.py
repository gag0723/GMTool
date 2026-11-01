"""与原站 https://cipher.huijusa.cn 的交叉验证（需要联网，离线自动跳过）。

对每个 action 用相同输入分别调用「原站接口」和「本地接口」，逐字节比较结果：

* 确定性输出（分组密码密文、ZUC 密钥流/MAC、GCM 密文与标签）：直接比较（HEX 忽略大小写）。
* 随机性输出（ISO10126 填充、原站的 ANSI X9.23 使用随机填充字节）：改为
  「原站加密 → 本地解密」「本地加密 → 原站解密」的双向交叉验证。

运行： cd /opt/cipherbox && .venv/bin/python -m pytest tests/test_sym_cross.py -q
跳过： CB_SKIP_CROSS=1（或网络不可用）
"""
from __future__ import annotations

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ORIGIN = os.environ.get("CB_ORIGIN", "https://cipher.huijusa.cn")
TIMEOUT = 20

requests = pytest.importorskip("requests")


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _origin_post(path: str, payload: dict) -> dict:
    """调用原站接口，最多重试 3 次（原站偶发 502）。"""
    last = None
    for _ in range(3):
        try:
            resp = requests.post(ORIGIN + path, json=payload, timeout=TIMEOUT,
                                 headers={"Content-Type": "application/json"})
            data = resp.json()
            if isinstance(data, dict) and data.get("code") in (0, 1, 500):
                return data
            if isinstance(data, dict) and data.get("status") == 400:
                # 原站参数枚举不接受（如 GB/T 17964 的 M2 / M3 填充）
                return {"code": 400, "msg": data.get("error", "Bad Request")}
            last = f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as err:  # noqa: BLE001 - 网络异常统一记录
            last = repr(err)
        time.sleep(1.0)
    raise AssertionError(f"原站接口不可用：{path} -> {last}")


def _local_post(client, path: str, payload: dict) -> dict:
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    return resp.get_json()


def _probe() -> bool:
    if os.environ.get("CB_SKIP_CROSS"):
        return False
    for _ in range(2):
        try:
            resp = requests.get(ORIGIN + "/api/health", timeout=6)
            return resp.status_code < 500
        except Exception:  # noqa: BLE001
            pass
    try:
        resp = requests.post(ORIGIN + "/api/cipher/encrypt", json={
            "type": "SM4", "mode": "ECB", "padding": "NOPADDING", "message": PT16,
            "messageFormat": "HEX", "cipherFormat": "HEX", "key": SM4_KEY, "keyFormat": "HEX",
        }, timeout=8)
        return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


_ONLINE = _probe()
pytestmark = pytest.mark.skipif(
    not _ONLINE,
    reason="原站不可达或已设置 CB_SKIP_CROSS，跳过交叉验证",
)


@pytest.fixture(scope="module")
def client():
    from app.server import create_app

    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def cross(client, origin_path: str, payload: dict) -> tuple[dict, dict]:
    """同一份 payload 同时打原站与本地接口。"""
    local_path = origin_path.replace("/api/cipher", "/api/sym")
    remote = _origin_post(origin_path, payload)
    local = _local_post(client, local_path, payload)
    return remote, local


def norm(value):
    """数值统一成大写 HEX / 结构比较。"""
    if isinstance(value, str):
        return value.upper()
    if isinstance(value, dict):
        return {k: norm(v) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# 用例数据
# ---------------------------------------------------------------------------

SM4_KEY = "0123456789ABCDEFFEDCBA9876543210"
IV16 = "000102030405060708090A0B0C0D0E0F"
IV8 = "0001020304050607"
PT16 = "6162636465666768696A6B6C6D6E6F70"

ALGOS = [
    ("SM4", SM4_KEY, IV16),
    ("AES128", "000102030405060708090A0B0C0D0E0F", IV16),
    ("AES192", "000102030405060708090A0B0C0D0E0F1011121314151617", IV16),
    ("AES256", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", IV16),
    ("DES", "0123456789ABCDEF", IV8),
    ("DESEDE16", "0123456789ABCDEFFEDCBA9876543210", IV8),
    ("DESEDE24", "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF", IV8),
]


# ---------------------------------------------------------------------------
# 分组密码：确定性输出对比
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algo,key,iv", ALGOS, ids=[a[0] for a in ALGOS])
@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR", "OFB", "CFB"])
@pytest.mark.parametrize("padding", ["PKCS7", "ISO7816_4", "ZERO"])
def test_group_encrypt_matches(client, algo, key, iv, mode, padding):
    payload = {
        "type": algo, "mode": mode, "padding": padding,
        "message": "616263", "messageFormat": "HEX",
        "cipherFormat": "HEX", "key": key, "keyFormat": "HEX",
        "iv": "" if mode == "ECB" else iv, "ivFormat": "HEX",
    }
    remote, local = cross(client, "/api/cipher/encrypt", payload)
    assert remote["code"] == 0, f"原站失败：{remote}"
    assert local["code"] == 0, f"本地失败：{local}"
    assert norm(local["data"]) == norm(remote["data"]), (
        f"{algo}/{mode}/{padding} 密文不一致\n原站={remote['data']}\n本地={local['data']}"
    )


@pytest.mark.parametrize("algo,key,iv", ALGOS, ids=[a[0] for a in ALGOS])
@pytest.mark.parametrize("mode", ["ECB", "CBC", "CTR", "OFB", "CFB"])
def test_group_decrypt_matches(client, algo, key, iv, mode):
    """原站加密的密文，本地必须能解出相同明文；反之亦然。"""
    enc = {
        "type": algo, "mode": mode, "padding": "PKCS7",
        "message": PT16, "messageFormat": "HEX", "cipherFormat": "HEX",
        "key": key, "keyFormat": "HEX", "iv": "" if mode == "ECB" else iv, "ivFormat": "HEX",
    }
    remote_enc, local_enc = cross(client, "/api/cipher/encrypt", enc)
    assert remote_enc["code"] == 0 and local_enc["code"] == 0
    assert norm(remote_enc["data"]) == norm(local_enc["data"])

    dec = {
        "type": algo, "mode": mode, "padding": "PKCS7",
        "cipher": remote_enc["data"], "cipherFormat": "HEX", "messageFormat": "HEX",
        "key": key, "keyFormat": "HEX", "iv": "" if mode == "ECB" else iv, "ivFormat": "HEX",
    }
    remote_dec, local_dec = cross(client, "/api/cipher/decrypt", dec)
    assert remote_dec["code"] == 0 and local_dec["code"] == 0
    assert norm(local_dec["data"]) == norm(remote_dec["data"]) == PT16


@pytest.mark.parametrize("padding", ["PKCS7", "ISO7816_4", "ZERO", "NOPADDING", "M2", "M3"])
def test_group_padding_vectors(client, padding):
    payload = {
        "type": "SM4", "mode": "ECB", "padding": padding,
        "message": PT16 if padding == "NOPADDING" else "61",
        "messageFormat": "HEX", "cipherFormat": "HEX",
        "key": SM4_KEY, "keyFormat": "HEX", "iv": "", "ivFormat": "HEX",
    }
    remote, local = cross(client, "/api/cipher/encrypt", payload)
    if remote["code"] != 0:
        # 原站未实现 GB/T 17964 的 M2 / M3（枚举校验直接 400），只记录不比对
        assert padding in ("M2", "M3"), f"原站异常：{remote}"
        assert local["code"] == 0, local
        return
    assert local["code"] == 0, local
    assert norm(local["data"]) == norm(remote["data"]), (
        f"{padding} 密文不一致\n原站={remote['data']}\n本地={local['data']}"
    )


@pytest.mark.parametrize("padding", ["ISO_10126", "ANSIX923"])
def test_group_random_padding_cross_roundtrip(client, padding):
    """原站这两个填充会写入随机字节（不满足标准），因此用双向解密校验。"""
    enc = {
        "type": "SM4", "mode": "ECB", "padding": padding,
        "message": "6162636465666768", "messageFormat": "HEX", "cipherFormat": "HEX",
        "key": SM4_KEY, "keyFormat": "HEX", "iv": "", "ivFormat": "HEX",
    }
    remote, local = cross(client, "/api/cipher/encrypt", enc)
    assert remote["code"] == 0 and local["code"] == 0

    # 原站密文 → 本地解密
    dec_remote = {
        "type": "SM4", "mode": "ECB", "padding": padding,
        "cipher": remote["data"], "cipherFormat": "HEX", "messageFormat": "HEX",
        "key": SM4_KEY, "keyFormat": "HEX", "iv": "", "ivFormat": "HEX",
    }
    _, local_dec = cross(client, "/api/cipher/decrypt", dec_remote)
    assert local_dec["code"] == 0 and norm(local_dec["data"]) == enc["message"], local_dec

    # 本地密文 → 原站解密
    dec_local = dict(dec_remote, cipher=local["data"])
    remote_dec, _ = cross(client, "/api/cipher/decrypt", dec_local)
    assert remote_dec["code"] == 0 and norm(remote_dec["data"]) == enc["message"], remote_dec


# ---------------------------------------------------------------------------
# XTS
# ---------------------------------------------------------------------------


XTS_KEY = SM4_KEY + "FEDCBA98765432100123456789ABCDEF"


@pytest.mark.parametrize("is_gb", [True, False], ids=["GB", "IEEE"])
@pytest.mark.parametrize("length", [16, 32, 34, 64])
def test_xts_matches(client, is_gb, length):
    msg = (PT16 * 4)[: length * 2]
    payload = {
        "type": "SM4", "message": msg, "messageFormat": "HEX", "cipherFormat": "HEX",
        "key": XTS_KEY, "keyFormat": "HEX",
        "tweak": "000102030405060708090A0B0C0D0E0F", "tweakFormat": "HEX",
        "isGB": is_gb,
    }
    remote, local = cross(client, "/api/cipher/xts/encrypt", payload)
    assert remote["code"] == 0 and local["code"] == 0, (remote, local)
    assert norm(local["data"]) == norm(remote["data"]), (
        f"XTS(isGB={is_gb}, len={length}) 不一致\n原站={remote['data']}\n本地={local['data']}"
    )

    dec = dict(payload)
    dec.pop("message")
    dec.update({"cipher": remote["data"], "messageFormat": "HEX"})
    remote_dec, local_dec = cross(client, "/api/cipher/xts/decrypt", dec)
    assert remote_dec["code"] == 0 and local_dec["code"] == 0
    assert norm(local_dec["data"]) == norm(remote_dec["data"]) == norm(msg)


# ---------------------------------------------------------------------------
# ZUC
# ---------------------------------------------------------------------------

ZUC128_KEY = "0123456789ABCDEFFEDCBA9876543210"
ZUC128_IV = "000102030405060708090A0B0C0D0E0F"
ZUC256_KEY = "0123456789ABCDEFFEDCBA9876543210" "FEDCBA98765432100123456789ABCDEF"
ZUC256_IV = "000102030405060708090A0B0C0D0E0F" "101112131415161718"


@pytest.mark.parametrize("algo,key,iv", [
    ("ZUC128", ZUC128_KEY, ZUC128_IV),
    ("ZUC256", ZUC256_KEY, ZUC256_IV),
], ids=["ZUC128", "ZUC256"])
@pytest.mark.parametrize("message", ["00000000", "6162636465666768696A", "00" * 40])
def test_zuc_encrypt_decrypt_matches(client, algo, key, iv, message):
    payload = {
        "type": algo, "message": message, "messageFormat": "HEX", "resultFormat": "HEX",
        "key": key, "keyFormat": "HEX", "iv": iv, "ivFormat": "HEX",
    }
    remote, local = cross(client, "/api/cipher/zuc/encrypt", payload)
    assert remote["code"] == 0 and local["code"] == 0, (remote, local)
    assert norm(local["data"]) == norm(remote["data"]), (
        f"{algo} 加密不一致\n原站={remote['data']}\n本地={local['data']}"
    )

    dec = {
        "type": algo, "result": remote["data"], "resultFormat": "HEX", "messageFormat": "HEX",
        "key": key, "keyFormat": "HEX", "iv": iv, "ivFormat": "HEX",
    }
    remote_dec, local_dec = cross(client, "/api/cipher/zuc/decrypt", dec)
    assert remote_dec["code"] == 0 and local_dec["code"] == 0
    assert norm(local_dec["data"]) == norm(remote_dec["data"]) == norm(message)


@pytest.mark.parametrize("algo,key,iv,mac_len", [
    ("ZUC128", ZUC128_KEY, ZUC128_IV, 4),
    ("ZUC256", ZUC256_KEY, ZUC256_IV, 4),
    ("ZUC256", ZUC256_KEY, ZUC256_IV, 8),
    ("ZUC256", ZUC256_KEY, ZUC256_IV, 16),
])
@pytest.mark.parametrize("message", ["00000000", "0000000000", "6162636465666768696A6B6C6D6E6F7071727374"])
def test_zuc_mac_matches(client, algo, key, iv, mac_len, message):
    payload = {
        "type": algo, "message": message, "messageFormat": "HEX", "resultFormat": "HEX",
        "key": key, "keyFormat": "HEX", "iv": iv, "ivFormat": "HEX", "macLength": mac_len,
    }
    remote, local = cross(client, "/api/cipher/zuc/mac", payload)
    assert remote["code"] == 0 and local["code"] == 0, (remote, local)
    assert norm(local["data"]) == norm(remote["data"]), (
        f"{algo} MAC({mac_len}B) 不一致\n原站={remote['data']}\n本地={local['data']}"
    )


# ---------------------------------------------------------------------------
# GCM
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algo,key", [
    ("SM4", SM4_KEY),
    ("AES128", "000102030405060708090A0B0C0D0E0F"),
    ("AES256", "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
], ids=["SM4", "AES128", "AES256"])
@pytest.mark.parametrize("tag_len", [4, 8, 16])
@pytest.mark.parametrize("aad,msg", [("", "616263"), ("AABBCC", "6162636465666768")])
def test_gcm_matches(client, algo, key, tag_len, aad, msg):
    payload = {
        "type": algo, "message": msg, "messageFormat": "HEX", "resultFormat": "HEX",
        "key": key, "keyFormat": "HEX", "iv": IV16, "ivFormat": "HEX",
        "aad": aad, "aadFormat": "HEX", "tagLength": tag_len, "tagFormat": "HEX",
    }
    remote, local = cross(client, "/api/cipher/gcm/encrypt", payload)
    assert remote["code"] == 0 and local["code"] == 0, (remote, local)
    assert norm(local["data"]["cipher"]) == norm(remote["data"]["cipher"]), (
        f"{algo} GCM 密文不一致\n原站={remote['data']}\n本地={local['data']}"
    )
    assert norm(local["data"]["tag"]) == norm(remote["data"]["tag"]), (
        f"{algo} GCM Tag 不一致（tag_len={tag_len}）\n原站={remote['data']}\n本地={local['data']}"
    )

    dec = {
        "type": algo, "result": remote["data"]["cipher"], "resultFormat": "HEX",
        "messageFormat": "HEX", "key": key, "keyFormat": "HEX",
        "iv": IV16, "ivFormat": "HEX", "aad": aad, "aadFormat": "HEX",
        "tag": remote["data"]["tag"], "tagFormat": "HEX", "tagLength": tag_len,
    }
    remote_dec, local_dec = cross(client, "/api/cipher/gcm/decrypt", dec)
    assert remote_dec["code"] == 0 and local_dec["code"] == 0, (remote_dec, local_dec)
    assert norm(local_dec["data"]) == norm(remote_dec["data"]) == norm(msg)


def test_gcm_tag_failure_matches(client):
    """篡改标签时双方都必须报错（错误文案不同，仅校验失败行为）。"""
    enc = {
        "type": "SM4", "message": "616263", "messageFormat": "HEX", "resultFormat": "HEX",
        "key": SM4_KEY, "keyFormat": "HEX", "iv": IV16, "ivFormat": "HEX",
        "aad": "", "aadFormat": "HEX", "tagLength": 16, "tagFormat": "HEX",
    }
    remote, local = cross(client, "/api/cipher/gcm/encrypt", enc)
    assert remote["code"] == 0 and local["code"] == 0
    dec = {
        "type": "SM4", "result": remote["data"]["cipher"], "resultFormat": "HEX",
        "messageFormat": "HEX", "key": SM4_KEY, "keyFormat": "HEX",
        "iv": IV16, "ivFormat": "HEX", "aad": "", "aadFormat": "HEX",
        "tag": "00" * 16, "tagFormat": "HEX", "tagLength": 16,
    }
    remote_dec, local_dec = cross(client, "/api/cipher/gcm/decrypt", dec)
    assert remote_dec["code"] != 0, remote_dec
    assert local_dec["code"] != 0, local_dec
    assert "认证标签校验不通过" in local_dec["msg"]
