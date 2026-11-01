"""其他常用工具：密文长度分析 / 大数运算 / 取模运算 / 逻辑运算 / 字节逆序。

包含与原站（https://cipher.huijusa.cn）的交叉验证：同一输入比对 HEX 输出
（大小写归一）。远端不可达时自动 skip，并记录原因。
"""
from __future__ import annotations

import os
import time

import pytest
import requests

from app.server import create_app

BASE = "https://cipher.huijusa.cn/api"
TIMEOUT = 20
SKIP_REMOTE = os.environ.get("CB_SKIP_REMOTE") == "1"


@pytest.fixture()
def client():
    return create_app().test_client()


def call(client, path, payload):
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    return resp.get_json()


def ok_data(client, path, payload):
    body = call(client, path, payload)
    assert body["code"] == 0, body
    return body["data"]


def remote_post(path, payload):
    """调用原站接口；网络不可用/网关错误返回 None。"""
    last = None
    for _ in range(4):
        try:
            resp = requests.post(BASE + path, json=payload, timeout=TIMEOUT)
            if resp.status_code == 200 and resp.text.strip().startswith("{"):
                body = resp.json()
                if body.get("code") == 0:
                    return body.get("data")
                return None
        except requests.RequestException as exc:  # 网关 502 / 超时
            last = exc
        time.sleep(0.8)
    if last is not None:
        return None
    return None


# ---------------------------------------------------------------------------
# 密文长度分析
# ---------------------------------------------------------------------------

def test_length_table_hash(client):
    data = ok_data(client, "/api/other/length/table", {"type": "HASH"})
    names = [row["name"] for row in data["rows"]]
    for algo in ("SM3", "SHA256", "SHA512", "SHA3-256", "MD5", "SHA1"):
        assert algo in names
    assert data["total"] == 13
    sm3 = next(r for r in data["rows"] if r["name"] == "SM3")
    assert sm3["lengthBits"] == 256 and sm3["strength"] == 128
    assert sm3["length"] == "256 位 / 32 字节"


def test_length_table_symmetric_and_asymmetric(client):
    sym = ok_data(client, "/api/other/length/table", {"type": "SYMMETRIC"})
    sm4 = next(r for r in sym["rows"] if r["name"] == "SM4")
    assert sm4["lengthBits"] == 128 and sm4["strength"] == 128
    des = next(r for r in sym["rows"] if r["name"] == "DES")
    assert des["lengthBits"] == 64 and des["strength"] == 56
    stream = next(r for r in sym["rows"] if r["name"] == "ZUC-128")
    assert stream["stream"] is True

    asym = ok_data(client, "/api/other/length/table", {"type": "3"})
    rsa = next(r for r in asym["rows"] if r["name"] == "RSA-2048-ENC")
    assert rsa["lengthBits"] == 2048 and rsa["strength"] == 112
    assert any(r["name"] == "SM2-ENC" for r in asym["rows"])
    assert any(r["name"] == "SM9-ENC" for r in asym["rows"])
    assert any(r["name"] == "RSA-4096-ENC" for r in asym["rows"])


def test_length_table_bad_group(client):
    body = call(client, "/api/other/length/table", {"type": "XYZ"})
    assert body["code"] == 1 and "分组" in body["msg"]


def test_length_analyze_matches(client):
    data = ok_data(client, "/api/other/length/analyze", {"message": "00" * 32, "messageFormat": "HEX"})
    assert data["bits"] == 256 and data["bytes"] == 32
    hash_names = {row["name"] for row in data["hash"]}
    assert {"SM3", "SHA256", "SHA3-256"} <= hash_names
    sym_names = {row["name"] for row in data["symmetric"]}
    assert {"SM4", "AES-128", "AES-192", "AES-256"} <= sym_names
    # 256 位不是 RSA 的模长，非对称应为空
    assert data["asymmetric"] == []


def test_length_analyze_stream_and_block(client):
    short = ok_data(client, "/api/other/length/analyze", {"message": "00" * 5, "messageFormat": "HEX"})
    # 40 位：只有流密码命中，分组密码无法整除
    assert {row["name"] for row in short["symmetric"]} == {"RC4", "ChaCha20", "ZUC-128", "ZUC-256", "Salsa20"}
    assert short["hash"] == []

    rsa = ok_data(client, "/api/other/length/analyze", {"message": "00" * 256, "messageFormat": "HEX"})
    assert "RSA-2048-ENC" in {row["name"] for row in rsa["asymmetric"]}


def test_length_analyze_empty(client):
    body = call(client, "/api/other/length/analyze", {"message": "", "messageFormat": "HEX"})
    assert body["code"] == 1


def test_length_alias_routes(client):
    via_get = client.get("/api/other/query/cipher/length?type=1").get_json()
    assert via_get["code"] == 0 and via_get["data"]["total"] == 13
    via_post = call(client, "/api/other/query/cipher", {"message": "00" * 16, "messageFormat": "HEX"})
    assert via_post["code"] == 0 and via_post["data"]["bits"] == 128


# ---------------------------------------------------------------------------
# 大数运算
# ---------------------------------------------------------------------------

def test_big_add_sub(client):
    add = ok_data(client, "/api/other/big/number",
                  {"type": "add", "s1": "FF", "s1Format": "HEX", "s2": "01", "s2Format": "HEX"})
    assert add["result"] == "0100" and add["bytes"] == 2
    # 最高位为 1 的正数按 BigInteger.toByteArray 语义前置 0x00（与原站一致）
    high = ok_data(client, "/api/other/big/number",
                   {"type": "add", "s1": "80", "s1Format": "HEX", "s2": "00", "s2Format": "HEX"})
    assert high["result"] == "0080"
    sub = ok_data(client, "/api/other/big/number",
                  {"type": "sub", "s1": "10", "s1Format": "HEX", "s2": "01", "s2Format": "HEX"})
    assert sub["result"] == "0F"


def test_big_sub_negative_twos_complement(client):
    neg1 = ok_data(client, "/api/other/big/number",
                   {"type": "sub", "s1": "01", "s1Format": "HEX", "s2": "03", "s2Format": "HEX"})
    assert neg1["result"] == "FE"
    neg128 = ok_data(client, "/api/other/big/number",
                     {"type": "sub", "s1": "01", "s1Format": "HEX", "s2": "81", "s2Format": "HEX"})
    assert neg128["result"] == "80"
    neg129 = ok_data(client, "/api/other/big/number",
                     {"type": "sub", "s1": "01", "s1Format": "HEX", "s2": "82", "s2Format": "HEX"})
    assert neg129["result"] == "FF7F"


def test_big_mul_div_mod_pow(client):
    mul = ok_data(client, "/api/other/big/number",
                  {"type": "mul", "s1": "0100", "s1Format": "HEX", "s2": "0100", "s2Format": "HEX"})
    assert mul["result"] == "010000"
    div = ok_data(client, "/api/other/big/number",
                  {"type": "div", "s1": "0A", "s1Format": "HEX", "s2": "03", "s2Format": "HEX"})
    assert div["result"] == "03"
    mod = ok_data(client, "/api/other/big/number",
                  {"type": "mod", "s1": "0A", "s1Format": "HEX", "s2": "03", "s2Format": "HEX"})
    assert mod["result"] == "01"
    pw = ok_data(client, "/api/other/big/number",
                 {"type": "pow", "s1": "02", "s1Format": "HEX", "s2": "08", "s2Format": "HEX"})
    assert pw["decimal"] == "256" and pw["result"] == "0100"


def test_big_bit_ops_and_compare(client):
    cmp_less = ok_data(client, "/api/other/big/number",
                       {"type": "cmp", "s1": "01", "s1Format": "HEX", "s2": "02", "s2Format": "HEX"})
    assert cmp_less["compare"] == -1 and cmp_less["result"] == "A < B"
    shl = ok_data(client, "/api/other/big/number",
                  {"type": "shl", "s1": "01", "s1Format": "HEX", "s2": "04", "s2Format": "HEX"})
    assert shl["result"] == "10"
    shr = ok_data(client, "/api/other/big/number",
                  {"type": "shr", "s1": "10", "s1Format": "HEX", "s2": "04", "s2Format": "HEX"})
    assert shr["result"] == "01"
    band = ok_data(client, "/api/other/big/number",
                   {"type": "and", "s1": "F0", "s1Format": "HEX", "s2": "3C", "s2Format": "HEX"})
    assert band["result"] == "30"
    # 大数工具按补码语义输出：0xFF 最高位为 1，前置 0x00
    bor = ok_data(client, "/api/other/big/number",
                  {"type": "or", "s1": "F0", "s1Format": "HEX", "s2": "0F", "s2Format": "HEX"})
    assert bor["result"] == "00FF"
    bxor = ok_data(client, "/api/other/big/number",
                   {"type": "xor", "s1": "F0", "s1Format": "HEX", "s2": "FF", "s2Format": "HEX"})
    assert bxor["result"] == "0F"


def test_big_base64_io(client):
    data = ok_data(client, "/api/other/big/number",
                   {"type": "add", "s1": "AQ==", "s1Format": "BASE64",
                    "s2": "Ag==", "s2Format": "BASE64", "resultFormat": "BASE64"})
    assert data["result"] == "Aw=="
    dec = ok_data(client, "/api/other/big/number",
                  {"type": "add", "s1": "FF", "s1Format": "HEX", "s2": "01", "s2Format": "HEX",
                   "resultFormat": "DEC"})
    assert dec["result"] == "256"


def test_big_errors(client):
    assert call(client, "/api/other/big/number",
                {"type": "add", "s1": "", "s1Format": "HEX", "s2": "01", "s2Format": "HEX"})["code"] == 1
    assert call(client, "/api/other/big/number",
                {"type": "div", "s1": "01", "s1Format": "HEX", "s2": "00", "s2Format": "HEX"})["code"] == 1
    assert call(client, "/api/other/big/number",
                {"type": "add", "s1": "zz", "s1Format": "HEX", "s2": "01", "s2Format": "HEX"})["code"] == 1
    assert call(client, "/api/other/big/number",
                {"type": "unknown", "s1": "01", "s1Format": "HEX", "s2": "01", "s2Format": "HEX"})["code"] == 1
    big_exp = call(client, "/api/other/big/number",
                   {"type": "pow", "s1": "02", "s1Format": "HEX", "s2": "FFFFFF", "s2Format": "HEX"})
    assert big_exp["code"] == 1 and "指数" in big_exp["msg"]


# ---------------------------------------------------------------------------
# 取模运算
# ---------------------------------------------------------------------------

def test_mod_ops(client):
    add = ok_data(client, "/api/other/mod/number",
                  {"type": "add", "s1": "0A", "s1Format": "HEX", "s2": "06",
                   "s2Format": "HEX", "p1": "07", "p1Format": "HEX"})
    assert add["result"] == "02"
    sub = ok_data(client, "/api/other/mod/number",
                  {"type": "sub", "s1": "03", "s1Format": "HEX", "s2": "06",
                   "s2Format": "HEX", "p1": "07", "p1Format": "HEX"})
    assert sub["result"] == "04"
    mul = ok_data(client, "/api/other/mod/number",
                  {"type": "mul", "s1": "06", "s1Format": "HEX", "s2": "06",
                   "s2Format": "HEX", "p1": "07", "p1Format": "HEX"})
    assert mul["result"] == "01"


def test_mod_pow_known_vector(client):
    # 3^200 mod 0x0B (11) —— 费马小定理：3^10 ≡ 1 (mod 11)，200 = 10*20
    data = ok_data(client, "/api/other/mod/number",
                   {"type": "pow", "s1": "03", "s1Format": "HEX", "s2": "C8",
                    "s2Format": "HEX", "p1": "0B", "p1Format": "HEX"})
    assert data["decimal"] == "1"
    # 2^10 mod 1000 = 24
    data2 = ok_data(client, "/api/other/mod/number",
                    {"type": "pow", "s1": "02", "s1Format": "HEX", "s2": "0A",
                     "s2Format": "HEX", "p1": "03E8", "p1Format": "HEX"})
    assert data2["decimal"] == "24"


def test_mod_p_one_returns_zero(client):
    data = ok_data(client, "/api/other/mod/number",
                   {"type": "add", "s1": "0A", "s1Format": "HEX", "s2": "06",
                    "s2Format": "HEX", "p1": "01", "p1Format": "HEX"})
    assert data["result"] == "00"
    body = call(client, "/api/other/mod/number",
                {"type": "add", "s1": "0A", "s1Format": "HEX", "s2": "06",
                 "s2Format": "HEX", "p1": "00", "p1Format": "HEX"})
    assert body["code"] == 1 and "模数" in body["msg"]


# ---------------------------------------------------------------------------
# 逻辑运算
# ---------------------------------------------------------------------------

def test_logic_ops(client):
    and_ = ok_data(client, "/api/other/xor",
                   {"type": "AND", "s1": "F0F0", "s1Format": "HEX", "s2": "0FF0", "s2Format": "HEX"})
    assert and_["result"] == "00F0"
    or_ = ok_data(client, "/api/other/xor",
                  {"type": "OR", "s1": "F0F0", "s1Format": "HEX", "s2": "0FF0", "s2Format": "HEX"})
    assert or_["result"] == "FFF0"
    xor = ok_data(client, "/api/other/xor",
                  {"type": "XOR", "s1": "F0F0", "s1Format": "HEX", "s2": "0FF0", "s2Format": "HEX"})
    assert xor["result"] == "FF00"
    not_ = ok_data(client, "/api/other/xor",
                   {"type": "NOT", "s1": "F0F0", "s1Format": "HEX", "s2": "", "s2Format": "HEX"})
    assert not_["result"] == "0F0F"


def test_logic_left_pad_shorter_operand(client):
    """长度不一致时较短一方左侧补 0（与原站一致）。"""
    data = ok_data(client, "/api/other/xor",
                   {"type": "AND", "s1": "0F", "s1Format": "HEX", "s2": "F0F0", "s2Format": "HEX"})
    assert data["result"] == "0000" and data["bytes"] == 2
    tail = ok_data(client, "/api/other/xor",
                   {"type": "OR", "s1": "0F", "s1Format": "HEX", "s2": "F0F0", "s2Format": "HEX"})
    assert tail["result"] == "F0FF"


def test_logic_errors(client):
    assert call(client, "/api/other/xor", {"type": "AND", "s1": "", "s1Format": "HEX"})["code"] == 1
    assert call(client, "/api/other/xor", {"type": "AND", "s1": "0F", "s1Format": "HEX"})["code"] == 1
    assert call(client, "/api/other/xor", {"type": "NAND", "s1": "0F", "s1Format": "HEX"})["code"] == 1


# ---------------------------------------------------------------------------
# 字节逆序
# ---------------------------------------------------------------------------

def test_byte_reverse_all(client):
    data = ok_data(client, "/api/other/byte/reverse", {"s1": "0102030405", "s1Format": "HEX"})
    assert data["result"] == "0504030201"


def test_byte_reverse_groups(client):
    g2 = ok_data(client, "/api/other/byte/reverse",
                 {"s1": "0102030405060708", "s1Format": "HEX", "mode": "2"})
    assert g2["result"] == "0201040306050807"
    g4 = ok_data(client, "/api/other/byte/reverse",
                 {"s1": "0102030405060708", "s1Format": "HEX", "mode": "4"})
    assert g4["result"] == "0403020108070605"
    g8 = ok_data(client, "/api/other/byte/reverse",
                 {"s1": "0102030405060708", "s1Format": "HEX", "mode": "8"})
    assert g8["result"] == "0807060504030201"


def test_byte_reverse_errors(client):
    body = call(client, "/api/other/byte/reverse", {"s1": "010203", "s1Format": "HEX", "mode": "4"})
    assert body["code"] == 1 and "整数倍" in body["msg"]
    assert call(client, "/api/other/byte/reverse", {"s1": "", "s1Format": "HEX"})["code"] == 1
    assert call(client, "/api/other/byte/reverse", {"s1": "0102", "s1Format": "HEX", "mode": "3"})["code"] == 1


# ---------------------------------------------------------------------------
# 与原站交叉验证
# ---------------------------------------------------------------------------

@pytest.mark.skipif(SKIP_REMOTE, reason="CB_SKIP_REMOTE=1，跳过远端交叉验证")
def test_cross_check_math_and_mod(client):
    """同一输入下本地结果与原站一致（HEX 大小写归一）。"""
    cases = [
        ("/api/other/big/number", "/other/math",
         {"type": "add", "s1": "FF", "s1Format": "HEX", "s2": "01", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/api/other/big/number", "/other/math",
         {"type": "add", "s1": "80", "s1Format": "HEX", "s2": "00", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/api/other/big/number", "/other/math",
         {"type": "sub", "s1": "01", "s1Format": "HEX", "s2": "82", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/api/other/big/number", "/other/math",
         {"type": "mul", "s1": "0100", "s1Format": "HEX", "s2": "0100", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/api/other/mod/number", "/other/mod",
         {"type": "sub", "s1": "03", "s1Format": "HEX", "s2": "06", "s2Format": "HEX",
          "p1": "07", "p1Format": "HEX", "resultFormat": "HEX"}),
        ("/api/other/mod/number", "/other/mod",
         {"type": "mul", "s1": "DEB9CA0D1EB4", "s1Format": "HEX", "s2": "D0", "s2Format": "HEX",
          "p1": "DA", "p1Format": "HEX", "resultFormat": "HEX"}),
    ]
    compared = 0
    for local_path, remote_path, payload in cases:
        remote = remote_post(remote_path, payload)
        if remote is None:
            continue
        local = ok_data(client, local_path, payload)["result"]
        assert str(local).upper() == str(remote).upper(), (local_path, payload, local, remote)
        compared += 1
    if compared == 0:
        pytest.skip("原站不可达（网关 502 / 超时），本次跳过交叉验证")


@pytest.mark.skipif(SKIP_REMOTE, reason="CB_SKIP_REMOTE=1，跳过远端交叉验证")
def test_cross_check_logic_and_reverse(client):
    cases = [
        ("/other/xor", {"type": "AND", "s1": "F0F0", "s1Format": "HEX", "s2": "0FF0", "s2Format": "HEX", "resultFormat": "HEX"},
         {"type": "AND", "s1": "F0F0", "s1Format": "HEX", "s2": "0FF0", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/other/xor", {"type": "OR", "s1": "0F", "s1Format": "HEX", "s2": "F0F0", "s2Format": "HEX", "resultFormat": "HEX"},
         {"type": "OR", "s1": "0F", "s1Format": "HEX", "s2": "F0F0", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/other/xor", {"type": "NOT", "s1": "F0F0", "s1Format": "HEX", "s2": "", "s2Format": "HEX", "resultFormat": "HEX"},
         {"type": "NOT", "s1": "F0F0", "s1Format": "HEX", "s2": "", "s2Format": "HEX", "resultFormat": "HEX"}),
        ("/other/byte/reverse", {"s1": "0102030405", "s1Format": "HEX", "resultFormat": "HEX"},
         {"s1": "0102030405", "s1Format": "HEX", "resultFormat": "HEX"}),
    ]
    compared = 0
    for remote_path, remote_payload, local_payload in cases:
        remote = remote_post(remote_path, remote_payload)
        if remote is None:
            continue
        local = ok_data(client, "/api/other/xor" if "xor" in remote_path else "/api/other/byte/reverse",
                        local_payload)["result"]
        assert str(local).upper() == str(remote).upper(), (remote_path, local, remote)
        compared += 1
    if compared == 0:
        pytest.skip("原站不可达（网关 502 / 超时），本次跳过交叉验证")


@pytest.mark.skipif(SKIP_REMOTE, reason="CB_SKIP_REMOTE=1，跳过远端交叉验证")
def test_cross_check_length_tables(client):
    """哈希表逐条一致；对称表差异仅为原站冗余的错误记录 (3DES,128,112)。"""
    remote_hash = remote_post_get("/other/query/cipher/length", {"type": 1})
    if remote_hash is None:
        pytest.skip("原站不可达，本次跳过长度表交叉验证")
    remote_set = {(r["name"], r["length"], r["strength"]) for r in remote_hash}
    local = ok_data(client, "/api/other/length/table", {"type": "HASH"})["rows"]
    local_set = {(r["name"], r["lengthBits"], r["strength"]) for r in local}
    assert local_set == remote_set

    remote_sym = remote_post_get("/other/query/cipher/length", {"type": 2})
    if remote_sym is not None:
        remote_sym_set = {(r["name"], r["length"], r["strength"]) for r in remote_sym}
        local_sym = ok_data(client, "/api/other/length/table", {"type": "SYMMETRIC"})["rows"]
        local_sym_set = {(r["name"], r["lengthBits"], r["strength"]) for r in local_sym}
        # 原站存在重复数据源，其中一行把 3DES 分组长度写成 128 位（实际应为 64 位）
        assert local_sym_set <= remote_sym_set
        assert remote_sym_set - local_sym_set == {("3DES", 128, 112)}


def remote_post_get(path, params):
    for _ in range(4):
        try:
            resp = requests.get(BASE + path, params=params, timeout=TIMEOUT)
            if resp.status_code == 200 and resp.text.strip().startswith("{"):
                body = resp.json()
                return body.get("data") if body.get("code") == 0 else None
        except requests.RequestException:
            pass
        time.sleep(0.8)
    return None


@pytest.mark.skipif(SKIP_REMOTE, reason="CB_SKIP_REMOTE=1，跳过远端交叉验证")
def test_cross_check_cipher_match(client):
    """query/cipher 的哈希与对称匹配结果与原站一致（128 位输入）。"""
    payload = {"message": "00" * 16, "messageFormat": "HEX"}
    remote = remote_post("/other/query/cipher", payload)
    if remote is None:
        pytest.skip("原站不可达，本次跳过匹配交叉验证")
    local = ok_data(client, "/api/other/length/analyze", payload)
    remote_hash = {(r["name"], r["length"]) for r in remote.get("hash") or []}
    local_hash = {(r["name"], r["lengthBits"]) for r in local["hash"]}
    assert local_hash == remote_hash
    remote_sym = {(r["name"], r["length"]) for r in remote.get("symmetry") or []}
    local_sym = {(r["name"], r["lengthBits"]) for r in local["symmetric"]}
    assert local_sym <= remote_sym
    assert remote_sym - local_sym == {("3DES", 128)}
