"""随机数检测（NIST SP 800-22 常用子集）与随机数生成。

统计量全部按 NIST SP 800-22 Rev.1a 实现，测试用两种方式验证：
1) 与解析公式独立复算（单比特频数、游程、累积和、块内频数）；
2) 确定性构造序列的行为校验（全 0 必然不通过、全交替必然游程/DFT 不通过）。
另外尝试与原站 /api/random/test 异步任务交叉验证，原站不可用时自动 skip。
"""
from __future__ import annotations

import math
import os
import time

import pytest
import requests

from app.core import randomness
from app.server import create_app

BASE = "https://cipher.huijusa.cn/api"
TIMEOUT = 20
SKIP_REMOTE = os.environ.get("CB_SKIP_REMOTE") == "1"

# 固定示例：SHA-256 计数器模式生成，2048 比特，全部检测项通过
SAMPLE_HEX = (
    "a6685f3b62d57bfc4935263140bae87fcd48088975c238c1c8455fa2c716659d"
    "d6b5915c46057bcb005f46f6433df65609dd3a7a57af75ac1a5a4a7c299ebffb"
    "673aeeb08cfbb00b91e5e3c60b5ba31896d55b522b1be2dccb0645a59bae877585"
    "f2ef987b76f4c3fc081acef84e0a730f5df8a2488a5bb7ddae4f7dee721ed849"
    "2ab00bbe71db09cc80c473346ab2119a8573638cf8c433e3d91a1a450522fc6669"
    "b8482999dfdcef11e5e9a07caffabe2509d25d14904f74ef47054de3af1b62325d"
    "fc1fc675255519674da6e2c4aad5f51cc6c3217ed3c6fbf6cabe0d86b03d5f0fd8"
    "38606f1f7c5b2a7cf3cfaa325e5552bc8f28ff26559445531a30fa60"
)


@pytest.fixture()
def client():
    return create_app().test_client()


def ok_data(client, path, payload):
    body = client.post(path, json=payload).get_json()
    assert body["code"] == 0, body
    return body["data"]


def test_gammaincc_known_values():
    # Q(1,1) = e^-1, Q(2,2) = 3e^-2, Q(0.5,0.5) = erfc(sqrt(0.5))
    assert abs(randomness._gammaincc(1, 1) - math.exp(-1)) < 1e-12
    assert abs(randomness._gammaincc(2, 2) - 3 * math.exp(-2)) < 1e-12
    assert abs(randomness._gammaincc(0.5, 0.5) - math.erfc(math.sqrt(0.5))) < 1e-12


def test_bits_from_bytes():
    assert randomness.bits_from_bytes(b"\x01") == [0, 0, 0, 0, 0, 0, 0, 1]
    assert randomness.bits_from_bytes(b"\xff") == [1] * 8
    assert len(randomness.bits_from_bytes(b"\x00" * 16)) == 128


def test_frequency_matches_formula():
    bits = randomness.bits_from_bytes(b"\xaa" * 32)
    result = randomness.frequency_test(bits)
    ones = sum(bits)
    s_obs = abs(2 * ones - len(bits)) / math.sqrt(len(bits))
    expected = math.erfc(s_obs / math.sqrt(2))
    assert result["pvalue"] == pytest.approx(round(expected, 6), abs=1e-6)
    assert result["passed"] is True

    zeros = randomness.frequency_test([0] * 2048)
    assert zeros["pvalue"] == 0.0 and zeros["passed"] is False


def test_runs_matches_formula():
    bits = randomness.bits_from_bytes(bytes.fromhex(SAMPLE_HEX[:64]))
    result = randomness.runs_test(bits)
    n = len(bits)
    ones = sum(bits)
    pi = ones / n
    v = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    expected = math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    assert result["pvalue"] == pytest.approx(round(expected, 6), abs=1e-6)


def test_runs_prerequisite_failure():
    # 0/1 严重失衡时 NIST 要求判定前置条件失败
    bits = [1] * 2000 + [0] * 48
    result = randomness.runs_test(bits)
    assert result["passed"] is False and "前置条件" in result["note"]


def test_block_frequency_matches_formula():
    data = bytes.fromhex(SAMPLE_HEX[:256])
    bits = randomness.bits_from_bytes(data)
    result = randomness.block_frequency_test(bits, block=128)
    n = len(bits)
    m = 128
    blocks = n // m
    chi2 = 0.0
    for i in range(blocks):
        pi = sum(bits[i * m:(i + 1) * m]) / m
        chi2 += (pi - 0.5) ** 2
    chi2 *= 4 * m
    expected = randomness._gammaincc(blocks / 2.0, chi2 / 2.0)
    assert result["pvalue"] == pytest.approx(round(expected, 6), abs=1e-6)


def test_cumulative_sums_z_statistic():
    bits = randomness.bits_from_bytes(bytes.fromhex(SAMPLE_HEX[:128]))
    fwd = randomness.cumulative_sums_test(bits, reverse=False)
    z = 0
    running = 0
    for b in bits:
        running += 1 if b else -1
        z = max(z, abs(running))
    assert fwd["params"]["z"] == z
    assert 0.0 <= fwd["pvalue"] <= 1.0
    # 反向序列的 z 可能不同，但都必须是合法的最大偏移
    bwd = randomness.cumulative_sums_test(bits, reverse=True)
    z_rev = 0
    running = 0
    for b in reversed(bits):
        running += 1 if b else -1
        z_rev = max(z_rev, abs(running))
    assert bwd["params"]["z"] == z_rev


def test_all_zero_fails_everything():
    bits = [0] * 2048
    for fn in (randomness.frequency_test, randomness.block_frequency_test,
               randomness.runs_test, randomness.cumulative_sums_test,
               randomness.approximate_entropy_test, randomness.serial_test):
        assert fn(bits)["passed"] is False


def test_alternating_sequence_behavior():
    bits = [0, 1] * 1024
    assert randomness.frequency_test(bits)["passed"] is True     # 0/1 均衡
    assert randomness.runs_test(bits)["passed"] is False         # 游程异常多
    assert randomness.dft_test(bits)["pvalue"] < 0.01            # 单一频率分量
    assert randomness.approximate_entropy_test(bits)["passed"] is False


def test_longest_run_block_choice():
    bits = randomness.bits_from_bytes(bytes.fromhex(SAMPLE_HEX))
    result = randomness.longest_run_test(bits)
    assert result["params"]["M"] == 8       # 2048 比特 → M=8
    assert result["params"]["N"] == len(bits) // 8


def test_detect_sample_all_pass(client):
    data = ok_data(client, "/api/random/detect", {"data": SAMPLE_HEX, "dataFormat": "HEX"})
    assert data["bits"] == 2048
    assert data["total"] == 9
    assert data["passedCount"] == 9 and data["passed"] is True
    keys = [t["key"] for t in data["tests"]]
    assert keys == ["frequency", "block_frequency", "runs", "longest_run",
                    "cumsum_forward", "cumsum_backward", "approximate_entropy",
                    "serial", "dft"]
    for t in data["tests"]:
        assert 0.0 <= t["pvalue"] <= 1.0
        assert t["pvalue"] >= 0.01
    assert data["threshold"] == 0.01


def test_detect_zero_sequence_fails(client):
    data = ok_data(client, "/api/random/detect", {"data": "00" * 256, "dataFormat": "HEX"})
    assert data["passed"] is False
    assert data["passedCount"] == 0
    assert "未通过" in data["conclusion"]


def test_detect_base64_and_text(client):
    import base64
    b64 = base64.b64encode(bytes.fromhex(SAMPLE_HEX)).decode()
    data = ok_data(client, "/api/random/detect", {"data": b64, "dataFormat": "BASE64"})
    assert data["passed"] is True
    text = ok_data(client, "/api/random/detect", {"message": "a" * 300, "messageFormat": "TEXT"})
    assert text["bits"] == 2400


def test_detect_errors(client):
    empty = client.post("/api/random/detect", json={"data": "", "dataFormat": "HEX"}).get_json()
    assert empty["code"] == 1
    short = client.post("/api/random/detect", json={"data": "0011", "dataFormat": "HEX"}).get_json()
    assert short["code"] == 1 and "128" in short["msg"]
    bad = client.post("/api/random/detect", json={"data": "zz", "dataFormat": "HEX"}).get_json()
    assert bad["code"] == 1


def test_detect_too_long(client):
    # 超过 1 Mbit 直接拒绝
    payload = {"data": "ab" * (140000), "dataFormat": "HEX"}
    body = client.post("/api/random/detect", json=payload).get_json()
    assert body["code"] == 1 and "最多" in body["msg"]


def test_generate_get_and_post(client):
    got = client.get("/api/random/generate?bits=256&format=HEX").get_json()
    assert got["code"] == 0
    assert got["data"]["bits"] == 256 and len(got["data"]["value"]) == 64
    int(got["data"]["value"], 16)  # 合法 HEX

    posted = client.post("/api/random/generate", json={"bits": 128, "format": "BASE64"}).get_json()
    assert posted["code"] == 0 and posted["data"]["bytes"] == 16

    odd = client.get("/api/random/generate?bits=12&format=HEX").get_json()
    assert odd["data"]["bits"] == 12 and odd["data"]["bytes"] == 2
    assert int(odd["data"]["value"], 16) < (1 << 12)   # 首字节多余高位被掩掉
    assert len(odd["data"]["value"]) == 4

    bad = client.get("/api/random/generate?bits=0").get_json()
    assert bad["code"] == 1


def test_generate_randomness_is_not_constant(client):
    values = {client.get("/api/random/generate?bits=128&format=HEX").get_json()["data"]["value"] for _ in range(3)}
    assert len(values) == 3


def test_tests_endpoint(client):
    data = ok_data(client, "/api/random/tests", {})
    assert len(data["tests"]) == 8
    assert data["alpha"] == 0.01 and data["minBits"] == 128


def test_dft_skipped_for_huge_input(client):
    # 131073 比特：DFT 跳过，其余项仍判定
    payload = {"data": "ff" * 16385, "dataFormat": "HEX"}
    data = ok_data(client, "/api/random/detect", payload)
    dft = next(t for t in data["tests"] if t["key"] == "dft")
    assert dft["pvalue"] is None and dft["passed"] is None
    assert data["total"] == 8


@pytest.mark.skipif(SKIP_REMOTE, reason="CB_SKIP_REMOTE=1，跳过远端交叉验证")
def test_cross_check_remote_randomness():
    """尝试与原站 /random/test + /random/query 交叉验证单比特频数检测。

    原站是 GM/T 0005-2021 的异步任务（multipart 上传 + fileIden 轮询），
    与本地 NIST 子集的实现不同源，因此只比对双方都实现的「单比特频数」
    通过/不通过结论；原站返回 502 / 结果长期不可用时跳过。
    """
    data = bytes.fromhex("00" * 2500)  # 20000 比特全 0：双方都应判不通过
    iden = None
    for _ in range(3):
        try:
            resp = requests.post(
                BASE + "/random/test",
                files={"randomFile": ("random_data.bin", data, "application/octet-stream")},
                data={"cipherLength": "20000", "methods": "1"},
                timeout=TIMEOUT,
            )
            if resp.status_code == 200 and resp.text.strip().startswith("{"):
                body = resp.json()
                if body.get("code") == 0:
                    iden = body.get("data")
                    break
        except requests.RequestException:
            pass
        time.sleep(1.0)
    if not iden:
        pytest.skip("原站 /random/test 不可用（网关 502），跳过随机数交叉验证")

    result = None
    for _ in range(8):
        try:
            resp = requests.get(BASE + "/random/query", params={"fileIden": iden}, timeout=TIMEOUT)
            if resp.status_code == 200:
                body = resp.json()
                if body.get("code") == 0 and body.get("data"):
                    result = body["data"]
                    break
                if body.get("code") == 1000:  # 结果尚未生成 / 已过期
                    time.sleep(2.0)
                    continue
        except requests.RequestException:
            pass
        time.sleep(1.0)
    if not result:
        pytest.skip("原站 /random/query 未返回检测结果（任务长期 pending 或已过期），跳过")

    local = randomness.detect(data.hex(), "HEX")
    monobit = next(t for t in local["tests"] if t["key"] == "frequency")
    assert monobit["passed"] is False
    # 原站结果结构随版本变化，只在其明确给出通过标志时比对
    rows = result.get("data") or []
    for row in rows:
        if str(row.get("index")) == "1" and "pass" in row:
            assert row["pass"] in (False, 0, "false", "0"), row
