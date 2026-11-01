"""随机数检测（NIST SP 800-22 常用子集）与随机数生成。

实现的检测项（共 8 类、9 个 P 值）：

======= ====================================== ==========================
序号    检测项                                  判定
======= ====================================== ==========================
1       单比特频数（Frequency / Monobit）        p ≥ 0.01
2       块内频数（Block Frequency）              p ≥ 0.01
3       游程（Runs）                             p ≥ 0.01
4       块内最长游程（Longest Run of Ones）      p ≥ 0.01
5       累积和-前向（Cumulative Sums Forward）    p ≥ 0.01
6       累积和-后向（Cumulative Sums Backward）   p ≥ 0.01
7       近似熵（Approximate Entropy）            p ≥ 0.01
8       序列（Serial）                           p1、p2 均 ≥ 0.01
9       离散傅里叶（Discrete Fourier Transform）  p ≥ 0.01
======= ====================================== ==========================

统计量的分布函数使用正则化不完全伽马函数 ``Q(a, x)``（即 ``igamc``）与
互补误差函数 ``erfc``，全部为纯 Python 实现，不依赖第三方数值库。

参考：NIST SP 800-22 Rev.1a, A Statistical Test Suite for Random and
Pseudorandom Number Generators for Cryptographic Applications.
"""
from __future__ import annotations

import math
import os

from .common import ToolError, format_bytes, parse_bytes

ALPHA = 0.01
MIN_BITS = 128
MAX_BITS = 1 << 20
DFT_MAX_BITS = 1 << 17  # 纯 Python FFT 的上限，超过则跳过该项


# ---------------------------------------------------------------------------
# 特殊函数
# ---------------------------------------------------------------------------

def _gammaincc(a: float, x: float) -> float:
    """正则化上不完全伽马函数 Q(a, x) = Γ(a, x) / Γ(a)（即 igamc）。"""
    if x < 0 or a <= 0:
        raise ValueError("gammaincc 参数非法")
    if x == 0:
        return 1.0
    if x < a + 1.0:
        return 1.0 - _gser(a, x)
    return _gcf(a, x)


def _gser(a: float, x: float) -> float:
    """下不完全伽马函数的级数展开 P(a, x)。"""
    gln = math.lgamma(a)
    ap = a
    total = 1.0 / a
    delta = total
    for _ in range(1000):
        ap += 1.0
        delta *= x / ap
        total += delta
        if abs(delta) < abs(total) * 1e-15:
            break
    return total * math.exp(-x + a * math.log(x) - gln)


def _gcf(a: float, x: float) -> float:
    """上不完全伽马函数的连分式展开（Lentz 算法）。"""
    tiny = 1e-300
    gln = math.lgamma(a)
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def _norm_cdf(x: float) -> float:
    return 0.5 * math.erfc(-x / math.sqrt(2.0))


# ---------------------------------------------------------------------------
# 数据准备
# ---------------------------------------------------------------------------

def bits_from_bytes(data: bytes) -> list[int]:
    """把字节串展开成比特列表（高位在前）。"""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


# ---------------------------------------------------------------------------
# 各个检测项
# ---------------------------------------------------------------------------

def _result(key, name, p1, params=None, statistic=None, p2=None, note="", passed=None):
    p1 = float(min(max(p1, 0.0), 1.0))
    ok = p1 >= ALPHA
    if p2 is not None:
        p2 = float(min(max(p2, 0.0), 1.0))
        ok = ok and p2 >= ALPHA
    if passed is not None:
        ok = bool(passed)
    return {
        "key": key,
        "name": name,
        "pvalue": round(p1, 6),
        "pvalue2": None if p2 is None else round(p2, 6),
        "passed": ok,
        "params": params or {},
        "statistic": None if statistic is None else round(float(statistic), 6),
        "note": note,
    }


def frequency_test(bits: list[int]) -> dict:
    """[1] 单比特频数检测。"""
    n = len(bits)
    s = sum(2 * b - 1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    p = math.erfc(s_obs / math.sqrt(2.0))
    return _result("frequency", "单比特频数检测", p,
                   {"n": n}, s_obs,
                   note=f"1 的个数 {sum(bits)}，0 的个数 {n - sum(bits)}")


def block_frequency_test(bits: list[int], block: int = 128) -> dict:
    """[2] 块内频数检测。"""
    n = len(bits)
    m = max(2, min(block, n // 2))
    count = n // m
    chi2 = 0.0
    for i in range(count):
        ones = sum(bits[i * m:(i + 1) * m])
        pi = ones / m
        chi2 += (pi - 0.5) ** 2
    chi2 *= 4.0 * m
    p = _gammaincc(count / 2.0, chi2 / 2.0)
    return _result("block_frequency", "块内频数检测", p,
                   {"n": n, "M": m, "N": count}, chi2,
                   note=f"共 {count} 个 {m} 比特分块")


_LONGEST_RUN_TABLE = {
    8: {
        "bounds": [1, 2, 3, 10 ** 9],
        "pi": [0.2148, 0.3672, 0.2305, 0.1875],
    },
    128: {
        "bounds": [4, 5, 6, 7, 8, 10 ** 9],
        "pi": [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124],
    },
    10000: {
        "bounds": [10, 11, 12, 13, 14, 15, 10 ** 9],
        "pi": [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727],
    },
}


def longest_run_test(bits: list[int], m: int | None = None) -> dict:
    """[4] 块内最长“1”游程检测（NIST 取 M = 8 / 128 / 10000 三档）。"""
    n = len(bits)
    if m is None:
        if n < 6272:
            m = 8
        elif n < 750000:
            m = 128
        else:
            m = 10000
    if m not in _LONGEST_RUN_TABLE:
        m = 8
    spec = _LONGEST_RUN_TABLE[m]
    blocks = n // m
    if blocks < 2:
        raise ToolError(f"块内最长游程检测至少需要 2 个分块，当前数据仅 {n} 比特")

    counts = [0] * len(spec["pi"])
    for i in range(blocks):
        longest = run = 0
        for b in bits[i * m:(i + 1) * m]:
            if b:
                run += 1
                longest = max(longest, run)
            else:
                run = 0
        idx = 0
        while idx < len(spec["bounds"]) - 1 and longest > spec["bounds"][idx]:
            idx += 1
        counts[idx] += 1
    chi2 = 0.0
    k = len(spec["pi"])
    for idx in range(k):
        expected = blocks * spec["pi"][idx]
        if expected > 0:
            chi2 += (counts[idx] - expected) ** 2 / expected
    p = _gammaincc((k - 1) / 2.0, chi2 / 2.0)
    return _result("longest_run", "块内最长“1”游程检测", p,
                   {"n": n, "M": m, "N": blocks, "classes": counts}, chi2,
                   note=f"分块大小 M={m}，共 {blocks} 块")


def runs_test(bits: list[int]) -> dict:
    """[3] 游程总数检测。"""
    n = len(bits)
    ones = sum(bits)
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return _result("runs", "游程检测", 0.0, {"n": n, "pi": round(pi, 6)}, None,
                       note="前置条件不满足：0/1 比例偏离 1:1 过多，本项判为不通过",
                       passed=False)
    v = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    num = abs(v - 2.0 * n * pi * (1 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)
    p = math.erfc(num / den)
    return _result("runs", "游程检测", p, {"n": n, "V": v, "pi": round(pi, 6)}, num / den,
                   note=f"游程总数 V={v}")


def _cumsum_pvalue(bits: list[int]) -> tuple[float, int]:
    n = len(bits)
    s = 0
    z = 0
    for b in bits:
        s += 1 if b else -1
        if abs(s) > z:
            z = abs(s)
    if z == 0:
        return 1.0, 0
    root = math.sqrt(n)
    total = 0.0
    k = math.floor((-n / z + 1) / 4.0)
    while k <= math.ceil((n / z - 1) / 4.0):
        total += _norm_cdf((4 * k + 1) * z / root) - _norm_cdf((4 * k - 1) * z / root)
        k += 1
    second = 0.0
    k = math.floor((-n / z - 3) / 4.0)
    while k <= math.ceil((n / z - 1) / 4.0):
        second += _norm_cdf((4 * k + 3) * z / root) - _norm_cdf((4 * k + 1) * z / root)
        k += 1
    p = 1.0 - total + second
    return min(max(p, 0.0), 1.0), z


def cumulative_sums_test(bits: list[int], reverse: bool = False) -> dict:
    """[5][6] 累积和检测（前向 / 后向）。"""
    seq = bits[::-1] if reverse else bits
    p, z = _cumsum_pvalue(seq)
    key = "cumsum_backward" if reverse else "cumsum_forward"
    name = "累积和检测（后向）" if reverse else "累积和检测（前向）"
    return _result(key, name, p, {"n": len(bits), "z": z}, z,
                   note="将 0 视为 -1 后计算累加和的最大绝对值" + ("（序列反向）" if reverse else ""))


def _pattern_counts(bits: list[int], m: int) -> dict[int, int]:
    n = len(bits)
    counts: dict[int, int] = {}
    for i in range(n):
        value = 0
        for j in range(m):
            value = (value << 1) | bits[(i + j) % n]
        counts[value] = counts.get(value, 0) + 1
    return counts


def _psi_square(bits: list[int], m: int) -> float:
    n = len(bits)
    if m <= 0:
        return 0.0
    counts = _pattern_counts(bits, m)
    return (2 ** m / n) * sum(c * c for c in counts.values()) - n


def approximate_entropy_test(bits: list[int], m: int = 2) -> dict:
    """[7] 近似熵检测。"""
    n = len(bits)
    if n <= (1 << (m + 1)):
        raise ToolError(f"近似熵检测（m={m}）要求序列长度大于 {1 << (m + 1)} 比特")

    def phi(order: int) -> float:
        counts = _pattern_counts(bits, order)
        total = 0.0
        for c in counts.values():
            pi = c / n
            if pi > 0:
                total += pi * math.log(pi)
        return total

    ap_en = phi(m) - phi(m + 1)
    chi2 = 2.0 * n * (math.log(2.0) - ap_en)
    p = _gammaincc(2 ** (m - 1), chi2 / 2.0)
    return _result("approximate_entropy", "近似熵检测", p,
                   {"n": n, "m": m}, chi2,
                   note=f"ApEn={ap_en:.6f}")


def serial_test(bits: list[int], m: int = 3) -> dict:
    """[8] 序列检测（两个 P 值）。"""
    n = len(bits)
    if m <= 1 or m >= n:
        raise ToolError("序列检测的模式长度 m 取值非法")
    psi_m = _psi_square(bits, m)
    psi_m1 = _psi_square(bits, m - 1)
    psi_m2 = _psi_square(bits, m - 2)
    d1 = psi_m - psi_m1
    d2 = psi_m - 2 * psi_m1 + psi_m2
    p1 = _gammaincc(2 ** (m - 2), d1 / 2.0)
    p2 = _gammaincc(2 ** (m - 3), max(d2, 0.0) / 2.0) if m >= 3 else 1.0
    return _result("serial", "序列检测", p1, {"n": n, "m": m}, d1, p2=p2,
                   note=f"m={m}，∇ψ²={d1:.4f}，∇²ψ²={d2:.4f}")


def _fft(values: list[complex]) -> None:
    """原地基 2 时间抽取 FFT（纯 Python 实现）。"""
    n = len(values)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j |= bit
        if i < j:
            values[i], values[j] = values[j], values[i]
    length = 2
    while length <= n:
        ang = -2.0 * math.pi / length
        w_len = complex(math.cos(ang), math.sin(ang))
        half = length >> 1
        for start in range(0, n, length):
            w = 1 + 0j
            for k in range(start, start + half):
                u = values[k]
                v = values[k + half] * w
                values[k] = u + v
                values[k + half] = u - v
                w *= w_len
        length <<= 1


def dft_test(bits: list[int]) -> dict:
    """[9] 离散傅里叶检测。

    基 2 FFT 要求长度为 2 的幂，因此取序列**前缀**中最大的 2 的幂长度参与
    计算（截断而非补零，避免边界突变引入虚假低频能量）。
    """
    total = len(bits)
    n = 1 << (total.bit_length() - 1)
    seq = [complex(2.0 * b - 1.0, 0.0) for b in bits[:n]]
    _fft(seq)
    threshold = math.sqrt(math.log(1.0 / 0.05) * n)
    peaks = [abs(seq[i]) for i in range(n // 2)]
    n0 = 0.95 * n / 2.0
    n1 = sum(1 for v in peaks if v < threshold)
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    p = math.erfc(abs(d) / math.sqrt(2.0))
    note = f"门限 T={threshold:.4f}，低于门限的谱峰 {n1} 个"
    if n != total:
        note += f"（取前 {n} 比特参与 FFT，原长 {total} 比特）"
    return _result("dft", "离散傅里叶检测", p,
                   {"n": n, "T": round(threshold, 4), "N0": round(n0, 2), "N1": n1}, d,
                   note=note)


# ---------------------------------------------------------------------------
# 组合检测
# ---------------------------------------------------------------------------

TEST_META = [
    {"key": "frequency", "name": "单比特频数检测", "standard": "NIST SP800-22 2.1",
     "desc": "检测序列中 0 与 1 的比例是否接近 1:1。"},
    {"key": "block_frequency", "name": "块内频数检测", "standard": "NIST SP800-22 2.2",
     "desc": "检测每个 M 比特分块内部 0/1 比例是否均衡。"},
    {"key": "runs", "name": "游程检测", "standard": "NIST SP800-22 2.3",
     "desc": "检测连续相同比特片段的总数是否符合随机期望。"},
    {"key": "longest_run", "name": "块内最长“1”游程检测", "standard": "NIST SP800-22 2.4",
     "desc": "检测各分块内最长 1 游程长度分布是否符合期望。"},
    {"key": "cumsum", "name": "累积和检测（前向/后向）", "standard": "NIST SP800-22 2.13",
     "desc": "把 0 视为 -1 后检测累加和的最大偏移是否合理。"},
    {"key": "approximate_entropy", "name": "近似熵检测", "standard": "NIST SP800-22 2.12",
     "desc": "比较 m 与 m+1 位模式频率，评估序列复杂度。"},
    {"key": "serial", "name": "序列检测", "standard": "NIST SP800-22 2.11",
     "desc": "检测重叠 m 位模式出现次数是否均匀（输出两个 P 值）。"},
    {"key": "dft", "name": "离散傅里叶检测", "standard": "NIST SP800-22 2.6",
     "desc": "检测频域谱峰分布，识别周期性结构。"},
]


def detect(value, fmt: str = "HEX", alpha: float = ALPHA) -> dict:
    """对输入数据执行全部已实现检测项，返回逐项 P 值与总体结论。"""
    data = parse_bytes(value, fmt)
    if not data:
        raise ToolError("请输入待检测的随机数序列")
    bits = bits_from_bytes(data)
    n = len(bits)
    if n < MIN_BITS:
        raise ToolError(f"检测数据至少需要 {MIN_BITS} 比特，当前仅 {n} 比特（{len(data)} 字节）")
    if n > MAX_BITS:
        raise ToolError(f"检测数据最多支持 {MAX_BITS} 比特，当前 {n} 比特，请截断后重试")

    tests = [
        frequency_test(bits),
        block_frequency_test(bits),
        runs_test(bits),
        longest_run_test(bits),
        cumulative_sums_test(bits, reverse=False),
        cumulative_sums_test(bits, reverse=True),
        approximate_entropy_test(bits, m=2),
        serial_test(bits, m=min(3, max(2, int(math.log2(n)) - 3))),
    ]
    if n <= DFT_MAX_BITS:
        tests.append(dft_test(bits))
    else:
        tests.append({
            "key": "dft",
            "name": "离散傅里叶检测",
            "pvalue": None,
            "pvalue2": None,
            "passed": None,
            "params": {"n": n},
            "statistic": None,
            "note": f"数据超过 {DFT_MAX_BITS} 比特，已跳过该项（纯 Python FFT 耗时过长）",
        })

    judged = [t for t in tests if t["passed"] is not None]
    passed_count = sum(1 for t in judged if t["passed"])
    all_passed = passed_count == len(judged)
    return {
        "bits": n,
        "bytes": (n + 7) // 8,
        "alpha": alpha,
        "threshold": alpha,
        "tests": tests,
        "total": len(judged),
        "passedCount": passed_count,
        "passed": all_passed,
        "conclusion": (
            "全部检测项通过，未发现明显非随机特征"
            if all_passed else
            f"{len(judged) - passed_count} 项检测未通过，序列可能存在非随机特征"
        ),
        "standard": "NIST SP 800-22 Rev.1a（常用子集）",
    }


def generate(bits: int = 256, fmt: str = "HEX") -> dict:
    """使用操作系统密码学安全随机源生成随机数。"""
    try:
        bits = int(bits)
    except (TypeError, ValueError):
        raise ToolError("随机数位数必须为整数")
    if bits <= 0:
        raise ToolError("随机数位数必须大于 0")
    if bits > MAX_BITS:
        raise ToolError(f"单次最多生成 {MAX_BITS} 比特随机数")
    length = (bits + 7) // 8
    data = os.urandom(length)
    if bits % 8:
        # 首字节中多余的高位清零，保证数值精确落在请求的位数范围内
        extra = 8 - bits % 8
        data = bytes([data[0] & (0xFF >> extra)]) + data[1:]
    return {
        "bits": bits,
        "bytes": length,
        "format": (fmt or "HEX").upper(),
        "value": format_bytes(data, fmt),
        "source": "os.urandom（操作系统 CSPRNG）",
    }


__all__ = [
    "ALPHA", "MIN_BITS", "MAX_BITS", "TEST_META",
    "bits_from_bytes", "detect", "generate",
    "frequency_test", "block_frequency_test", "runs_test", "longest_run_test",
    "cumulative_sums_test", "approximate_entropy_test", "serial_test", "dft_test",
]
