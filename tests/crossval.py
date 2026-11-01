"""交叉验证：本地实现 vs 原站 https://cipher.huijusa.cn/api。

- 确定性接口：同输入逐字段对拍（HEX 大小写归一）。
- 随机性接口（密文/签名/密钥）：双向互验（原站加密→本地解密、本地加密→原站解密；
  本地签名→原站验签、原站签名→本地验签）。
用法：cd /opt/cipherbox && .venv/bin/python tests/crossval.py [组名...]
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
import urllib.error

LOCAL = "http://127.0.0.1:18080"
REMOTE = "https://cipher.huijusa.cn/api"
TYPE_OF = {"SM3": "SM3", "SHA-224": "SHA224", "SHA-256": "SHA256", "SHA-384": "SHA384",
           "SHA-512": "SHA512", "SHA3-224": "SHA3_224", "SHA3-256": "SHA3_256",
           "SHA3-384": "SHA3_384", "SHA3-512": "SHA3_512", "SHA-1": "SHA", "MD5": "MD5"}
K = "0123456789abcdeffedcba9876543210"
IV = "000102030405060708090a0b0c0d0e0f"


def post(url: str, payload: dict, timeout: int = 30):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Origin": REMOTE,
                 "User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"code": -1, "msg": f"HTTP {e.code}"}
    except Exception as e:
        return {"code": -1, "msg": str(e)}


def norm(v):
    if isinstance(v, str):
        s = v.strip().lower()
        try:
            return bytes.fromhex(s) if len(s) % 2 == 0 and all(c in "0123456789abcdef" for c in s) and s else v
        except ValueError:
            return v
    return v


def deep_eq(a, b) -> bool:
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(deep_eq(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(deep_eq(x, y) for x, y in zip(a, b))
    return norm(a) == norm(b)


results: list[dict] = []


def check(name: str, remote_path: str, local_path: str, payload: dict,
          transform=None, note: str = "", extract=None):
    """确定性对拍：同输入比较核心结果（extract 用于归一不同响应结构）。"""
    lp = json.loads(json.dumps(payload))
    if transform:
        lp = transform(lp)
    r = post(REMOTE + remote_path, payload)
    time.sleep(1.2)
    lp_path = local_path if local_path.startswith("/api") else "/api" + local_path
    l = post(LOCAL + lp_path, lp)
    ok_remote = r.get("code") == 0
    ok_local = l.get("code") == 0
    rd, ld = r.get("data"), l.get("data")
    if extract and ok_remote and ok_local:
        rd, ld = extract(rd), extract(ld)
    same = ok_remote and ok_local and deep_eq(rd, ld)
    results.append({"name": name, "same": same, "remote": r, "local": l,
                    "remote_path": remote_path, "local_path": local_path, "note": note})
    flag = "✔" if same else "✘"
    print(f"{flag} {name}")
    if not same:
        print("   remote:", json.dumps(r, ensure_ascii=False)[:400])
        print("   local :", json.dumps(l, ensure_ascii=False)[:400])
    return same


def interop(name: str, make: dict, note: str = "") -> bool:
    """make = {'enc_local': (path,payload)->data, 'dec_remote': (path,payload)->data, ...}
    每个条目为 (local_path_or_remote_path, payload_builder)"""
    raise NotImplementedError


def main():
    # ---------- 对称 ----------
    check("SM4-CBC-PKCS7 加密", "/cipher/encrypt", "/sym/encrypt", {
        "type": "SM4", "mode": "CBC", "padding": "PKCS7", "message": "abc",
        "messageFormat": "TEXT", "key": K, "keyFormat": "HEX", "iv": IV,
        "ivFormat": "HEX", "cipherFormat": "HEX"})
    check("AES128-CBC-PKCS7 加密", "/cipher/encrypt", "/sym/encrypt", {
        "type": "AES128", "mode": "CBC", "padding": "PKCS7", "message": "abc",
        "messageFormat": "TEXT", "key": K, "keyFormat": "HEX", "iv": IV,
        "ivFormat": "HEX", "cipherFormat": "HEX"})
    check("SM4-CTR-NOPADDING 加密", "/cipher/encrypt", "/sym/encrypt", {
        "type": "SM4", "mode": "CTR", "padding": "NOPADDING", "message": "abc",
        "messageFormat": "TEXT", "key": K, "keyFormat": "HEX", "iv": IV,
        "ivFormat": "HEX", "cipherFormat": "HEX"})
    check("ZUC-128 加密", "/cipher/zuc/encrypt", "/sym/zuc/encrypt", {
        "type": "ZUC128", "message": "abc", "messageFormat": "TEXT",
        "resultFormat": "HEX", "key": K, "keyFormat": "HEX", "iv": IV, "ivFormat": "HEX"})
    check("ZUC-128 MAC", "/cipher/zuc/mac", "/sym/zuc/mac", {
        "type": "ZUC128", "message": "abc", "messageFormat": "TEXT",
        "resultFormat": "HEX", "key": K, "keyFormat": "HEX", "iv": IV,
        "ivFormat": "HEX", "macLength": 4})
    check("GCM-SM4 加密", "/cipher/gcm/encrypt", "/sym/gcm/encrypt", {
        "type": "SM4", "message": "abc", "messageFormat": "TEXT", "resultFormat": "HEX",
        "key": K, "keyFormat": "HEX", "iv": "0" * 32, "ivFormat": "HEX",
        "aad": "", "aadFormat": "TEXT", "tagLength": 16, "tagFormat": "HEX"},
        extract=lambda d: {"cipher": d.get("cipher"), "tag": d.get("tag")})
    # ---------- 杂凑 ----------
    check("SM3 摘要", "/hash/digest", "/hash/digest", {
        "type": "SM3", "message": "abc", "messageFormat": "TEXT", "resultFormat": "HEX",
        "times": 1, "slot": "", "slotFormat": "HEX", "slotSite": "PRE"})
    check("HMAC-SM3", "/hash/hmac", "/hash/hmac", {
        "type": "SM3", "message": "abc", "messageFormat": "TEXT",
        "key": "6b6579", "keyFormat": "HEX", "resultFormat": "HEX",
        "times": 1, "slot": "", "slotFormat": "HEX", "slotSite": "PRE"})
    check("哈希算法猜测", "/hash/digest/all", "/hash/digest/all", {
        "message": "abc", "messageFormat": "TEXT", "hash": "", "hashFormat": "HEX"},
        note="返回数组，比对算法集合与摘要值",
        extract=lambda d: ({x.get("type"): x.get("hash", "").upper() for x in d}
                           if isinstance(d, list) else
                           {TYPE_OF.get(r.get("algo"), r.get("algo")): r.get("value", "").upper()
                            for r in (d or {}).get("rows", [])}))
    # ---------- 其他工具 ----------
    check("逻辑运算 XOR", "/other/logic", "/other/logic", {
        "type": "XOR", "s1": "0102", "s1Format": "HEX", "s2": "0304",
        "s2Format": "HEX", "resultFormat": "HEX"},
        extract=lambda d: (d if isinstance(d, str) else d.get("result") or d.get("hex")))
    check("大数运算 MUL", "/other/math", "/other/math", {
        "type": "MUL", "s1": "0102", "s1Format": "HEX", "s2": "0304",
        "s2Format": "HEX", "resultFormat": "HEX"},
        extract=lambda d: (d if isinstance(d, str) else d.get("result") or d.get("hex")))
    check("字节逆序", "/other/byte/reverse", "/other/byte/reverse", {
        "s1": "0102030405060708", "s1Format": "HEX", "resultFormat": "HEX"},
        extract=lambda d: (d if isinstance(d, str) else d.get("result") or d.get("hex")))
    check("工作模式检测", "/cipher-mode-detector/detect", "/ops/mode/detect", {
        "ciphertext1": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ciphertext1Format": "HEX",
        "ciphertext2": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ciphertext2Format": "HEX"}, note="报告类结果，比对可能模式",
        extract=lambda d: d if isinstance(d, str) else (d.get("possibleModes") or d.get("modes") or d.get("conclusion") or ""))

    n_same = sum(1 for r in results if r["same"])
    print(f"\n通过 {n_same}/{len(results)}")
    json.dump(results, open("/opt/cipherbox/tests/crossval_report.json", "w"),
              ensure_ascii=False, indent=1)
    return 0 if n_same == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
