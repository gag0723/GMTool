"""与原站（https://cipher.huijusa.cn）协议解析接口的交叉验证脚本。

用法：
    .venv/bin/python tests/crossval_proto.py            # 生成报告并打印对比表
    .venv/bin/python tests/crossval_proto.py --strict    # 有差异时返回非 0

说明：
- 原站接口为 multipart/form-data：POST /api/pcap/parse/{tls,ssh,ipsec,ukey}，
  字段 pcapFile（文件）、srcAddr、dstAddr、sshPort（仅 SSH）。
- 同时用独立工具（dpkt 读包、openssl 解析证书）核对本地解析结果，
  避免"两个实现一起错"。
- 原站不可用时脚本不会失败，只在报告中记录 skipped 及原因。
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
ORIGIN = os.environ.get("CB_ORIGIN", "https://cipher.huijusa.cn")
ORIGIN_API = ORIGIN + "/api/pcap/parse/%s"

EXPECT = json.load(open(os.path.join(FIX, "expectations.json"), encoding="utf-8"))


# ---------------------------------------------------------------- 本地解析
def local_parse(kind: str) -> dict:
    from app.server import create_app

    client = create_app().test_client()
    with open(EXPECT[kind]["file"], "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    payload = {"pcap": b64, "pcapFormat": "BASE64"}
    if kind == "ssh":
        payload["sshPort"] = 22
    endpoint = "ipsec" if kind.startswith("ipsec") else kind
    body = client.post("/api/proto/%s/parse" % endpoint, json=payload).get_json()
    if body.get("code") != 0:
        raise RuntimeError("本地解析失败：%s" % body.get("msg"))
    return body["data"]


# ---------------------------------------------------------------- 原站调用
def origin_parse(kind: str, path: str, extra: dict | None = None,
                 attempts: int = 3) -> tuple[dict | None, str]:
    """调用原站接口；原站偶发返回空响应（限流），因此带退避重试。"""
    try:
        import requests
        import time
    except ImportError:
        return None, "requests 未安装，无法访问原站"

    data = {"srcAddr": "", "dstAddr": ""}
    if kind == "ssh":
        data["sshPort"] = "22"
    data.update(extra or {})
    err = ""
    for i in range(attempts):
        try:
            with open(path, "rb") as fh:
                resp = requests.post(
                    ORIGIN_API % kind,
                    files={"pcapFile": (os.path.basename(path), fh, "application/vnd.tcpdump.pcap")},
                    data=data, timeout=60,
                )
            if resp.status_code == 200 and resp.text.strip():
                try:
                    return resp.json(), ""
                except ValueError:
                    err = "返回内容不是 JSON（可能被限流）：%r" % resp.text[:80]
            else:
                err = "HTTP %s / 空响应" % resp.status_code
        except Exception as exc:                 # 网络不可达 / 超时
            err = "原站不可用：%s" % exc
        time.sleep(1.5 * (i + 1))
    return None, "%s（已重试 %d 次）" % (err, attempts)


# ---------------------------------------------------------------- 比较工具
def norm(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "|".join(norm(v) for v in value)
    return str(value).strip().strip("'\"").lower()


def cmp_row(module: str, field: str, orig, local, note: str = "", strip_space: bool = False,
            prefix: bool = False) -> dict:
    a, b = norm(orig), norm(local)
    if strip_space:
        a, b = a.replace(" ", ""), b.replace(" ", "")
    match = bool(a) and (b.startswith(a) if prefix else a == b)
    return {"module": module, "field": field,
            "origin": str(orig)[:160] if orig is not None else "null",
            "local": str(local)[:160] if local is not None else "null",
            "match": match, "note": note}


def cmp_list(module: str, field: str, orig_text, local_list, note: str = "") -> dict:
    """原站用"；"或逗号连接算法列表，本地是数组，逐项比较。"""
    raw = str(orig_text or "").replace("；", ",").replace(";", ",")
    theirs = [x.strip() for x in raw.split(",") if x.strip()]
    mine = [str(x) for x in (local_list or [])]
    return {"module": module, "field": field,
            "origin": ",".join(theirs)[:160], "local": ",".join(mine)[:160],
            "match": bool(theirs) and theirs == mine, "note": note}


def cert_subjects(orig_texts) -> list[str]:
    """从原站的证书文本里提取使用者 DN。"""
    out = []
    for text in orig_texts or []:
        for line in str(text).splitlines():
            if line.startswith("使用者"):
                out.append(line.split(":", 1)[1].strip())
    return out


def cert_der(orig_base64_list) -> list[bytes]:
    return [base64.b64decode(x) for x in (orig_base64_list or [])]


# ---------------------------------------------------------------- 独立核对
def openssl_check(der: bytes) -> str:
    """用 openssl 独立解析证书，返回 subject 字符串（失败返回空）。"""
    try:
        with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as fh:
            fh.write(der)
            path = fh.name
        out = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-in", path, "-noout", "-subject", "-issuer", "-serial"],
            capture_output=True, text=True, timeout=20,
        )
        os.unlink(path)
        if out.returncode != 0:
            return ""
        parts = {}
        for line in out.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                parts[k.strip()] = v.strip()
        return " | ".join(parts.values())
    except Exception:
        return ""


def dpkt_check(path: str) -> dict:
    """用 dpkt 独立统计报文数，核对本地 pcap 读取。"""
    try:
        import dpkt
    except ImportError:
        return {"ok": False, "reason": "dpkt 未安装"}
    count = 0
    tcp = udp = 0
    try:
        with open(path, "rb") as fh:
            reader = dpkt.pcap.Reader(fh)
            for _ts, buf in reader:
                count += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        if isinstance(eth.data.data, dpkt.tcp.TCP):
                            tcp += 1
                        elif isinstance(eth.data.data, dpkt.udp.UDP):
                            udp += 1
                except Exception:
                    continue
    except Exception as exc:
        return {"ok": False, "reason": "dpkt 读取失败：%s" % exc}
    return {"ok": True, "packets": count, "tcp": tcp, "udp": udp}


# ---------------------------------------------------------------- 各模块对比
def crossval_tls(local: dict) -> list[dict]:
    orig, err = origin_parse("tls", EXPECT["tls"]["file"])
    if orig is None or orig.get("code") != 0:
        return [{"module": "tls", "field": "(原站)", "origin": (orig or {}).get("msg", err),
                 "local": "-", "match": False, "note": "无法比较"}]
    o = (orig.get("data") or [{}])[0]
    sessions = local["sessions"]
    tls12 = next((s for s in sessions if s["protocol"] == "TLS 1.2"), sessions[0])
    rows = [
        cmp_row("tls", "会话数", len(orig.get("data") or []), local["count"],
                note="原站只返回 TLS 1.2 会话，未识别仅有加密握手的 TLS 1.3 流（本地返回 2 组）"),
        cmp_row("tls", "协议版本", o.get("protocol"), tls12["protocol"]),
        cmp_row("tls", "服务端密码套件", o.get("serverCipherSuite"), tls12["serverCipherSuite"],
                strip_space=True),
        cmp_row("tls", "客户端随机数", o.get("clientRandom"), tls12["clientRandom"]),
        cmp_row("tls", "服务端随机数", o.get("serverRandom"), tls12["serverRandom"]),
        cmp_row("tls", "是否完成握手", o.get("successHandshake"), tls12["successHandshake"]),
        cmp_row("tls", "认证方式", o.get("bilateralAuth"), tls12["bilateralAuth"]),
        cmp_row("tls", "源/目的地址", o.get("address"),
                "%s:%s----->%s:%s" % (tls12["addressInfo"]["srcAddr"], tls12["addressInfo"]["srcPort"],
                                      tls12["addressInfo"]["dstAddr"], tls12["addressInfo"]["dstPort"])),
        cmp_row("tls", "服务端证书链", cert_subjects(o.get("serverCertTextList")),
                tls12["serverCertChain"]),
        cmp_row("tls", "客户端证书链", cert_subjects(o.get("clientCertTextList")),
                tls12["clientCertChain"]),
        cmp_row("tls", "密钥交换参数", o.get("keyExchangeParams"),
                tls12["serverKeyExchange"].get("raw"),
                note="原站 = 曲线+公钥（69 字节）；本地额外附带签名算法与签名值，按前缀比对",
                prefix=True),
    ]
    # 证书 DER 必须逐字节一致
    theirs = cert_der(o.get("serverCertBase64List"))
    ours = [base64.b64decode(c["base64"]) for c in tls12["serverCertList"]]
    rows.append({"module": "tls", "field": "服务端证书 DER 一致",
                 "origin": "%d 张 / %d 字节" % (len(theirs), sum(len(x) for x in theirs)),
                 "local": "%d 张 / %d 字节" % (len(ours), sum(len(x) for x in ours)),
                 "match": theirs == ours, "note": ""})
    return rows


def crossval_ssh(local: dict) -> list[dict]:
    orig, err = origin_parse("ssh", EXPECT["ssh"]["file"])
    if orig is None or orig.get("code") != 0:
        return [{"module": "ssh", "field": "(原站)", "origin": (orig or {}).get("msg", err),
                 "local": "-", "match": False, "note": "无法比较"}]
    o = (orig.get("data") or [{}])[0]
    s = local["sessions"][0]
    return [
        cmp_row("ssh", "会话数", len(orig.get("data") or []), local["count"]),
        cmp_row("ssh", "协议版本", o.get("protocolVersion"), s["protocolVersion"]),
        cmp_row("ssh", "密钥交换算法", o.get("kexAlgorithms"), s["kexAlgorithms"]),
        cmp_row("ssh", "对称加密算法", o.get("encryptAlgorithm"), s["encryptAlgorithm"]),
        cmp_row("ssh", "MAC 算法", o.get("macAlgorithm"), s["macAlgorithm"]),
        cmp_list("ssh", "服务端加密算法列表", o.get("serverEncryptAlgorithms"), s["serverEncryptAlgorithms"]),
        cmp_list("ssh", "客户端加密算法列表", o.get("clientEncryptAlgorithms"), s["clientEncryptAlgorithms"]),
        cmp_list("ssh", "服务端 KEX 算法列表", o.get("serverKexAlgorithms"), s["serverKexAlgorithms"]),
        cmp_list("ssh", "服务端 MAC 算法列表", o.get("serverMacAlgorithms"), s["serverMacAlgorithms"]),
        cmp_list("ssh", "客户端 MAC 算法列表", o.get("clientMacAlgorithms"), s["clientMacAlgorithms"]),
        cmp_row("ssh", "客户端 DH 参数", o.get("clientDHQc"), s["clientDHQc"]),
        cmp_row("ssh", "服务端 DH 参数", o.get("serverDHQc"), s["serverDHQc"]),
        cmp_row("ssh", "签名算法", o.get("signAlgorithm"), s["signatureAlgorithm"]),
        cmp_row("ssh", "签名值", o.get("signature"), s["signature"]),
    ]


def crossval_ipsec(local_v1: dict, local_v2: dict) -> list[dict]:
    orig, err = origin_parse("ipsec", EXPECT["ipsecV1"]["file"])
    if orig is None or orig.get("code") != 0:
        return [{"module": "ipsec", "field": "(原站)", "origin": (orig or {}).get("msg", err),
                 "local": "-", "match": False, "note": "无法比较"}]
    o = (orig.get("data") or [{}])[0]
    s1 = local_v1["sessions"][0]
    rows = [
        cmp_row("ipsec", "会话数(IKEv1)", len(orig.get("data") or []), local_v1["count"]),
        cmp_row("ipsec", "协议版本", o.get("version"), s1["version"]),
        cmp_row("ipsec", "发起方 Cookie/SPI", o.get("initiatorCookie"), s1["initiatorSPI"]),
        cmp_row("ipsec", "响应方 Cookie/SPI", o.get("responseCookie"), s1["responderSPI"]),
        cmp_row("ipsec", "加密算法密钥长度", o.get("encKeyLength"), s1["encKeyLength"]),
        cmp_row("ipsec", "服务端 Nonce", o.get("serverNonce"), s1["serverNonce"]),
        cmp_row("ipsec", "客户端 Nonce", o.get("clientNonce"), s1["clientNonce"],
                note="原站返回 null（其实现未取到请求侧 Nonce）"),
    ]
    # IKEv2 原站不支持，只做本地自证
    resp2, err2 = origin_parse("ipsec", EXPECT["ipsec"]["file"])
    rows.append({
        "module": "ipsec", "field": "IKEv2 支持情况",
        "origin": (resp2 or {}).get("msg", err2) if resp2 else err2,
        "local": "%d 组会话 / %s" % (local_v2["count"], local_v2["sessions"][0]["protocol"]),
        "match": False,
        "note": "原站仅解析 IKEv1，对 IKEv2 样例返回 No IPsec protocol data found",
    })
    return rows


def crossval_ukey(local: dict) -> list[dict]:
    orig, err = origin_parse("ukey", EXPECT["ukey"]["file"])
    msg = (orig or {}).get("msg", err)
    return [{
        "module": "ukey", "field": "UKey 解析",
        "origin": msg or "无响应",
        "local": "厂商=%s，APDU=%d 条，证书=%d 张" % (
            local["vendor"], local["apduCount"], len(local["certificates"])),
        "match": False,
        "note": "原站 ukey 接口对该样例（以及任意输入）返回 500 NPE，无法交叉验证",
    }]


# ---------------------------------------------------------------- 独立核对
def independent_checks() -> list[dict]:
    rows: list[dict] = []
    tls = local_parse("tls")
    tls12 = next(s for s in tls["sessions"] if s["protocol"] == "TLS 1.2")
    der = base64.b64decode(tls12["serverCertList"][0]["base64"])
    text = openssl_check(der)
    rows.append({
        "module": "独立核对", "field": "openssl 解析服务端证书",
        "origin": text or "(openssl 不可用)",
        "local": tls12["serverCertList"][0]["subject"],
        "match": bool(text) and "test-server" in text,
        "note": "openssl x509 -inform DER 独立解析",
    })
    for kind, label in (("tls", "TLS"), ("ssh", "SSH"), ("ipsec", "IKEv2")):
        info = dpkt_check(EXPECT[kind]["file"])
        if not info.get("ok"):
            rows.append({"module": "独立核对", "field": "dpkt 读包(%s)" % label,
                         "origin": info.get("reason", ""), "local": "-", "match": False, "note": ""})
            continue
        mine = local_parse(kind)["meta"]["packets"]
        rows.append({
            "module": "独立核对", "field": "dpkt 报文数(%s)" % label,
            "origin": info["packets"], "local": mine,
            "match": info["packets"] == mine,
            "note": "TCP=%d UDP=%d" % (info["tcp"], info["udp"]),
        })
    ukey = local_parse("ukey")
    if ukey["certificates"]:
        text = openssl_check(base64.b64decode(ukey["certificates"][0]["base64"]))
        rows.append({
            "module": "独立核对", "field": "openssl 解析 UKey 证书",
            "origin": text or "(openssl 不可用)",
            "local": ukey["certificates"][0]["subject"],
            "match": bool(text) and "ukey-user" in text, "note": "",
        })
    return rows


def main() -> int:
    rows: list[dict] = []
    local_tls = local_parse("tls")
    local_ssh = local_parse("ssh")
    local_v1 = local_parse("ipsecV1")
    local_v2 = local_parse("ipsec")
    local_ukey = local_parse("ukey")

    rows += crossval_tls(local_tls)
    rows += crossval_ssh(local_ssh)
    rows += crossval_ipsec(local_v1, local_v2)
    rows += crossval_ukey(local_ukey)
    rows += independent_checks()

    report = {"origin": ORIGIN, "generatedAt": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
              "rows": rows,
              "summary": {
                  "total": len(rows),
                  "match": sum(1 for r in rows if r["match"]),
                  "mismatch": sum(1 for r in rows if not r["match"]),
              }}
    out = os.path.join(FIX, "crossval_report.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    for r in rows:
        flag = "一致  " if r["match"] else "差异/说明"
        print("%-6s %-24s %s" % (flag, r["module"] + "/" + r["field"],
                                 ("原站=" + str(r["origin"])[:56] + " | 本地=" + str(r["local"])[:56])))
        if r["note"]:
            print("        └ %s" % r["note"])
    print("\n一致 %d / 共 %d 项，报告：%s" % (report["summary"]["match"], len(rows), out))
    if "--strict" in sys.argv:
        return 0 if report["summary"]["mismatch"] == 0 else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
