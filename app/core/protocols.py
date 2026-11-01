"""协议流量包解析：TLS / SSH / IPSec(IKE) / UKey(CCID-APDU)。

全部为本地真实解析，不依赖外部服务：
- pcap / pcapng 由本模块自行解析（以太网、裸 IP、Linux SLL、USBPcap 链路类型）
- TCP 流重组后逐字段解析握手报文，证书使用 cryptography 解析
- 加密载荷（TLS 1.3 之后的握手、IKEv2 SK、SSH NEWKEYS 之后的报文）无法解密，
  结果中会明确标注，不会伪造任何字段
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import struct
from typing import Any

from .common import ToolError

try:  # cryptography 为项目依赖，缺失时降级为“证书不展开”
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False


def _now_text() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 基础读取工具
# ---------------------------------------------------------------------------
class _Reader:
    """大端读取器，越界时抛出中文错误。"""

    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes, pos: int = 0):
        self.buf = buf
        self.pos = pos

    def eof(self) -> bool:
        return self.pos >= len(self.buf)

    def left(self) -> int:
        return len(self.buf) - self.pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.buf):
            raise ToolError("报文长度不足，数据可能被截断")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def peek(self, n: int = 1) -> bytes:
        return self.buf[self.pos:self.pos + n]


def _hex(data: bytes) -> str:
    return data.hex()


# ---------------------------------------------------------------------------
# pcap / pcapng 读取
# ---------------------------------------------------------------------------
_LINKTYPE_NAMES = {
    0: "NULL", 1: "Ethernet", 12: "RawIP", 101: "RawIP", 113: "LinuxSLL",
    189: "USB_LINUX", 228: "IPv4", 229: "IPv6", 249: "USBPcap",
}

_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = (12, 14, 101, 228, 229)
_LINKTYPE_SLL = 113
_LINKTYPE_USBPCAP = 249
_LINKTYPE_USB_LINUX = 189


def read_capture(data: bytes) -> dict:
    """解析 pcap 或 pcapng，返回 {"packets": [...], "linktypes": [...], "format": "pcap"}。"""
    if not data or len(data) < 24:
        raise ToolError("流量包为空或长度不足，无法解析")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        packets, linktypes = _read_pcapng(data)
        fmt = "pcapng"
    else:
        packets, linktypes = _read_pcap(data)
        fmt = "pcap"
    if not packets:
        raise ToolError("流量包中没有可解析的报文")
    return {"packets": packets, "linktypes": linktypes, "format": fmt}


def _read_pcap(data: bytes) -> tuple[list[dict], list[int]]:
    head = data[:4]
    if head in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nano = "<", head[0] == 0x4D
    elif head in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nano = ">", head[3] == 0x4D
    else:
        raise ToolError("不是有效的 pcap / pcapng 文件（文件头标识不正确）")
    if len(data) < 24:
        raise ToolError("pcap 文件头不完整")
    (_, _, _, _, _, linktype) = struct.unpack(endian + "HHiiii", data[4:24])
    pos = 24
    packets: list[dict] = []
    unit = 1_000_000_000 if nano else 1_000_000
    while pos + 16 <= len(data):
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        if incl > len(data) - pos:
            break
        raw = data[pos:pos + incl]
        pos += incl
        packets.append({"ts": ts_sec + ts_frac / unit, "linktype": linktype, "raw": raw})
    return packets, [linktype]


def _read_pcapng(data: bytes) -> tuple[list[dict], list[int]]:
    if len(data) < 12 or data[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
        raise ToolError("pcapng 文件缺少有效的字节序标识")
    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    pos = 0
    packets: list[dict] = []
    interfaces: list[dict] = []
    while pos + 12 <= len(data):
        btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
        if btype == 0x0A0D0D0A:
            blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 0x00000001 and len(body) >= 8:      # Interface Description Block
            linktype, _res, _snap = struct.unpack(endian + "HHI", body[:8])
            tsresol = 6
            i = 8
            while i + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[i:i + 4])
                if code == 0:
                    break
                val = body[i + 4:i + 4 + olen]
                if code == 9 and val:
                    tsresol = val[0] & 0x7F
                i += 4 + olen + ((4 - olen % 4) % 4)
            interfaces.append({"linktype": linktype, "tsresol": tsresol})
        elif btype == 0x00000006 and len(body) >= 20:   # Enhanced Packet Block
            iface, tsh, tsl, caplen, _olen = struct.unpack(endian + "IIIII", body[:20])
            info = interfaces[iface] if iface < len(interfaces) else {"linktype": 1, "tsresol": 6}
            raw = body[20:20 + caplen]
            ts = ((tsh << 32) | tsl) / (10 ** info["tsresol"])
            packets.append({"ts": ts, "linktype": info["linktype"], "raw": raw})
        elif btype == 0x00000003 and len(body) >= 4:    # Simple Packet Block
            info = interfaces[0] if interfaces else {"linktype": 1}
            blen2 = len(body) - 4
            packets.append({"ts": 0.0, "linktype": info["linktype"], "raw": body[4:4 + blen2]})
        pos += blen
    return packets, [i["linktype"] for i in interfaces]


# ---------------------------------------------------------------------------
# 链路层 / IP / TCP / UDP 解码
# ---------------------------------------------------------------------------
def _decode_packets(capture: dict) -> list[dict]:
    out: list[dict] = []
    for item in capture["packets"]:
        rec = _decode_link(item["linktype"], item["raw"], item["ts"])
        if rec:
            out.append(rec)
    return out


def _decode_link(linktype: int, raw: bytes, ts: float) -> dict | None:
    if linktype == _LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return None
        etype = int.from_bytes(raw[12:14], "big")
        off = 14
        while etype in (0x8100, 0x88A8) and len(raw) >= off + 4:
            etype = int.from_bytes(raw[off + 2:off + 4], "big")
            off += 4
        if etype == 0x0800:
            return _decode_ipv4(raw[off:], ts, "ethernet")
        if etype == 0x86DD:
            return _decode_ipv6(raw[off:], ts, "ethernet")
        return {"ts": ts, "l2": "ethernet", "proto": "other", "payload": raw[off:], "ethertype": etype}
    if linktype in _LINKTYPE_RAW:
        return _decode_ip(raw, ts, "rawip")
    if linktype == _LINKTYPE_SLL:
        if len(raw) < 16:
            return None
        return _decode_ip(raw[16:], ts, "linux-sll")
    if linktype == _LINKTYPE_USBPCAP:
        return _decode_usbpcap(raw, ts)
    if linktype == _LINKTYPE_USB_LINUX:
        return {"ts": ts, "l2": "usb-linux", "proto": "usb", "payload": raw[64:] if len(raw) > 64 else raw}
    return {"ts": ts, "l2": "linktype-%d" % linktype, "proto": "other", "payload": raw}


def _decode_usbpcap(raw: bytes, ts: float) -> dict:
    if len(raw) < 27:
        return {"ts": ts, "l2": "usbpcap", "proto": "usb", "payload": raw}
    header_len = int.from_bytes(raw[0:2], "little")
    if not (27 <= header_len <= 64):
        header_len = 27
    data_len = int.from_bytes(raw[23:27], "little")
    payload = raw[header_len:header_len + data_len] if data_len else raw[header_len:]
    return {"ts": ts, "l2": "usbpcap", "proto": "usb", "payload": payload or raw[header_len:]}


def _decode_ip(raw: bytes, ts: float, l2: str) -> dict | None:
    if not raw:
        return None
    ver = raw[0] >> 4
    if ver == 4:
        return _decode_ipv4(raw, ts, l2)
    if ver == 6:
        return _decode_ipv6(raw, ts, l2)
    return {"ts": ts, "l2": l2, "proto": "other", "payload": raw}


def _decode_ipv4(raw: bytes, ts: float, l2: str) -> dict | None:
    if len(raw) < 20:
        return None
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(raw):
        return None
    total = int.from_bytes(raw[2:4], "big") or len(raw)
    proto = raw[9]
    frag = int.from_bytes(raw[6:8], "big")
    src = str(ipaddress.IPv4Address(raw[12:16]))
    dst = str(ipaddress.IPv4Address(raw[16:20]))
    body = raw[ihl:max(ihl, min(total, len(raw)))]
    rec = {"ts": ts, "l2": l2, "ipVersion": 4, "src": src, "dst": dst}
    if frag & 0x1FFF:
        rec.update({"proto": "fragment", "payload": body})
        return rec
    return _decode_l4(rec, proto, body, ts)


def _decode_ipv6(raw: bytes, ts: float, l2: str) -> dict | None:
    if len(raw) < 40:
        return None
    nxt = raw[6]
    plen = int.from_bytes(raw[4:6], "big")
    src = str(ipaddress.IPv6Address(raw[8:24]))
    dst = str(ipaddress.IPv6Address(raw[24:40]))
    body = raw[40:40 + plen] if plen else raw[40:]
    rec = {"ts": ts, "l2": l2, "ipVersion": 6, "src": src, "dst": dst}
    return _decode_l4(rec, nxt, body, ts)


def _decode_l4(rec: dict, proto: int, body: bytes, ts: float) -> dict:
    if proto == 6 and len(body) >= 20:
        sport = int.from_bytes(body[0:2], "big")
        dport = int.from_bytes(body[2:4], "big")
        seq = int.from_bytes(body[4:8], "big")
        ack = int.from_bytes(body[8:12], "big")
        off = (body[12] >> 4) * 4
        flags = body[13]
        payload = body[off:] if 20 <= off <= len(body) else b""
        rec.update({
            "proto": "tcp", "sport": sport, "dport": dport, "seq": seq, "ack": ack,
            "flags": flags, "payload": payload,
        })
        return rec
    if proto == 17 and len(body) >= 8:
        sport = int.from_bytes(body[0:2], "big")
        dport = int.from_bytes(body[2:4], "big")
        ulen = int.from_bytes(body[4:6], "big")
        payload = body[8:ulen] if 8 <= ulen <= len(body) else body[8:]
        rec.update({"proto": "udp", "sport": sport, "dport": dport, "payload": payload})
        return rec
    rec.update({"proto": "ip-proto-%d" % proto, "payload": body})
    return rec


def _reassemble(segs: list[tuple[float, int, bytes]]) -> tuple[bytes, list[tuple[int, int, float]]]:
    """按 seq 重组单方向 TCP 流，返回 (数据, [(起始偏移, 结束偏移, 时间戳)])。"""
    segs = [s for s in segs if s[2]]
    if not segs:
        return b"", []
    segs.sort(key=lambda s: (s[1], s[0]))
    base = segs[0][1]
    buf = bytearray()
    spans: list[tuple[int, int, float]] = []
    for ts, seq, payload in segs:
        start = seq - base
        if start < 0:                       # 早于基准（异常/重传）
            cut = -start
            if cut >= len(payload):
                continue
            payload, start = payload[cut:], 0
        if start > len(buf):                # 中间丢包：保留空洞位置
            buf.extend(b"\x00" * (start - len(buf)))
        if start + len(payload) <= len(buf):  # 纯重传
            continue
        if start < len(buf):
            payload = payload[len(buf) - start:]
            start = len(buf)
        buf.extend(payload)
        spans.append((start, len(buf), ts))
    return bytes(buf), spans


def _ts_at(spans: list[tuple[int, int, float]], off: int) -> float:
    low, high = 0, len(spans) - 1
    while low <= high:
        mid = (low + high) // 2
        s, e, ts = spans[mid]
        if off < s:
            high = mid - 1
        elif off >= e:
            low = mid + 1
        else:
            return ts
    if spans:
        return spans[-1][2] if off >= spans[-1][1] else spans[0][2]
    return 0.0


def _fmt_time(ts: float) -> str:
    if not ts:
        return ""
    dt = datetime.datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S.%f")[:-3]


def _tcp_flows(packets: list[dict]) -> list[dict]:
    flows: dict[tuple, dict] = {}
    for p in packets:
        if p.get("proto") != "tcp":
            continue
        ea = (p["src"], p["sport"])
        eb = (p["dst"], p["dport"])
        key = tuple(sorted([ea, eb]))
        fl = flows.get(key)
        if fl is None:
            fl = {"a": key[0], "b": key[1], "ab": [], "ba": []}
            flows[key] = fl
        (fl["ab"] if ea == key[0] else fl["ba"]).append((p["ts"], p["seq"], p.get("payload") or b""))
    return list(flows.values())


def _flow_match(flow: dict, ips: tuple[str, str], ports: tuple[int | None, int | None]) -> bool:
    src_ip, dst_ip = ips
    src_port, dst_port = ports
    ends = [(flow["a"][0], flow["a"][1]), (flow["b"][0], flow["b"][1])]
    if src_ip and dst_ip:
        pairs = {(ends[0], ends[1]), (ends[1], ends[0])}
        if not any(p[0][0] == src_ip and p[1][0] == dst_ip for p in pairs):
            return False
    elif src_ip and src_ip not in (ends[0][0], ends[1][0]):
        return False
    elif dst_ip and dst_ip not in (ends[0][0], ends[1][0]):
        return False
    if src_port and dst_port:
        if not ({ends[0][1], ends[1][1]} >= {int(src_port), int(dst_port)}):
            return False
    elif src_port and int(src_port) not in (ends[0][1], ends[1][1]):
        return False
    elif dst_port and int(dst_port) not in (ends[0][1], ends[1][1]):
        return False
    return True


def parse_ips_from_filename(name: str) -> list[str]:
    """从抓包文件名中提取 IPv4/IPv6 地址（形如 src_10.0.0.1_dst_10.0.0.2.pcap）。"""
    import re

    found: list[str] = []
    for m in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", name or ""):
        try:
            ip = str(ipaddress.IPv4Address(m))
        except ValueError:
            continue
        if ip not in found:
            found.append(ip)
    return found

# ---------------------------------------------------------------------------
# 证书解析
# ---------------------------------------------------------------------------
def _pem_of(der: bytes) -> str:
    import base64

    text = base64.b64encode(der).decode()
    body = "\n".join(text[i:i + 64] for i in range(0, len(text), 64))
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"


def _key_desc(pub) -> tuple[str, int]:
    if not _HAVE_CRYPTO:
        return ("", 0)
    if isinstance(pub, rsa.RSAPublicKey):
        return ("RSA", pub.key_size)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return ("ECC/" + pub.curve.name, pub.key_size)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return ("Ed25519", 256)
    return (type(pub).__name__, 0)


def _cert_info(der: bytes) -> dict:
    import base64

    info: dict[str, Any] = {
        "length": len(der),
        "base64": base64.b64encode(der).decode(),
        "pem": _pem_of(der),
        "sha256": hashlib.sha256(der).hexdigest(),
        "parsed": False,
        "subject": "",
        "issuer": "",
        "serial": "",
        "notBefore": "",
        "notAfter": "",
        "signatureAlgorithm": "",
        "publicKeyAlgorithm": "",
        "keyBits": 0,
        "isCA": False,
        "san": [],
        "selfSigned": False,
    }
    if not _HAVE_CRYPTO:
        info["error"] = "运行环境缺少 cryptography，无法解析证书内容"
        return info
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:
        info["error"] = "证书 DER 解析失败：%s" % exc
        return info
    info["parsed"] = True
    info["subject"] = cert.subject.rfc4514_string()
    info["issuer"] = cert.issuer.rfc4514_string()
    info["serial"] = format(cert.serial_number, "X")
    info["notBefore"] = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S") if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
    info["notAfter"] = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S") if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)
    info["signatureAlgorithm"] = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid)
    alg, bits = _key_desc(cert.public_key())
    info["publicKeyAlgorithm"] = alg
    info["keyBits"] = bits
    info["selfSigned"] = cert.subject == cert.issuer
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        info["isCA"] = bool(bc.value.ca)
    except Exception:
        info["isCA"] = False
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info["san"] = [str(v) for v in san.value.get_values_for_type(x509.DNSName)]
    except Exception:
        info["san"] = []
    info["daysLeft"] = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days if hasattr(cert, "not_valid_after_utc") else None
    return info


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

CIPHER_SUITES = {
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x00C6: "TLS_SM4_GCM_SM3",
    0x00C7: "TLS_SM4_CCM_SM3",
    0xE011: "TLS_ECC_SM4_CBC_SM3",
    0xE013: "TLS_ECDHE_SM4_CBC_SM3",
    0xE051: "TLS_ECC_SM4_GCM_SM3",
}

TLS_HANDSHAKE_NAMES = {
    0: "HelloRequest", 1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
    5: "EndOfEarlyData", 8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
    13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
    16: "ClientKeyExchange", 20: "Finished", 24: "KeyUpdate", 25: "CompressedCertificate",
}

TLS_EXT_NAMES = {
    0: "server_name", 10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms",
    16: "application_layer_protocol_negotiation", 21: "padding", 23: "extended_master_secret",
    35: "session_ticket", 43: "supported_versions", 45: "psk_key_exchange_modes",
    51: "key_share", 65281: "renegotiation_info",
    0x2A: "early_data",
}

SIG_ALGS = {
    0x0201: ("rsa", "sha1"), 0x0401: ("rsa", "sha256"), 0x0501: ("rsa", "sha384"), 0x0601: ("rsa", "sha512"),
    0x0203: ("ecdsa", "sha1"), 0x0403: ("ecdsa", "sha256"), 0x0503: ("ecdsa", "sha384"), 0x0603: ("ecdsa", "sha512"),
    0x0804: ("pss", "sha256"), 0x0805: ("pss", "sha384"), 0x0806: ("pss", "sha512"),
    0x0809: ("pss", "sha256"), 0x080A: ("pss", "sha384"), 0x080B: ("pss", "sha512"),
    0x0708: ("ed25519", None), 0x0807: ("ed448", None),
}

SIG_ALG_NAMES = {
    0x0201: "rsa_pkcs1_sha1", 0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0203: "ecdsa_sha1", 0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512", 0x0809: "rsa_pss_pss_sha256", 0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512", 0x0708: "ed25519", 0x0807: "ed448",
}

_HASH_NAMES = {
    "sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
} if _HAVE_CRYPTO else {}


def _digest(name: str):
    return _HASH_NAMES[name]()


def _verify_with_key(pub, sig_alg: int, data: bytes, signature: bytes) -> tuple[bool | None, str]:
    """用公钥验证签名，返回 (是否通过 / None 表示无法判定, 说明)。"""
    if not _HAVE_CRYPTO:
        return None, "运行环境缺少 cryptography，无法验签"
    kind = SIG_ALGS.get(sig_alg)
    if not kind:
        return None, "未识别的签名算法 0x%04X" % sig_alg
    mode, hname = kind
    try:
        if mode == "rsa" and isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, data, padding.PKCS1v15(), _digest(hname))
            return True, "验签通过（RSA PKCS#1 v1.5）"
        if mode == "pss" and isinstance(pub, rsa.RSAPublicKey):
            digest = _digest(hname)
            pub.verify(signature, data, padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.DIGEST_LENGTH), digest)
            return True, "验签通过（RSA-PSS）"
        if mode == "ecdsa" and isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(_digest(hname)))
            return True, "验签通过（ECDSA）"
        if mode == "ed25519" and isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, data)
            return True, "验签通过（Ed25519）"
        return None, "公钥类型（%s）与签名算法 %s 不匹配" % (type(pub).__name__, SIG_ALG_NAMES.get(sig_alg, sig_alg))
    except InvalidSignature:
        return False, "验签失败：签名值与证书公钥不匹配"
    except Exception as exc:
        return None, "验签异常：%s" % exc


def _pub_from_cert_der(der: bytes | None):
    if not der or not _HAVE_CRYPTO:
        return None
    try:
        return x509.load_der_x509_certificate(der).public_key()
    except Exception:
        return None


def _tls_records(buf: bytes, spans: list[tuple[int, int, float]]) -> list[dict]:
    out: list[dict] = []
    i = 0
    while i + 5 <= len(buf):
        ctype = buf[i]
        ver = int.from_bytes(buf[i + 1:i + 3], "big")
        ln = int.from_bytes(buf[i + 3:i + 5], "big")
        if ctype not in (20, 21, 22, 23, 24) or (ver >> 8) != 3 or ln > 18432:
            break
        if i + 5 + ln > len(buf):
            break
        out.append({
            "type": ctype, "version": ver, "length": ln,
            "body": buf[i + 5:i + 5 + ln], "ts": _ts_at(spans, i), "offset": i,
        })
        i += 5 + ln
    return out


def _tls_handshake_messages(records: list[dict]) -> list[dict]:
    """把跨记录的握手报文拼接成完整消息列表。"""
    pending = b""
    start_ts = 0.0
    msgs: list[dict] = []
    for rec in records:
        if rec["type"] != 22:
            continue
        if not pending:
            start_ts = rec["ts"]
        pending += rec["body"]
        pos = 0
        while pos + 4 <= len(pending):
            mtype = pending[pos]
            mlen = int.from_bytes(pending[pos + 1:pos + 4], "big")
            if pos + 4 + mlen > len(pending):
                break
            body = pending[pos + 4:pos + 4 + mlen]
            raw = pending[pos:pos + 4 + mlen]
            msgs.append({
                "type": mtype,
                "name": TLS_HANDSHAKE_NAMES.get(mtype, "Handshake(%d)" % mtype),
                "body": body, "raw": raw, "ts": start_ts,
            })
            pos += 4 + mlen
        pending = pending[pos:]
    return msgs


def _parse_extensions(data: bytes) -> dict[int, bytes]:
    exts: dict[int, bytes] = {}
    r = _Reader(data)
    while r.left() >= 4:
        etype = r.u16()
        elen = r.u16()
        if elen > r.left():
            break
        exts[etype] = r.take(elen)
    return exts


def _parse_client_hello(body: bytes) -> dict:
    r = _Reader(body)
    hello: dict[str, Any] = {}
    hello["legacyVersion"] = r.u16()
    hello["random"] = r.take(32)
    sid_len = r.u8()
    hello["sessionId"] = r.take(sid_len)
    cs_len = r.u16()
    suites = []
    for _ in range(cs_len // 2):
        suites.append(r.u16())
    hello["cipherSuites"] = suites
    comp_len = r.u8()
    hello["compressions"] = list(r.take(comp_len))
    exts: dict[int, bytes] = {}
    if r.left() >= 2:
        ext_total = r.u16()
        exts = _parse_extensions(r.take(min(ext_total, r.left())))
    hello["extensions"] = exts
    hello["extTypes"] = sorted(exts)
    if 0 in exts:
        try:
            rr = _Reader(exts[0])
            rr.u16()          # server_name_list 总长度
            rr.u8()           # name_type: 0 = host_name
            name_len = rr.u16()
            hello["sni"] = rr.take(min(name_len, rr.left())).decode("ascii", "replace")
        except Exception:
            hello["sni"] = ""
    if 43 in exts:
        try:
            rr = _Reader(exts[43])
            n = rr.u8()
            hello["supportedVersions"] = [rr.u16() for _ in range(n // 2)]
        except Exception:
            hello["supportedVersions"] = []
    if 10 in exts:
        try:
            rr = _Reader(exts[10])
            n = rr.u16()
            hello["groups"] = [rr.u16() for _ in range(n // 2)]
        except Exception:
            hello["groups"] = []
    if 13 in exts:
        try:
            rr = _Reader(exts[13])
            n = rr.u16()
            hello["signatureAlgorithms"] = [rr.u16() for _ in range(n // 2)]
        except Exception:
            hello["signatureAlgorithms"] = []
    if 16 in exts:
        try:
            rr = _Reader(exts[16])
            _n = rr.u16()
            alpn = []
            while rr.left() >= 1:
                ln = rr.u8()
                alpn.append(rr.take(ln).decode("ascii", "replace"))
            hello["alpn"] = alpn
        except Exception:
            hello["alpn"] = []
    return hello


def _parse_server_hello(body: bytes) -> dict:
    r = _Reader(body)
    hello: dict[str, Any] = {}
    hello["legacyVersion"] = r.u16()
    hello["random"] = r.take(32)
    sid_len = r.u8()
    hello["sessionId"] = r.take(sid_len)
    hello["cipherSuite"] = r.u16()
    hello["compression"] = r.u8()
    exts: dict[int, bytes] = {}
    if r.left() >= 2:
        ext_total = r.u16()
        exts = _parse_extensions(r.take(min(ext_total, r.left())))
    hello["extensions"] = exts
    hello["extTypes"] = sorted(exts)
    if 43 in exts and len(exts[43]) == 2:
        hello["supportedVersion"] = int.from_bytes(exts[43], "big")
    if 51 in exts and len(exts[51]) >= 4:
        hello["keyShareGroup"] = int.from_bytes(exts[51][0:2], "big")
        klen = int.from_bytes(exts[51][2:4], "big")
        hello["keyShare"] = exts[51][4:4 + klen]
    return hello


def _parse_cert_list(body: bytes, is_tls13: bool) -> list[dict]:
    r = _Reader(body)
    if is_tls13:
        ctx_len = r.u8()
        r.take(ctx_len)
        total = r.u24()
        data = r.take(min(total, r.left()))
    else:
        total = r.u24()
        data = r.take(min(total, r.left()))
    certs: list[dict] = []
    rr = _Reader(data)
    while rr.left() >= 3:
        ln = rr.u24()
        if ln == 0 or ln > rr.left():
            break
        der = rr.take(ln)
        certs.append(_cert_info(der))
        if is_tls13:                      # 每条证书后带扩展
            if rr.left() >= 2:
                ext_len = rr.u16()
                rr.take(min(ext_len, rr.left()))
    return certs


def _suite_name(code: int) -> str:
    name = CIPHER_SUITES.get(code)
    return "%s (0x%04X)" % (name, code) if name else "TLS_UNKNOWN_0x%04X" % code


def _looks_like_tls(buf: bytes) -> bool:
    return len(buf) >= 6 and buf[0] in (20, 21, 22, 23) and buf[1] == 0x03


def _has_client_hello(buf: bytes) -> bool:
    idx = buf.find(b"\x01\x00\x00")
    return _looks_like_tls(buf) and idx >= 0 and idx < 16


def _has_server_hello(buf: bytes) -> bool:
    idx = buf.find(b"\x02\x00\x00", 0, 16)
    return _looks_like_tls(buf) and idx >= 0


def _build_tls_session(client: dict, server: dict, index: int) -> dict | None:
    c_records = _tls_records(client["data"], client["spans"])
    s_records = _tls_records(server["data"], server["spans"])
    c_msgs = _tls_handshake_messages(c_records)
    s_msgs = _tls_handshake_messages(s_records)
    client_hello = next((m for m in c_msgs if m["type"] == 1), None)
    server_hello = next((m for m in s_msgs if m["type"] == 2), None)
    if client_hello is None and server_hello is None:
        return None

    ch = _parse_client_hello(client_hello["body"]) if client_hello else {}
    sh = _parse_server_hello(server_hello["body"]) if server_hello else {}

    # 协议版本：优先使用 ServerHello 的 supported_versions 扩展
    proto_code = sh.get("supportedVersion") or sh.get("legacyVersion") or ch.get("legacyVersion") or 0x0303
    if not sh and ch.get("supportedVersions"):
        proto_code = max(ch["supportedVersions"])
    protocol = TLS_VERSIONS.get(proto_code, "TLS 0x%04X" % proto_code)
    is_tls13 = proto_code == 0x0304

    notes: list[str] = []
    timeline: list[dict] = []

    def add_event(ts: float, who: str, name: str, detail: str = "") -> None:
        timeline.append({"time": _fmt_time(ts), "from": who, "message": name, "detail": detail})

    if client_hello:
        add_event(client_hello["ts"], "客户端", "ClientHello",
                  "支持 %d 个密码套件，SNI=%s" % (len(ch.get("cipherSuites", [])), ch.get("sni") or "无"))
    else:
        notes.append("抓包中未捕获 ClientHello（可能为中途抓包），客户端随机数与套件列表不可得")
    if server_hello:
        add_event(server_hello["ts"], "服务端", "ServerHello", "选定 %s" % _suite_name(sh.get("cipherSuite", 0)))

    for rec in c_records + s_records:
        if rec["type"] == 20:
            add_event(rec["ts"], "客户端" if rec in c_records else "服务端", "ChangeCipherSpec", "")
        elif rec["type"] == 21:
            add_event(rec["ts"], "客户端" if rec in c_records else "服务端", "Alert", rec["body"].hex())

    for m in sorted(c_msgs + s_msgs, key=lambda x: x["ts"]):
        if m["type"] in (1, 2):
            continue
        who = "客户端" if any(m is x for x in c_msgs) else "服务端"
        add_event(m["ts"], who, m["name"], "长度 %d 字节" % len(m["body"]))

    # 证书链
    server_certs = next((_parse_cert_list(m["body"], is_tls13) for m in s_msgs if m["type"] == 11), [])
    client_certs = next((_parse_cert_list(m["body"], is_tls13) for m in c_msgs if m["type"] == 11), [])
    cert_request = next((m for m in s_msgs if m["type"] == 13), None)

    # ServerKeyExchange（TLS 1.2 ECDHE/DHE）
    skx = next((m for m in s_msgs if m["type"] == 12), None)
    skx_info: dict[str, Any] = {}
    if skx:
        skx_info = _parse_server_key_exchange(skx, ch, sh, server_certs)

    # 握手消息序列（用于 CertificateVerify 验签）
    transcript: list[dict] = []
    for m in sorted(c_msgs + s_msgs, key=lambda x: x["ts"]):
        transcript.append(m)

    def cv_info(msg: dict, side: str) -> dict:
        sig_alg = int.from_bytes(msg["body"][0:2], "big") if len(msg["body"]) >= 4 else 0
        sig_len = int.from_bytes(msg["body"][2:4], "big") if len(msg["body"]) >= 4 else 0
        signature = msg["body"][4:4 + sig_len] if sig_len else b""
        info = {
            "present": True,
            "side": side,
            "signatureAlgorithm": SIG_ALG_NAMES.get(sig_alg, "0x%04X" % sig_alg),
            "signatureAlgCode": "0x%04X" % sig_alg,
            "signature": signature.hex(),
            "signatureLength": len(signature),
            "plaintext": "",
            "publicKey": "",
            "checked": False,
            "result": None,
            "reason": "",
        }
        if not signature:
            info["reason"] = "签名值为空"
            return info
        # 计算签名原文
        try:
            pos = next(i for i, x in enumerate(transcript) if x is msg)
            before = transcript[:pos]
            if is_tls13:
                ctx = b"TLS 1.3, " + (b"server" if side == "服务端" else b"client") + b" CertificateVerify"
                digest_name = "sha384" if sh.get("cipherSuite", 0) in (0x1302,) else "sha256"
                th = hashlib.new(digest_name, b"".join(m["raw"] for m in before)).digest()
                data = b"\x20" * 64 + ctx + b"\x00" + th
                info["plaintext"] = "64 个 0x20 + \"TLS 1.3, %s CertificateVerify\" + 0x00 + %s 摘要" % ("server" if side == "服务端" else "client", digest_name.upper())
            else:
                data = b"".join(m["raw"] for m in before)
                info["plaintext"] = "在此之前全部握手报文的拼接（%d 字节，%d 条消息）" % (len(data), len(before))
        except ValueError:
            info["reason"] = "无法定位该消息在握手序列中的位置"
            return info
        certs = server_certs if side == "服务端" else client_certs
        pub = _pub_from_cert_der(_first_der(certs))
        if pub is None:
            info["reason"] = "缺少%s证书公钥，无法验签" % ("服务端" if side == "服务端" else "客户端")
            return info
        info["publicKey"] = _pub_text(pub)
        passed, reason = _verify_with_key(pub, sig_alg, data, signature)
        info["checked"] = passed is not None
        info["result"] = passed
        info["reason"] = reason
        return info

    server_cv = next((m for m in s_msgs if m["type"] == 15), None)
    client_cv = next((m for m in c_msgs if m["type"] == 15), None)
    server_cert_verify = cv_info(server_cv, "服务端") if server_cv else {"present": False}
    client_cert_verify = cv_info(client_cv, "客户端") if client_cv else {"present": False}

    # Finished / 握手完成判定
    c_finished = any(m["type"] == 20 for m in c_msgs)
    s_finished = any(m["type"] == 20 for m in s_msgs)
    success = c_finished and s_finished
    if is_tls13 and not success:
        app_data_after_sh = [
            r for r in s_records
            if r["type"] == 23 and server_hello and r["ts"] >= server_hello["ts"]
        ]
        if app_data_after_sh:
            success = True
            notes.append("TLS 1.3 的 Finished 位于加密记录中，本工具依据 ServerHello 之后的应用数据推断握手已完成")

    if not server_hello:
        notes.append("仅捕获到 ClientHello，未捕获服务端响应，无法判断握手是否完成")
    if is_tls13:
        notes.append("TLS 1.3 的 Certificate / CertificateVerify 为加密报文，被动抓包无法解析证书链与签名")
    if not success and server_hello and not is_tls13:
        notes.append("未同时捕获到双方 Finished 报文，握手可能未完成或抓包不完整")

    bilateral = bool(client_certs) or bool(cert_request)

    addr_info = {
        "srcAddr": client["addr"][0], "srcPort": client["addr"][1],
        "dstAddr": server["addr"][0], "dstPort": server["addr"][1],
    }

    session = {
        "index": index,
        "address": "%s:%s-%s:%s" % (addr_info["srcAddr"], addr_info["srcPort"], addr_info["dstAddr"], addr_info["dstPort"]),
        "addressInfo": addr_info,
        "protocol": protocol,
        "protocolVersionCode": "0x%04X" % proto_code,
        "successHandshake": bool(success),
        "bilateralAuth": bool(bilateral),
        "authMode": "双向认证" if bilateral else "单向认证",
        "serverCipherSuite": _suite_name(sh["cipherSuite"]) if sh.get("cipherSuite") else "",
        "cipherSuiteCode": "0x%04X" % sh["cipherSuite"] if sh.get("cipherSuite") else "",
        "clientCipherSuites": [_suite_name(c) for c in ch.get("cipherSuites", [])],
        "clientCipherSuiteCodes": ["0x%04X" % c for c in ch.get("cipherSuites", [])],
        "clientRandom": ch.get("random", b"").hex(),
        "serverRandom": sh.get("random", b"").hex(),
        "sni": ch.get("sni", ""),
        "alpn": ch.get("alpn", []),
        "clientCertList": client_certs,
        "serverCertList": server_certs,
        "clientCertChain": [c.get("subject") for c in client_certs],
        "serverCertChain": [c.get("subject") for c in server_certs],
        "serverKeyExchange": skx_info,
        "serverCertVerify": server_cert_verify,
        "clientCertVerify": client_cert_verify,
        "serverSign": (skx_info.get("signature") or server_cert_verify.get("signature") or ""),
        "clientSign": client_cert_verify.get("signature", ""),
        "timeline": timeline,
        "notes": notes,
        "recordCount": len(c_records) + len(s_records),
        "firstPacket": _fmt_time(min([r["ts"] for r in c_records + s_records] or [0])),
        "lastPacket": _fmt_time(max([r["ts"] for r in c_records + s_records] or [0])),
    }
    return session


def _first_der(certs: list[dict]) -> bytes | None:
    import base64

    for c in certs:
        b64 = c.get("base64")
        if b64:
            return base64.b64decode(b64)
    return None


def _pub_text(pub) -> str:
    try:
        nums = pub.public_numbers()
        if isinstance(pub, rsa.RSAPublicKey):
            return "RSA %d bit, e=%d" % (pub.key_size, nums.e)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return "ECC %s, x=%s" % (pub.curve.name, format(nums.x, "x"))
        if isinstance(pub, ed25519.Ed25519PublicKey):
            from cryptography.hazmat.primitives import serialization

            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return "Ed25519 %s" % raw.hex()
    except Exception:
        pass
    return type(pub).__name__


def _parse_server_key_exchange(msg: dict, ch: dict, sh: dict, server_certs: list[dict]) -> dict:
    """解析 TLS 1.2 ECDHE/DHE ServerKeyExchange 并验证签名。"""
    body = msg["body"]
    info: dict[str, Any] = {
        "present": True,
        "raw": body.hex(),
        "curve": "",
        "publicKey": "",
        "signatureAlgorithm": "",
        "signature": "",
        "checked": False,
        "result": None,
        "reason": "",
        "plaintext": "",
    }
    if len(body) < 4:
        info["reason"] = "报文过短"
        return info
    r = _Reader(body)
    params_len = 0
    if body[0] == 3:                       # named_curve
        r.u8()
        group = r.u16()
        info["curve"] = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519"}.get(group, "group-%d" % group)
        pk_len = r.u8()
        info["publicKey"] = r.take(pk_len).hex()
        params_len = 4 + pk_len
    else:                                   # DHE: p, g, Ys 三个 mpint
        for _ in range(3):
            ln = r.u16()
            r.take(ln)
        params_len = r.pos
    if r.left() < 4:
        info["reason"] = "缺少签名字段"
        return info
    sig_alg = r.u16()
    sig_len = r.u16()
    signature = r.take(min(sig_len, r.left()))
    info["signatureAlgorithm"] = SIG_ALG_NAMES.get(sig_alg, "0x%04X" % sig_alg)
    info["signature"] = signature.hex()
    data = ch.get("random", b"") + sh.get("random", b"") + body[:params_len]
    info["plaintext"] = "client_random + server_random + 密钥交换参数（%d 字节）" % len(data)
    pub = _pub_from_cert_der(_first_der(server_certs))
    if pub is None:
        info["reason"] = "缺少服务端证书公钥，无法验签"
        return info
    info["publicKeyText"] = _pub_text(pub)
    passed, reason = _verify_with_key(pub, sig_alg, data, signature)
    info["checked"] = passed is not None
    info["result"] = passed
    info["reason"] = reason
    if passed:
        info["note"] = "服务端密钥交换消息验签通过"
    return info


def parse_tls(raw: bytes, src_ip: str = "", dst_ip: str = "", src_port: Any = None,
              dst_port: Any = None, file_name: str = "") -> dict:
    """解析 TLS 流量，返回会话列表。"""
    started = datetime.datetime.now()
    capture = read_capture(raw)
    packets = _decode_packets(capture)
    ips = (src_ip or "", dst_ip or "")
    ports = (src_port or None, dst_port or None)
    flows = _tcp_flows(packets)

    sessions: list[dict] = []
    inspected = 0
    for flow in flows:
        if not _flow_match(flow, ips, ports):
            continue
        data_a, spans_a = _reassemble(flow["ab"])
        data_b, spans_b = _reassemble(flow["ba"])
        if not (_looks_like_tls(data_a) or _looks_like_tls(data_b)):
            continue
        inspected += 1
        if _has_client_hello(data_a):
            client = {"data": data_a, "spans": spans_a, "addr": flow["a"]}
            server = {"data": data_b, "spans": spans_b, "addr": flow["b"]}
        elif _has_client_hello(data_b):
            client = {"data": data_b, "spans": spans_b, "addr": flow["b"]}
            server = {"data": data_a, "spans": spans_a, "addr": flow["a"]}
        elif _has_server_hello(data_a):
            client = {"data": data_b, "spans": spans_b, "addr": flow["b"]}
            server = {"data": data_a, "spans": spans_a, "addr": flow["a"]}
        else:
            client = {"data": data_a, "spans": spans_a, "addr": flow["a"]}
            server = {"data": data_b, "spans": spans_b, "addr": flow["b"]}
        try:
            session = _build_tls_session(client, server, len(sessions) + 1)
        except ToolError:
            raise
        except Exception:                       # 单个流解析失败不影响其它会话
            session = None
        if session:
            sessions.append(session)
        if len(sessions) >= 50:
            break

    if not sessions:
        raise ToolError("未在网络包中识别到 TLS 会话，请检查端口或源/目的 IP 过滤条件")
    return {
        "sessions": sessions,
        "count": len(sessions),
        "parsedAt": _now_text(),
        "meta": {
            "format": capture["format"],
            "packets": len(packets),
            "tlsFlows": inspected,
            "linkTypes": [_LINKTYPE_NAMES.get(t, str(t)) for t in capture["linktypes"]],
            "filter": {"srcIp": src_ip, "dstIp": dst_ip, "srcPort": src_port, "dstPort": dst_port},
            "fileName": file_name,
            "elapsedMs": int((datetime.datetime.now() - started).total_seconds() * 1000),
        },
    }

# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
SSH_MSG = {
    1: "SSH_MSG_DISCONNECT", 2: "SSH_MSG_IGNORE", 3: "SSH_MSG_UNIMPLEMENTED",
    4: "SSH_MSG_DEBUG", 5: "SSH_MSG_SERVICE_REQUEST", 6: "SSH_MSG_SERVICE_ACCEPT",
    20: "SSH_MSG_KEXINIT", 21: "SSH_MSG_NEWKEYS", 30: "SSH_MSG_KEXDH_INIT",
    31: "SSH_MSG_KEXDH_REPLY", 32: "SSH_MSG_KEX_DH_GEX_REQUEST",
    50: "SSH_MSG_USERAUTH_REQUEST", 51: "SSH_MSG_USERAUTH_FAILURE",
    52: "SSH_MSG_USERAUTH_SUCCESS", 60: "SSH_MSG_GLOBAL_REQUEST",
}

SSH_KEX_HASH = {
    "curve25519-sha256": "sha256",
    "curve25519-sha256@libssh.org": "sha256",
    "ecdh-sha2-nistp256": "sha256",
    "ecdh-sha2-nistp384": "sha384",
    "ecdh-sha2-nistp521": "sha512",
    "diffie-hellman-group14-sha256": "sha256",
    "diffie-hellman-group16-sha512": "sha512",
    "diffie-hellman-group14-sha1": "sha1",
    "diffie-hellman-group1-sha1": "sha1",
}


def _ssh_string(r: _Reader) -> bytes:
    ln = r.u32()
    return r.take(ln)


def _ssh_namelist(data: bytes) -> list[str]:
    if not data:
        return []
    return [x for x in data.decode("ascii", "replace").split(",") if x]


def _mpint(raw: bytes) -> bytes:
    """按 RFC 4251 规则把无符号大端整数编码为 mpint。"""
    v = raw.lstrip(b"\x00")
    if not v:
        return b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return v


def _ssh_banner(buf: bytes) -> tuple[str, int]:
    """返回 (版本行, 该行之后的偏移)。"""
    limit = min(len(buf), 8192)
    pos = 0
    while pos < limit:
        end = buf.find(b"\n", pos, limit)
        if end < 0:
            break
        line = buf[pos:end].rstrip(b"\r")
        if line.startswith(b"SSH-"):
            return line.decode("ascii", "replace"), end + 1
        pos = end + 1
    return "", 0


def _ssh_packets(buf: bytes, start: int) -> list[dict]:
    out: list[dict] = []
    i = start
    while i + 5 <= len(buf):
        plen = int.from_bytes(buf[i:i + 4], "big")
        if plen < 5 or plen > 35000:
            break
        pad = buf[i + 4]
        end = i + 4 + plen
        if end > len(buf) or pad >= plen:
            break
        payload = buf[i + 5:end - pad]
        out.append({"offset": i, "payload": payload, "length": plen, "padding": pad})
        i = end
    return out


def _ssh_host_key(blob: bytes) -> dict:
    info: dict[str, Any] = {"type": "", "bits": 0, "fingerprint": "SHA256:" }
    r = _Reader(blob)
    try:
        ktype = _ssh_string(r).decode("ascii", "replace")
    except ToolError:
        return info
    info["type"] = ktype
    info["fingerprint"] = "SHA256:" + __import__("base64").b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    if ktype == "ssh-ed25519":
        key = _ssh_string(r)
        info["bits"] = 256
        info["publicKey"] = key.hex()
    elif ktype in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
        e = int.from_bytes(_ssh_string(r), "big")
        n = int.from_bytes(_ssh_string(r), "big")
        info["bits"] = n.bit_length()
        info["publicKey"] = "e=%d, n=%d bits" % (e, n.bit_length())
        info["_rsa"] = (n, e)
    elif ktype.startswith("ecdsa-sha2-"):
        curve = _ssh_string(r).decode("ascii", "replace")
        point = _ssh_string(r)
        info["bits"] = {"nistp256": 256, "nistp384": 384, "nistp521": 521}.get(curve, 0)
        info["curve"] = curve
        info["publicKey"] = point.hex()
    return info


def _ssh_verify_host_sig(host_key: dict, sig_blob: bytes, exchange_hash: bytes) -> tuple[bool | None, str]:
    if not _HAVE_CRYPTO:
        return None, "运行环境缺少 cryptography，无法验签"
    r = _Reader(sig_blob)
    try:
        algo = _ssh_string(r).decode("ascii", "replace")
        sig = _ssh_string(r)
    except ToolError:
        return None, "签名数据结构不完整"
    ktype = host_key.get("type", "")
    try:
        if ktype == "ssh-ed25519" and algo == "ssh-ed25519":
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(host_key["publicKey"]))
            pub.verify(sig, exchange_hash)
            return True, "主机密钥签名验证通过（Ed25519）"
        if ktype in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
            n, e = host_key["_rsa"]
            pub = rsa.RSAPublicNumbers(e, n).public_key()
            digest = {"ssh-rsa": hashes.SHA1(), "rsa-sha2-256": hashes.SHA256(), "rsa-sha2-512": hashes.SHA512()}.get(algo)
            if digest is None:
                return None, "未支持的 RSA 签名算法：%s" % algo
            pub.verify(sig, exchange_hash, padding.PKCS1v15(), digest)
            return True, "主机密钥签名验证通过（%s）" % algo
        if ktype.startswith("ecdsa-sha2-"):
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

            curve_map = {"nistp256": ec.SECP256R1(), "nistp384": ec.SECP384R1(), "nistp521": ec.SECP521R1()}
            curve = curve_map.get(host_key.get("curve", ""))
            if curve is None:
                return None, "未支持的 ECDSA 曲线"
            pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, bytes.fromhex(host_key["publicKey"]))
            half = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
            hash_map = {"nistp256": hashes.SHA256(), "nistp384": hashes.SHA384(), "nistp521": hashes.SHA512()}
            pub.verify(der, exchange_hash, ec.ECDSA(hash_map[host_key["curve"]]))
            return True, "主机密钥签名验证通过（ECDSA）"
    except InvalidSignature:
        return False, "签名验证失败：与主机公钥不匹配"
    except Exception as exc:
        return None, "签名验证异常：%s" % exc
    return None, "主机密钥类型（%s）与签名算法（%s）不匹配" % (ktype, algo)


def _ssh_exchange_hash(hname: str, v_c: bytes, v_s: bytes, i_c: bytes, i_s: bytes,
                       k_s: bytes, q_c: bytes, q_s: bytes, k: bytes) -> bytes:
    """RFC 4253 §8 交换哈希；K 为共享秘密的 mpint（含 4 字节长度前缀）。"""
    buf = b"".join([
        struct.pack(">I", len(v_c)), v_c,
        struct.pack(">I", len(v_s)), v_s,
        struct.pack(">I", len(i_c)), i_c,
        struct.pack(">I", len(i_s)), i_s,
        struct.pack(">I", len(k_s)), k_s,
        struct.pack(">I", len(q_c)), q_c,
        struct.pack(">I", len(q_s)), q_s,
        struct.pack(">I", len(k)), k,
    ])
    return hashlib.new(hname, buf).digest()


def parse_ssh(raw: bytes, src_ip: str = "", dst_ip: str = "", src_port: Any = None,
              dst_port: Any = None, kex_secret: str = "", file_name: str = "") -> dict:
    started = datetime.datetime.now()
    capture = read_capture(raw)
    packets = _decode_packets(capture)
    ips = (src_ip or "", dst_ip or "")
    ports = (src_port or None, dst_port or None)
    flows = _tcp_flows(packets)

    shared_key = b""
    if kex_secret:
        try:
            shared_key = bytes.fromhex(kex_secret.strip().replace(":", "").replace(" ", ""))
        except ValueError:
            raise ToolError("共享密钥 K 必须为十六进制字符串")
    elif kex_secret:
        raise ToolError("共享密钥 K 格式不正确")

    sessions: list[dict] = []
    for flow in flows:
        if not _flow_match(flow, ips, ports):
            continue
        data_a, spans_a = _reassemble(flow["ab"])
        data_b, spans_b = _reassemble(flow["ba"])
        v_a, off_a = _ssh_banner(data_a)
        v_b, off_b = _ssh_banner(data_b)
        if not v_a and not v_b:
            continue
        # 客户端判定：谁先发出 SSH 版本行谁就是客户端（SSH 由客户端先发 banner）
        first_a = min((x[2] for x in spans_a), default=float("inf"))
        first_b = min((x[2] for x in spans_b), default=float("inf"))
        if v_a and v_b:
            client_is_a = first_a <= first_b
        else:
            client_is_a = bool(v_a)
        if client_is_a:
            client = {"data": data_a, "spans": spans_a, "addr": flow["a"], "ver": v_a, "off": off_a}
            server = {"data": data_b, "spans": spans_b, "addr": flow["b"], "ver": v_b, "off": off_b}
        else:
            client = {"data": data_b, "spans": spans_b, "addr": flow["b"], "ver": v_b, "off": off_b}
            server = {"data": data_a, "spans": spans_a, "addr": flow["a"], "ver": v_a, "off": off_a}
        session = _build_ssh_session(client, server, len(sessions) + 1, shared_key)
        if session:
            sessions.append(session)
        if len(sessions) >= 50:
            break

    if not sessions:
        raise ToolError("未在网络包中识别到 SSH 会话，请确认抓包端口（默认 22）或源/目的 IP")
    return {
        "sessions": sessions,
        "count": len(sessions),
        "parsedAt": _now_text(),
        "meta": {
            "format": capture["format"], "packets": len(packets),
            "linkTypes": [_LINKTYPE_NAMES.get(t, str(t)) for t in capture["linktypes"]],
            "filter": {"srcIp": src_ip, "dstIp": dst_ip, "srcPort": src_port, "dstPort": dst_port},
            "fileName": file_name,
            "elapsedMs": int((datetime.datetime.now() - started).total_seconds() * 1000),
        },
    }


def _build_ssh_session(client: dict, server: dict, index: int, shared_key: bytes) -> dict | None:
    c_pkts = _ssh_packets(client["data"], client["off"])
    s_pkts = _ssh_packets(server["data"], server["off"])
    c_kexinit = next((p for p in c_pkts if p["payload"][:1] == b"\x14"), None)
    s_kexinit = next((p for p in s_pkts if p["payload"][:1] == b"\x14"), None)
    if c_kexinit is None and s_kexinit is None:
        return None

    def parse_kexinit(pkt: dict | None) -> dict:
        if pkt is None:
            return {}
        r = _Reader(pkt["payload"], 1)
        r.take(16)                       # cookie
        lists = [_ssh_namelist(_ssh_string(r)) for _ in range(10)]
        r.u8()                           # first_kex_packet_follows
        r.u32()                          # reserved
        keys = ["kexAlgorithms", "hostKeyAlgorithms", "encryptionCS", "encryptionSC",
                "macCS", "macSC", "compressionCS", "compressionSC", "languagesCS", "languagesSC"]
        return dict(zip(keys, lists))

    c_ki = parse_kexinit(c_kexinit)
    s_ki = parse_kexinit(s_kexinit)

    def negotiate(key: str) -> str:
        mine = c_ki.get(key) or []
        theirs = set(s_ki.get(key) or [])
        for alg in mine:
            if alg in theirs:
                return alg
        return ""

    kex = negotiate("kexAlgorithms")
    host_key_alg = negotiate("hostKeyAlgorithms")
    enc_cs = negotiate("encryptionCS")
    enc_sc = negotiate("encryptionSC")
    mac_cs = negotiate("macCS")
    mac_sc = negotiate("macSC")

    timeline: list[dict] = []
    if client["ver"]:
        timeline.append({"time": "", "from": "客户端", "message": "版本交换", "detail": client["ver"]})
    if server["ver"]:
        timeline.append({"time": "", "from": "服务端", "message": "版本交换", "detail": server["ver"]})
    if c_kexinit:
        timeline.append({"time": "", "from": "客户端", "message": "KEXINIT", "detail": "KEX 算法 %d 个" % len(c_ki.get("kexAlgorithms", []))})
    if s_kexinit:
        timeline.append({"time": "", "from": "服务端", "message": "KEXINIT", "detail": "KEX 算法 %d 个" % len(s_ki.get("kexAlgorithms", []))})

    # 密钥交换报文
    reply = next((p for p in s_pkts if p["payload"][:1] == b"\x1f"), None)
    init = next((p for p in c_pkts if p["payload"][:1] == b"\x1e"), None)
    client_qc = b""
    server_qs = b""
    host_key: dict = {}
    sig_blob = b""
    sign_hex = ""
    verify: dict[str, Any] = {"checked": False, "result": None, "reason": ""}

    if init:
        r = _Reader(init["payload"], 1)
        if kex.startswith("diffie-hellman-group"):
            client_qc = _mpint(_ssh_string(r))
        else:
            client_qc = _ssh_string(r)
        timeline.append({"time": "", "from": "客户端", "message": "KEXDH_INIT", "detail": "%d 字节公钥" % len(client_qc)})

    if reply:
        r = _Reader(reply["payload"], 1)
        k_s = _ssh_string(r)
        host_key = _ssh_host_key(k_s)
        if kex.startswith("diffie-hellman-group"):
            server_qs = _mpint(_ssh_string(r))
        else:
            server_qs = _ssh_string(r)
        if r.left() >= 4:
            sig_blob = _ssh_string(r)
        if sig_blob:
            rr = _Reader(sig_blob)
            try:
                sign_alg = _ssh_string(rr).decode("ascii", "replace")
                sig_val = _ssh_string(rr)
                sign_hex = sig_val.hex()
                verify["algorithm"] = sign_alg
            except ToolError:
                verify["reason"] = "签名结构不完整"
        timeline.append({"time": "", "from": "服务端", "message": "KEXDH_REPLY", "detail": "主机密钥 %s" % (host_key.get("type") or "未知")})

        # 只有拿到共享秘密 K 才能复算交换哈希
        if shared_key and client_qc and server_qs and c_kexinit and s_kexinit:
            hname = SSH_KEX_HASH.get(kex, "sha256")
            k_mpint = _mpint(shared_key)
            try:
                h = _ssh_exchange_hash(
                    hname,
                    client["ver"].encode(), server["ver"].encode(),
                    c_kexinit["payload"], s_kexinit["payload"],
                    k_s, client_qc, server_qs, k_mpint,
                )
                verify["exchangeHash"] = h.hex()
                okv, reason = _ssh_verify_host_sig(host_key, sig_blob, h)
                verify.update({"checked": okv is not None, "result": okv, "reason": reason})
            except Exception as exc:
                verify.update({"checked": False, "result": None, "reason": "计算交换哈希失败：%s" % exc})
        elif sig_blob:
            verify["reason"] = "被动抓包无法获得共享秘密 K，无法复算交换哈希；如需验签请在“共享密钥 K”中填写"

    addr_info = {
        "srcAddr": client["addr"][0], "srcPort": client["addr"][1],
        "dstAddr": server["addr"][0], "dstPort": server["addr"][1],
    }
    return {
        "index": index,
        "address": "%s:%s-%s:%s" % (addr_info["srcAddr"], addr_info["srcPort"], addr_info["dstAddr"], addr_info["dstPort"]),
        "addressInfo": addr_info,
        "protocolVersion": server["ver"] or client["ver"],
        "clientVersion": client["ver"],
        "serverVersion": server["ver"],
        "encryptAlgorithm": enc_cs,
        "encryptAlgorithmSC": enc_sc,
        "macAlgorithm": mac_cs,
        "macAlgorithmSC": mac_sc,
        "kexAlgorithms": kex,
        "hostKeyAlgorithm": host_key_alg,
        "compression": negotiate("compressionCS"),
        "clientEncryptAlgorithms": c_ki.get("encryptionCS", []),
        "serverEncryptAlgorithms": s_ki.get("encryptionCS", []),
        "clientMacAlgorithms": c_ki.get("macCS", []),
        "serverMacAlgorithms": s_ki.get("macCS", []),
        "clientKexAlgorithms": c_ki.get("kexAlgorithms", []),
        "serverKexAlgorithms": s_ki.get("kexAlgorithms", []),
        "clientHostKeyAlgorithms": c_ki.get("hostKeyAlgorithms", []),
        "serverHostKeyAlgorithms": s_ki.get("hostKeyAlgorithms", []),
        "clientDHQc": client_qc.hex(),
        "serverDHQc": server_qs.hex(),
        "clientDHParam": client_qc.hex(),
        "serverDHParam": server_qs.hex(),
        "hostKeyType": host_key.get("type", ""),
        "hostKeyBits": host_key.get("bits", 0),
        "hostKeyFingerprint": host_key.get("fingerprint", ""),
        "hostKeyPublic": host_key.get("publicKey", ""),
        "signAlgorithm": host_key.get("type", ""),
        "signatureAlgorithm": verify.get("algorithm", ""),
        "signature": sign_hex,
        "signVerify": verify,
        "timeline": timeline,
        "notes": [] if verify.get("checked") else ["SSH 主机密钥签名需共享秘密 K 才能复算交换哈希，被动抓包默认无法验签"],
    }


# ---------------------------------------------------------------------------
# IPSec / IKE (IKEv2 为主，IKEv1 仅识别报文头)
# ---------------------------------------------------------------------------
IKE_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}

IKE_V1_EXCHANGE_TYPES = {
    1: "Base", 2: "身份保护模式（主模式）", 3: "仅认证模式", 4: "野蛮模式",
    5: "信息交换", 32: "快速模式（Quick Mode）",
}

IKE_PAYLOAD_TYPES = {
    0: "None", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Ni/Nonce", 41: "N", 42: "D", 43: "V", 44: "TSi", 45: "TSr",
    46: "SK", 47: "CP", 48: "EAP", 49: "GSA",
}

IKE_V1_PAYLOAD_TYPES = {
    0: "None", 1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT",
    7: "CR", 8: "HASH", 9: "SIG", 10: "Nonce", 11: "Notify", 12: "Delete", 13: "VendorID",
    14: "Payload", 15: "Config",
}

# 语义类型：把 IKEv1/IKEv2 的不同编号统一成同一套 kind
_IKE_KIND_V2 = {33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
                39: "AUTH", 40: "NONCE", 41: "NOTIFY", 46: "SK", 44: "TSi", 45: "TSr"}
_IKE_KIND_V1 = {1: "SA", 4: "KE", 5: "ID", 6: "CERT", 7: "CERTREQ", 8: "AUTH",
                9: "SIG", 10: "NONCE", 11: "NOTIFY", 13: "VENDOR", 2: "PROPOSAL", 3: "TRANSFORM"}

IKE_ENCR = {
    1: "DES-IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "Blowfish",
    8: "3IDEA", 9: "DES-IV32", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8",
    18: "AES-GCM-8", 19: "AES-CCM-12", 20: "AES-GCM-16", 21: "AES-CCM-16",
    23: "NULL-AES-GMAC", 30: "SM4-CBC", 31: "SM4-GCM",
}

IKE_PRF = {1: "HMAC-SHA1", 2: "HMAC-MD5", 3: "HMAC-SHA2-256", 4: "HMAC-SHA2-384",
           5: "HMAC-SHA2-512", 6: "AES128-XCBC", 7: "HMAC-SHA1-160"}

IKE_INTEG = {1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 3: "DES-MAC", 4: "KPDK", 5: "AES-XCBC-96",
             6: "HMAC-MD5-128", 7: "HMAC-SHA1-128", 8: "AES-CMAC-96", 9: "AES-128-GMAC",
             12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}

IKE_DH = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072",
          16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384",
          21: "ECP-521", 22: "MODP-1024s", 23: "MODP-2048s", 24: "MODP-2048s", 31: "CURVE25519",
          32: "CURVE448"}

IKE_ID_TYPES = {1: "IPv4 地址", 2: "FQDN", 3: "RFC822 邮箱", 4: "IPv6 地址", 5: "DER ASN.1 DN",
                9: "DER ASN.1 DN", 11: "KEY_ID"}

IKE_AUTH_METHODS = {1: "RSA 数字签名", 2: "预共享密钥", 3: "DSS 数字签名", 4: "ECDSA(SHA256)",
                    5: "ECDSA(SHA384)", 6: "ECDSA(SHA512)", 9: "ECDSA(SHA256)",
                    14: "数字签名(DSA-SHA256)"}


def parse_ipsec(raw: bytes, src_ip: str = "", dst_ip: str = "", src_port: Any = None,
                dst_port: Any = None, file_name: str = "") -> dict:
    started = datetime.datetime.now()
    capture = read_capture(raw)
    packets = _decode_packets(capture)
    ips = (src_ip or "", dst_ip or "")
    ports = (src_port or None, dst_port or None)

    messages: list[dict] = []
    for p in packets:
        if p.get("proto") != "udp":
            continue
        if not _flow_match({"a": (p["src"], p["sport"]), "b": (p["dst"], p["dport"])}, ips, ports):
            continue
        payload = p.get("payload") or b""
        if len(payload) < 28:
            continue
        parsed = _parse_ike_message(payload, p)
        if parsed:
            messages.append(parsed)

    if not messages:
        raise ToolError("未在网络包中识别到 IPSec/IKE 报文，请确认抓包端口（500/4500）或源/目的 IP")

    groups: dict[tuple, dict] = {}
    for m in messages:
        if m["initiatorSPI"] and m["initiatorSPI"] != "0" * 16:
            key = ("spi", m["initiatorSPI"])
        else:                       # 无有效 SPI（如 IKEv1 部分报文）时按地址对分组
            pair = tuple(sorted([(m["srcAddr"], m["srcPort"]), (m["dstAddr"], m["dstPort"])]))
            key = ("addr", pair)
        groups.setdefault(key, {"messages": [], "spi": m["initiatorSPI"]})["messages"].append(m)

    sessions: list[dict] = []
    for idx, (_key, grp) in enumerate(groups.items(), 1):
        sessions.append(_build_ipsec_session(grp["messages"], idx))
    sessions.sort(key=lambda s: s["index"])

    return {
        "sessions": sessions,
        "count": len(sessions),
        "parsedAt": _now_text(),
        "meta": {
            "format": capture["format"], "packets": len(packets),
            "ikeMessages": len(messages),
            "linkTypes": [_LINKTYPE_NAMES.get(t, str(t)) for t in capture["linktypes"]],
            "filter": {"srcIp": src_ip, "dstIp": dst_ip, "srcPort": src_port, "dstPort": dst_port},
            "fileName": file_name,
            "elapsedMs": int((datetime.datetime.now() - started).total_seconds() * 1000),
        },
    }


def _parse_ike_message(payload: bytes, pkt: dict) -> dict | None:
    if len(payload) < 28:
        return None
    init_spi = payload[0:8]
    resp_spi = payload[8:16]
    next_payload = payload[16]
    version = payload[17]
    exchange = payload[18]
    flags = payload[19]
    msg_id = int.from_bytes(payload[20:24], "big")
    length = int.from_bytes(payload[24:28], "big")
    if version >> 4 not in (1, 2):
        return None
    if length < 28 or length > len(payload) + 8:
        return None
    body = payload[28:length]
    is_v2 = (version >> 4) == 2
    msg = {
        "ts": pkt["ts"],
        "srcAddr": pkt["src"], "srcPort": pkt["sport"],
        "dstAddr": pkt["dst"], "dstPort": pkt["dport"],
        "initiatorSPI": init_spi.hex(),
        "responderSPI": resp_spi.hex(),
        "version": "%d.%d" % (version >> 4, version & 0x0F),
        "exchangeType": exchange,
        "exchangeName": (IKE_EXCHANGE_TYPES if is_v2 else IKE_V1_EXCHANGE_TYPES).get(exchange, "类型 %d" % exchange),
        "flags": flags,
        "isResponse": bool(flags & 0x20) if is_v2 else bool(flags & 0x01),
        "messageId": msg_id,
        "payloads": [],
        "isV2": is_v2,
        "raw": payload[:length].hex(),
    }
    _walk_ike_payloads(body, next_payload, msg, v1=not is_v2)
    return msg


def _walk_ike_payloads(body: bytes, first_type: int, msg: dict, v1: bool = False) -> None:
    names = IKE_V1_PAYLOAD_TYPES if v1 else IKE_PAYLOAD_TYPES
    kinds = _IKE_KIND_V1 if v1 else _IKE_KIND_V2
    pos = 0
    ptype = first_type
    guard = 0
    while ptype != 0 and pos + 4 <= len(body) and guard < 32:
        guard += 1
        nxt = body[pos]
        plen = int.from_bytes(body[pos + 2:pos + 4], "big")
        if plen < 4 or pos + plen > len(body):
            break
        data = body[pos + 4:pos + plen]
        msg["payloads"].append({
            "type": ptype, "name": names.get(ptype, "类型 %d" % ptype),
            "kind": kinds.get(ptype, ""), "data": data,
        })
        pos += plen
        ptype = nxt


def _parse_ike_sa(data: bytes) -> list[dict]:
    """解析 SA payload 中的 proposal / transform。"""
    proposals = []
    r = _Reader(data)
    while r.left() >= 8:
        last = r.u8()
        r.u8()
        plen = r.u16()
        if plen < 8 or plen > r.left() + 4:
            break
        end = r.pos - 4 + plen
        num = r.u8()
        proto_id = r.u8()
        spi_size = r.u8()
        num_trans = r.u8()
        spi = r.take(spi_size)
        prop = {"protocol": {1: "IKE", 2: "AH", 3: "ESP"}.get(proto_id, str(proto_id)),
                "spi": spi.hex(), "transforms": []}
        while r.pos + 8 <= end and len(prop["transforms"]) < num_trans + 4:
            tlast = r.u8()
            r.u8()
            tlen = r.u16()
            if tlen < 8 or r.pos - 4 + tlen > end:
                break
            ttype = r.u8()
            r.u8()
            tid = r.u16()
            attrs = {}
            tend = r.pos - 8 + tlen
            while r.pos + 4 <= tend:
                atype = r.u16()
                if atype & 0x8000:              # TV：高 15 位是属性类型，后 2 字节是值
                    attrs[atype & 0x7FFF] = r.u16()
                else:                           # TLV：先长度再取值
                    alen = r.u16()
                    raw = r.take(min(max(alen, 0), max(r.left(), 0)))
                    attrs[atype] = int.from_bytes(raw, "big") if raw else 0
            prop["transforms"].append({"type": ttype, "id": tid, "attributes": attrs})
            r.pos = tend
        proposals.append(prop)
        if last:
            break
        r.pos = end
    return proposals


def _build_ipsec_session(messages: list[dict], index: int) -> dict:
    messages.sort(key=lambda m: (m["ts"], m["messageId"]))
    first = messages[0]
    enc_alg = ""
    enc_key_len = 0
    integ = ""
    prf = ""
    dh = ""
    life_type = ""
    life_duration = 0
    client_nonce = ""
    server_nonce = ""
    certs: list[dict] = []
    certs_side: dict[str, list[dict]] = {"发起方": [], "响应方": []}
    certs_der: list[bytes] = []
    ids: dict[str, str] = {}
    auths: list[dict] = []
    has_sk = False
    ke_group = ""
    ke_data = ""
    timeline: list[dict] = []
    combos: list[dict] = []

    for m in messages:
        who = "响应方" if m["isResponse"] else "发起方"
        timeline.append({
            "time": _fmt_time(m["ts"]), "from": who, "message": m["exchangeName"],
            "detail": "消息 ID=%d，载荷：%s" % (m["messageId"], ", ".join(p["name"] for p in m["payloads"]) or "无"),
        })
        for pl in m["payloads"]:
            data = pl["data"]
            kind = pl.get("kind") or ""
            if kind == "SA":
                sa_body = data[8:] if (not m["isV2"] and len(data) > 8) else data
                for prop in _parse_ike_sa(sa_body):
                    combo = {"protocol": prop["protocol"], "spi": prop["spi"], "enc": "", "encLen": 0,
                             "integ": "", "prf": "", "dh": "", "lifeType": "", "lifeDuration": 0}
                    for t in prop["transforms"]:
                        attrs = t["attributes"]
                        if t["type"] == 1:
                            combo["enc"] = IKE_ENCR.get(t["id"], "算法-%d" % t["id"])
                            combo["encLen"] = attrs.get(14, 0)
                        elif t["type"] == 3:
                            combo["integ"] = IKE_INTEG.get(t["id"], "算法-%d" % t["id"])
                        elif t["type"] == 2:
                            combo["prf"] = IKE_PRF.get(t["id"], "算法-%d" % t["id"])
                        elif t["type"] == 4:
                            combo["dh"] = IKE_DH.get(t["id"], "组-%d" % t["id"])
                        elif t["type"] == 11:
                            combo["lifeType"] = "秒" if t["id"] == 1 else ("KB" if t["id"] == 2 else "类型-%d" % t["id"])
                            combo["lifeDuration"] = attrs.get(12, 0) or attrs.get(13, 0)
                    if not enc_alg and combo["enc"]:
                        enc_alg, enc_key_len = combo["enc"], combo["encLen"] or 0
                        integ, prf = combo["integ"], combo["prf"]
                        dh = combo["dh"]
                        life_type, life_duration = combo["lifeType"], combo["lifeDuration"]
                    combos.append(combo)
            elif kind == "KE" and data:
                if m["isV2"] and len(data) >= 4:
                    group = int.from_bytes(data[0:2], "big")
                    ke_group = IKE_DH.get(group, "组-%d" % group)
                    ke_data = data[4:].hex()
                    dh = dh or ke_group
                else:                       # IKEv1 的 KE 载荷不带 DH 组
                    ke_data = data.hex()
            elif kind == "NONCE":
                if who == "响应方":
                    server_nonce = data.hex()
                else:
                    client_nonce = data.hex()
            elif kind == "CERT" and data:
                enc_type = data[0]
                der = data[1:]
                info = _cert_info(der)
                info["encoding"] = {1: "X.509 证书-签名", 2: "CRL", 3: "X.509 证书-哈希", 4: "X.509 属性"} .get(enc_type, str(enc_type))
                certs.append(info)
                certs_side.setdefault(who, []).append(info)
                certs_der.append(der)
            elif kind in ("IDi", "IDr", "ID") and data:
                id_type = data[0]
                val = data[1:]
                text = ""
                if id_type == 1 and len(val) == 4:
                    text = str(ipaddress.IPv4Address(val))
                elif id_type == 2:
                    text = val.decode("utf-8", "replace")
                elif id_type == 11:
                    text = val.hex()
                else:
                    text = val.hex()[:128]
                side_key = "IDr" if (kind == "IDr" or who == "响应方") else "IDi"
                ids[side_key] = "%s(%s)" % (text, IKE_ID_TYPES.get(id_type, "类型 %d" % id_type))
            elif kind in ("AUTH", "SIG") and data:
                method = data[0] if kind == "AUTH" else 0
                auths.append({"method": IKE_AUTH_METHODS.get(method, "方法 %d" % method),
                              "methodCode": method, "data": data[1:].hex(),
                              "side": "响应方" if m["isResponse"] else "发起方"})
            elif kind == "SK":
                has_sk = True

    notes: list[str] = []
    if has_sk:
        notes.append("IKE_AUTH 的 SK 载荷已加密，其中的 ID/证书/AUTH 无法解密。证书链仅能从未加密 CERT 载荷中提取")
    if not certs:
        notes.append("未发现明文 CERT 载荷，无法提取对端证书链")
    if combos:
        notes.append("SA 中共有 %d 组提案（proposal），表格展示第一组" % len(combos))

    resp_spi = next((m["responderSPI"] for m in messages if m["responderSPI"] and m["responderSPI"] != "0" * 16), first["responderSPI"])
    client_certs = certs_side.get("发起方") or []
    server_certs = certs_side.get("响应方") or []
    if not client_certs and not server_certs:
        client_certs = server_certs = certs

    return {
        "index": index,
        "initiatorCookie": first["initiatorSPI"],
        "responderCookie": resp_spi,
        "initiatorSPI": first["initiatorSPI"],
        "responderSPI": resp_spi,
        "protocol": "IKEv2" if first["isV2"] else "IKEv1",
        "version": first["version"],
        "encAlgorithm": enc_alg,
        "encKeyLength": enc_key_len or (128 if enc_alg.startswith("AES") and not enc_key_len else 0),
        "macAlgorithm": integ,
        "authAlgorithm": prf,
        "prfAlgorithm": prf,
        "asymmetricAlg": dh,
        "dhGroup": dh,
        "keGroup": ke_group,
        "keData": ke_data[:128],
        "lifeType": life_type,
        "lifeDuration": life_duration,
        "proposals": combos,
        "clientNonce": client_nonce,
        "serverNonce": server_nonce,
        "nonceClient": client_nonce,
        "nonceServer": server_nonce,
        "clientCertList": client_certs,
        "serverCertList": server_certs,
        "clientCertBase64List": [c["base64"] for c in client_certs],
        "serverCertBase64List": [c["base64"] for c in server_certs],
        "clientCertTextList": [c.get("subject", "") for c in client_certs],
        "serverCertTextList": [c.get("subject", "") for c in server_certs],
        "clientIdentity": ids.get("IDi", ""),
        "serverIdentity": ids.get("IDr", ""),
        "authList": auths,
        "clientSign": next((a["data"] for a in auths if a["side"] == "发起方"), ""),
        "serverSign": next((a["data"] for a in auths if a["side"] == "响应方"), ""),
        "skEncrypted": has_sk,
        "messages": [{"time": _fmt_time(m["ts"]), "from": "响应方" if m["isResponse"] else "发起方",
                      "exchange": m["exchangeName"], "messageId": m["messageId"],
                      "payloads": [p["name"] for p in m["payloads"]]} for m in messages],
        "timeline": timeline,
        "notes": notes,
        "addressInfo": {
            "srcAddr": first["srcAddr"], "srcPort": first["srcPort"],
            "dstAddr": first["dstAddr"], "dstPort": first["dstPort"],
        },
        "label": "会话 %d" % index,
    }

# ---------------------------------------------------------------------------
# UKey / USB CCID-APDU
# ---------------------------------------------------------------------------
CCID_MSG_TYPES = {
    0x61: "RDR_to_PC_NotifySlotChange", 0x62: "RDR_to_PC_HardwareError",
    0x65: "PC_to_RDR_IccPowerOn", 0x66: "PC_to_RDR_IccPowerOff",
    0x67: "PC_to_RDR_GetSlotStatus", 0x68: "PC_to_RDR_Secure",
    0x69: "PC_to_RDR_T0APDU", 0x6A: "PC_to_RDR_Escape",
    0x6B: "PC_to_RDR_GetParameters", 0x6C: "PC_to_RDR_ResetParameters",
    0x6D: "PC_to_RDR_SetParameters", 0x6E: "PC_to_RDR_Abort",
    0x6F: "PC_to_RDR_XfrBlock", 0x71: "PC_to_RDR_SetDataRateAndClockFrequency",
    0x72: "PC_to_RDR_GetDataRateAndClockFrequency",
    0x80: "RDR_to_PC_DataBlock", 0x81: "RDR_to_PC_SlotStatus",
    0x82: "RDR_to_PC_Parameters", 0x83: "RDR_to_PC_Escape",
    0x84: "RDR_to_PC_DataRateAndClockFrequency",
}

_CCID_FROM_HOST = (0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x71, 0x72)
_CCID_TO_HOST = (0x80, 0x81, 0x82, 0x83, 0x84)

APDU_INS = {
    0xA4: "SELECT", 0xB0: "READ BINARY", 0xB2: "READ RECORD", 0xC0: "GET RESPONSE",
    0xCA: "GET DATA", 0xCB: "GET DATA", 0xD0: "WRITE BINARY", 0xD6: "UPDATE BINARY",
    0xE2: "APPEND RECORD", 0x20: "VERIFY", 0x21: "VERIFY", 0x22: "MANAGE SECURITY ENVIRONMENT",
    0x24: "CHANGE REFERENCE DATA", 0x2A: "PERFORM SECURITY OPERATION",
    0x2C: "RESET RETRY COUNTER", 0x44: "ACTIVATE FILE", 0x46: "GENERATE KEY PAIR",
    0x47: "GENERATE KEY PAIR", 0x70: "MANAGE CHANNEL", 0x82: "EXTERNAL AUTHENTICATE",
    0x84: "GET CHALLENGE", 0x88: "INTERNAL AUTHENTICATE", 0xA0: "SEARCH BINARY",
    0xA2: "SEARCH RECORD", 0xA8: "SELECT? (0xA8)", 0xBC: "READ BINARY",
}

APDU_SW = {
    0x9000: "执行成功", 0x6300: "认证失败", 0x6982: "安全状态不满足",
    0x6983: "认证方法被锁定", 0x6985: "使用条件不满足", 0x6A81: "功能不支持",
    0x6A82: "文件或应用未找到", 0x6A83: "记录未找到", 0x6A86: "参数 P1/P2 不正确",
    0x6A88: "引用数据未找到", 0x6B00: "参数不合法", 0x6C00: "Le 长度不正确",
    0x6D00: "指令不支持", 0x6E00: "CLA 不支持", 0x6700: "长度不正确",
}

UKEY_VENDOR_KEYWORDS = [
    ("山东渔翁", [b"yuweng", b"sdyw"]),
    ("海泰方圆", [b"hitrust", b"haitai", b"htfy"]),
    ("上海华申", [b"huashen", b"shhs"]),
    ("三未信安", [b"sansec", b"swxa"]),
    ("飞天诚信", [b"feitian"]),
    ("北京 CA", [b"bjca"]),
    ("中金国信（CFCA）", [b"cfca"]),
    ("符合 0017 标准规范", [b"gmt0017", b"0017"]),
]

UKEY_FACTORIES = ["符合 0017 标准规范", "山东渔翁", "海泰方圆", "上海华申",
                  "三未信安", "飞天诚信", "北京 CA", "中金国信（CFCA）"]


def _ccid_blocks(payload: bytes) -> list[dict]:
    """从一段 USB 传输数据中提取 CCID 消息块。"""
    out: list[dict] = []
    i = 0
    n = len(payload)
    while i + 10 <= n:
        mtype = payload[i]
        if mtype not in _CCID_FROM_HOST and mtype not in _CCID_TO_HOST:
            i += 1
            continue
        length = int.from_bytes(payload[i + 1:i + 5], "little")
        total = 10 + length
        if length > 65535 or i + total > n:
            i += 1
            continue
        out.append({
            "offset": i,
            "type": mtype,
            "name": CCID_MSG_TYPES.get(mtype, "未知(0x%02X)" % mtype),
            "length": length,
            "slot": payload[i + 5],
            "seq": payload[i + 6],
            "status": payload[i + 7],
            "error": payload[i + 8],
            "data": payload[i + 10:i + total],
            "direction": "命令" if mtype in _CCID_FROM_HOST else "响应",
        })
        i += total
    return out


def _parse_command_apdu(data: bytes) -> dict:
    info: dict[str, Any] = {
        "cla": "", "ins": "", "p1": "", "p2": "", "lc": 0,
        "data": "", "le": "", "name": "", "valid": False, "description": "",
    }
    if len(data) < 4:
        return info
    cla, ins, p1, p2 = data[0], data[1], data[2], data[3]
    info.update({"cla": "%02X" % cla, "ins": "%02X" % ins, "p1": "%02X" % p1, "p2": "%02X" % p2,
                 "name": APDU_INS.get(ins, "未知指令 0x%02X" % ins), "valid": True})
    body = data[4:]
    # ISO 7816-4 四种 APDU 情形（1/2S/3S/4S 以及扩展长度）
    if len(body) == 0:
        pass                                    # Case 1：无数据无 Le
    elif len(body) in (1, 2):
        info["le"] = body.hex()                 # Case 2S/2E
    else:
        if body[0] == 0 and len(body) >= 3:      # 扩展长度：00 + 2 字节 Lc
            lc = int.from_bytes(body[1:3], "big")
            pos = 3
        else:
            lc = body[0]
            pos = 1
        if pos + lc <= len(body):
            info["data"] = body[pos:pos + lc].hex()
            info["lc"] = lc
            rest = body[pos + lc:]
            if rest:
                info["le"] = rest.hex()
        else:
            info["data"] = body[pos:].hex()
            info["lc"] = len(body) - pos
    # 描述
    if ins == 0xA4:
        info["description"] = "选择应用/文件，P1=%s（%s）" % (
            info["p1"], "按 DF 名称选择" if p1 == 0x04 else "按文件标识符选择")
        if info["data"]:
            info["aid"] = info["data"].upper()
    elif ins == 0xB0:
        le_val = int(info["le"], 16) if info["le"] else 0
        info["description"] = "读取二进制文件，偏移 0x%04X，长度 %d" % (
            (int(info["p1"], 16) << 8) | int(info["p2"], 16), info["lc"] or le_val)
    elif ins == 0xC0:
        info["description"] = "取响应，期望长度 %s" % (info["le"] or "0")
    elif ins == 0xCA:
        info["description"] = "读取数据对象 0x%s%s" % (info["p1"], info["p2"])
    elif ins == 0x2A:
        info["description"] = "安全操作（签名/解密），P1=%s P2=%s" % (info["p1"], info["p2"])
    elif ins == 0x46 or ins == 0x47:
        info["description"] = "生成密钥对，P1=%s P2=%s" % (info["p1"], info["p2"])
    elif ins == 0x20:
        info["description"] = "校验 PIN"
    elif ins == 0x88:
        info["description"] = "内部认证/签名"
    return info


def _sw_text(sw: int) -> str:
    if sw in APDU_SW:
        return APDU_SW[sw]
    if (sw & 0xFF00) == 0x6C00:
        return "Le 长度不正确，正确长度应为 %d" % (sw & 0xFF)
    if (sw & 0xFF00) == 0x6100:
        return "还有 %d 字节可用，请使用 GET RESPONSE" % (sw & 0xFF)
    if (sw & 0xFF00) == 0x6300:
        return "认证失败，剩余重试次数 %d" % (sw & 0xFF)
    if (sw & 0xFF00) == 0x6A00:
        return "参数不正确（0x%04X）" % sw
    return "状态字 0x%04X" % sw


def _scan_der(buf: bytes) -> list[bytes]:
    """在二进制流中扫描 DER 编码对象（SEQUENCE）。"""
    out: list[bytes] = []
    i = 0
    n = len(buf)
    while i + 4 <= n:
        if buf[i] == 0x30:
            tag = buf[i + 1]
            if tag == 0x82:
                ln, hdr = int.from_bytes(buf[i + 2:i + 4], "big"), 4
            elif tag == 0x81:
                ln, hdr = buf[i + 2], 3
            elif tag == 0x83:
                ln, hdr = int.from_bytes(buf[i + 2:i + 5], "big"), 5
            else:
                ln, hdr = -1, 0
            if ln > 0 and i + hdr + ln <= n:
                out.append(buf[i:i + hdr + ln])
                i += hdr + ln
                continue
        i += 1
    return out


def _pubkey_info(der: bytes) -> dict | None:
    if not _HAVE_CRYPTO:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        pub = load_der_public_key(der)
        alg, bits = _key_desc(pub)
        import base64

        return {
            "algorithm": alg, "bits": bits, "base64": base64.b64encode(der).decode(),
            "hex": der.hex(), "text": _pub_text(pub),
        }
    except Exception:
        return None


def parse_ukey(raw: bytes, factory: str = "", public_key: str = "", file_name: str = "") -> dict:
    started = datetime.datetime.now()
    capture = read_capture(raw)
    packets = _decode_packets(capture)

    blocks: list[dict] = []
    for p in packets:
        payload = p.get("payload") or b""
        for blk in _ccid_blocks(payload):
            blk["ts"] = p["ts"]
            blk["l2"] = p.get("l2", "")
            blocks.append(blk)

    # 若没有 CCID 头，退化为直接寻找 APDU（例如某些抓包工具只保留数据段）
    if not blocks:
        for p in packets:
            payload = p.get("payload") or b""
            if len(payload) >= 4 and payload[0] in (0x00, 0x80) and payload[1] in APDU_INS:
                blocks.append({"type": 0x6F, "name": "原始 APDU", "seq": 0, "slot": 0,
                               "status": 0, "error": 0, "data": payload, "ts": p["ts"],
                               "direction": "命令", "l2": p.get("l2", ""), "length": len(payload)})

    if not blocks:
        raise ToolError("未在流量包中找到 CCID/APDU 数据，请确认是否为 UKey 的 USB 抓包")

    apdus: list[dict] = []
    pending: list[dict] = []
    atr_list: list[str] = []
    certs: list[dict] = []
    seen_cert: set[str] = set()
    pubkeys: list[dict] = []
    prev_type = None
    for blk in sorted(blocks, key=lambda b: b["ts"]):
        at_power_on = prev_type == 0x65
        prev_type = blk["type"]
        if blk["type"] == 0x65 and blk["data"]:
            atr_list.append(blk["data"].hex().upper())
        if blk["type"] == 0x80 and at_power_on and blk["data"]:
            atr_list.append(blk["data"].hex().upper())   # 上电后返回的 ATR
            continue
        if blk["type"] == 0x6F:
            cmd = _parse_command_apdu(blk["data"])
            item = {
                "index": len(apdus) + 1,
                "time": _fmt_time(blk["ts"]),
                "direction": "命令",
                "ccidType": blk["name"],
                "seq": blk["seq"],
                "slot": blk["slot"],
                "raw": blk["data"].hex(),
                "response": "",
                "sw": "",
                "swText": "",
                **cmd,
            }
            apdus.append(item)
            pending.append(item)
        elif blk["type"] == 0x80:
            resp_data = blk["data"]
            sw = 0
            body = resp_data
            if len(resp_data) >= 2:
                sw = int.from_bytes(resp_data[-2:], "big")
                body = resp_data[:-2]
            target = pending.pop(0) if pending else None
            if target is not None:
                target["response"] = body.hex()
                target["responseLength"] = len(body)
                target["sw"] = "%04X" % sw
                target["swText"] = _sw_text(sw)
            apdus.append({
                "index": len(apdus) + 1,
                "time": _fmt_time(blk["ts"]),
                "direction": "响应",
                "ccidType": blk["name"],
                "seq": blk["seq"],
                "slot": blk["slot"],
                "raw": resp_data.hex(),
                "responseLength": len(body),
                "sw": "%04X" % sw,
                "swText": _sw_text(sw),
                "name": "响应数据",
                "description": "返回 %d 字节，状态字 0x%04X" % (len(body), sw),
            })
            if body:
                for der in _scan_der(body):
                    key = hashlib.sha256(der).hexdigest()
                    if key in seen_cert:
                        continue
                    info = _cert_info(der)
                    if info.get("parsed"):
                        seen_cert.add(key)
                        certs.append(info)
                    else:
                        pk = _pubkey_info(der)
                        if pk:
                            seen_cert.add(key)
                            pubkeys.append(pk)

    # 厂商识别
    vendor = ""
    evidence = ""
    confidence = "none"
    blob = b""
    for blk in blocks:
        blob += blk["data"]
    lowered = blob.lower()
    for name, keys in UKEY_VENDOR_KEYWORDS:
        hit = next((k for k in keys if k in lowered), None)
        if hit:
            vendor, evidence, confidence = name, "报文数据中出现厂商标识 “%s”" % hit.decode("latin-1"), "high"
            break
    if not vendor:
        aid = next((a.get("aid") for a in apdus if a.get("aid")), "")
        if aid.startswith("A000000063") or aid.startswith("A000000308"):
            vendor, evidence, confidence = "符合 0017 标准规范", "SELECT 的 AID 为 %s" % aid, "medium"
    if not vendor:
        vendor, evidence, confidence = "未知厂商", "未在报文特征中匹配到已知厂商标识", "low"
    if factory and factory in UKEY_FACTORIES:
        if factory != vendor:
            evidence += "；用户指定厂商为 %s，与自动识别结果不同，按用户选择展示" % factory
        vendor = factory
        confidence = "manual"

    return {
        "vendor": vendor,
        "vendorEvidence": evidence,
        "vendorConfidence": confidence,
        "factoryOptions": UKEY_FACTORIES,
        "atr": atr_list[0] if atr_list else "",
        "atrList": atr_list,
        "apdus": apdus,
        "apduCount": len([a for a in apdus if a["direction"] == "命令"]),
        "certificates": certs,
        "certList": certs,
        "publicKeys": pubkeys,
        "publicKeyInput": public_key or "",
        "parsedAt": _now_text(),
        "meta": {
            "format": capture["format"],
            "packets": len(packets),
            "ccidBlocks": len(blocks),
            "l2": sorted({b.get("l2", "") for b in blocks if b.get("l2")}),
            "fileName": file_name,
            "elapsedMs": int((datetime.datetime.now() - started).total_seconds() * 1000),
        },
        "notes": [
            "UKey 解析基于 CCID 报文特征识别，命令与响应按顺序配对",
            "证书/公钥仅在 APDU 响应数据中出现完整 DER 结构时才能解析",
        ],
    }
