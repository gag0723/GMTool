"""可重复生成 tests/fixtures/*.pcap 的测试数据构造脚本。

不依赖 scapy：手写 pcap 头 + 以太网/IP/TCP 报文，TLS/SSH/IKE 报文均为真实字节，
证书与签名由 cryptography 现场生成，因此每次运行字节不同但结构一致。

用法：
    .venv/bin/python tests/make_fixtures.py              # 生成全部 pcap
    .venv/bin/python tests/make_fixtures.py --emit-samples   # 额外打印前端 samples 常量
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TS0 = 1767225600.0          # 2026-01-01 00:00:00 UTC


# ---------------------------------------------------------------- pcap 写入
def write_pcap(path: str, packets: list[tuple[float, bytes]], linktype: int = 1) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for ts, data in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ip_bytes(text: str) -> bytes:
    return bytes(int(x) for x in text.split("."))


def eth_ip_tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
               payload: bytes, flags: int = 0x18, src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
               dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, 65535, 0, 0) + payload
    pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack(">BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack(">H", _cksum(pseudo + tcp)) + tcp[18:]
    total_len = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total_len, 1, 0x4000, 64, 6, 0) + _ip_bytes(src) + _ip_bytes(dst)
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + tcp


def eth_ip_udp(src: str, dst: str, sport: int, dport: int, payload: bytes,
               src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
               dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02") -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack(">BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack(">H", _cksum(pseudo + udp)) + udp[8:]
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0) + _ip_bytes(src) + _ip_bytes(dst)
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + udp


def write_pcapng(path: str, packets: list[tuple[float, bytes]], linktype: int = 1) -> None:
    """写一个最小 pcapng：SHB + IDB + 逐包 EPB，用于验证 pcapng 分支。"""
    def block(btype: int, body: bytes) -> bytes:
        pad = (4 - len(body) % 4) % 4
        body = body + b"\x00" * pad
        total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(0x00000001, struct.pack("<HHI", linktype, 0, 262144))
    out = [shb, idb]
    for ts, data in packets:
        value = int(round(ts * 1_000_000))          # pcapng 时间戳以 tsresol 为单位
        body = struct.pack("<IIIII", 0, value >> 32, value & 0xFFFFFFFF, len(data), len(data)) + data
        out.append(block(0x00000006, body))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(b"".join(out))


def usbpcap_frame(data: bytes, endpoint: int = 0x01) -> bytes:
    """构造 USBPcap（LINKTYPE 249）报文头 + 数据。"""
    header = struct.pack("<H", 27) + struct.pack("<Q", 1) + struct.pack("<I", 0)
    header += struct.pack("<H", 9) + b"\x00" + struct.pack("<HH", 1, 2)
    header += bytes([endpoint, 3])
    header += struct.pack("<I", len(data))
    return header + data


class TcpConv:
    """维护一次 TCP 双向会话的序号与时间戳。"""

    def __init__(self, cli: tuple[str, int], srv: tuple[str, int], t: float):
        self.cli, self.srv = cli, srv
        self.seq = {cli: 1000, srv: 5000}
        self.ack = {cli: 5000, srv: 1000}
        self.t = t
        self.packets: list[tuple[float, bytes]] = []

    def send(self, who: tuple[str, int], data: bytes, split_at: int | None = None, gap: float = 0.004) -> None:
        other = self.srv if who == self.cli else self.cli
        chunks = [data] if not split_at else [data[:split_at], data[split_at:]]
        for chunk in chunks:
            if not chunk:
                continue
            self.t += gap
            frame = eth_ip_tcp(who[0], other[0], who[1], other[1],
                               self.seq[who], self.ack[who], chunk)
            self.packets.append((self.t, frame))
            self.seq[who] += len(chunk)
            self.ack[other] = self.seq[who]

    def handshake(self) -> None:
        self.t += 0.002
        syn = eth_ip_tcp(self.cli[0], self.srv[0], self.cli[1], self.srv[1], self.seq[self.cli] - 1, 0, b"", flags=0x02)
        synack = eth_ip_tcp(self.srv[0], self.cli[0], self.srv[1], self.cli[1], self.seq[self.srv] - 1,
                           self.seq[self.cli], b"", flags=0x12)
        ack = eth_ip_tcp(self.cli[0], self.srv[0], self.cli[1], self.srv[1], self.seq[self.cli],
                         self.seq[self.srv], b"", flags=0x10)
        self.packets.extend([(self.t, syn), (self.t + 0.001, synack), (self.t + 0.002, ack)])
        self.t += 0.003


# ---------------------------------------------------------------- 证书
def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CipherBox Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def make_ca(cn: str = "CipherBox Test Root CA") -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = 1767225600
    import datetime

    nb = datetime.datetime.fromtimestamp(now - 86400, datetime.timezone.utc)
    na = datetime.datetime.fromtimestamp(now + 86400 * 3650, datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def make_leaf(cn: str, ca_cert: x509.Certificate, ca_key, dns: str = "", ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    import datetime

    now = 1767225600
    nb = datetime.datetime.fromtimestamp(now - 3600, datetime.timezone.utc)
    na = datetime.datetime.fromtimestamp(now + 86400 * 365, datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(_name(cn)).issuer_name(ca_cert.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(nb).not_valid_after(na)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if dns:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert, key


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------- TLS
def hs(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def rec(ctype: int, body: bytes, version: int = 0x0303) -> bytes:
    return bytes([ctype]) + version.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def ext(etype: int, data: bytes) -> bytes:
    return struct.pack(">HH", etype, len(data)) + data


def sig_alg(a: int, b: int) -> str:
    return "%04x%04x" % (a, b)


def build_tls12(ca_cert, ca_key):
    server_cert, server_key = make_leaf("test-server", ca_cert, ca_key, dns="test.local")
    client_cert, client_key = make_leaf("test-client", ca_cert, ca_key)
    return server_cert, server_key, client_cert, client_key


def tls12_flow(ca_cert, ca_key, cli, srv, t0):
    server_cert, server_key, client_cert, client_key = build_tls12(ca_cert, ca_key)
    conv = TcpConv(cli, srv, t0)
    conv.handshake()

    c_random = bytes(range(32))
    s_random = bytes(range(32, 64))
    session_id = b"\x11" * 32

    eph_server = ec.generate_private_key(ec.SECP256R1())
    eph_client = ec.generate_private_key(ec.SECP256R1())

    exts_ch = (
        ext(0, struct.pack(">H", 13) + b"\x00" + b"\x00\x0a" + b"test.local")
        + ext(10, struct.pack(">H", 4) + struct.pack(">HH", 29, 23))
        + ext(11, b"\x01\x00")
        + ext(13, struct.pack(">H", 6) + struct.pack(">HHH", 0x0403, 0x0401, 0x0503))
        + ext(16, struct.pack(">H", 14) + b"\x02h2" + b"\x08http/1.1")
        + ext(23, b"")
        + ext(43, b"\x04" + struct.pack(">HH", 0x0304, 0x0303))
    )
    ch_body = (struct.pack(">H", 0x0303) + c_random + bytes([len(session_id)]) + session_id
               + struct.pack(">H", 10) + struct.pack(">HHHHH", 0xC02B, 0xC02F, 0x009C, 0x1301, 0x1302)
               + b"\x01\x00" + struct.pack(">H", len(exts_ch)) + exts_ch)
    client_hello = hs(1, ch_body)

    exts_sh = ext(11, b"\x01\x00") + ext(23, b"") + ext(65281, b"\x00")
    sh_body = (struct.pack(">H", 0x0303) + s_random + bytes([len(session_id)]) + session_id
               + struct.pack(">H", 0xC02B) + b"\x00"
               + struct.pack(">H", len(exts_sh)) + exts_sh)
    server_hello = hs(2, sh_body)

    entries = b""
    for c in (server_cert, ca_cert):
        d = der(c)
        entries += len(d).to_bytes(3, "big") + d
    cert_body = len(entries).to_bytes(3, "big") + entries
    server_cert_msg = hs(11, cert_body)

    point = eph_server.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
    params = b"\x03" + struct.pack(">H", 23) + bytes([len(point)]) + point
    signed = c_random + s_random + params
    sig = server_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    ske = hs(12, params + struct.pack(">HH", 0x0403, len(sig)) + sig)

    cert_req = hs(13, b"\x02\x01\x40" + struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0401)
                  + struct.pack(">H", 0))
    shd = hs(14, b"")

    conv.send(cli, rec(22, client_hello), split_at=37)          # 故意拆成两个 TCP 段
    conv.send(srv, rec(22, server_hello))
    conv.send(srv, rec(22, server_cert_msg))
    conv.send(srv, rec(22, ske))
    conv.send(srv, rec(22, cert_req + shd))

    # 客户端证书链
    client_chain = b""
    for c in (client_cert,):
        d = der(c)
        client_chain += len(d).to_bytes(3, "big") + d
    client_cert_msg = hs(11, len(client_chain).to_bytes(3, "big") + client_chain)

    c_point = eph_client.public_key().public_bytes(serialization.Encoding.X962,
                                                   serialization.PublicFormat.UncompressedPoint)
    ckx = hs(16, bytes([len(c_point)]) + c_point)

    transcript = client_hello + server_hello + server_cert_msg + ske + cert_req + shd + client_cert_msg + ckx
    cv_sig = client_key.sign(transcript, ec.ECDSA(hashes.SHA256()))
    cv = hs(15, struct.pack(">HH", 0x0403, len(cv_sig)) + cv_sig)

    conv.send(cli, rec(22, client_cert_msg))
    conv.send(cli, rec(22, ckx))
    conv.send(cli, rec(22, cv))
    conv.send(cli, rec(20, b"\x01"))
    conv.send(cli, rec(22, hs(20, b"\xaa" * 12)))
    conv.send(srv, rec(20, b"\x01"))
    conv.send(srv, rec(22, hs(20, b"\xbb" * 12)))
    return conv.packets, server_cert, client_cert


def tls13_flow(cli, srv, t0, ca_cert, ca_key):
    conv = TcpConv(cli, srv, t0)
    conv.handshake()
    c_random = bytes(range(64, 96))
    eph = x25519.X25519PrivateKey.generate()
    pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_share = struct.pack(">HH", 29, len(pub)) + pub
    exts_ch = (
        ext(0, struct.pack(">H", 14) + b"\x00" + b"\x00\x0b" + b"tls13.local")
        + ext(10, struct.pack(">H", 2) + struct.pack(">H", 29))
        + ext(13, struct.pack(">H", 2) + struct.pack(">H", 0x0804))
        + ext(43, b"\x02" + struct.pack(">H", 0x0304))
        + ext(51, struct.pack(">H", len(key_share)) + key_share)
    )
    ch = hs(1, struct.pack(">H", 0x0303) + c_random + b"\x00"
            + struct.pack(">H", 4) + struct.pack(">HH", 0x1301, 0x1302) + b"\x01\x00"
            + struct.pack(">H", len(exts_ch)) + exts_ch)
    spub = x25519.X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    exts_sh = ext(43, struct.pack(">H", 0x0304)) + ext(51, struct.pack(">HH", 29, len(spub)) + spub)
    sh = hs(2, struct.pack(">H", 0x0303) + bytes(range(96, 128)) + b"\x00"
            + struct.pack(">H", 0x1301) + b"\x00"
            + struct.pack(">H", len(exts_sh)) + exts_sh)
    conv.send(cli, rec(22, ch))
    conv.send(srv, rec(22, sh))
    conv.send(srv, rec(23, b"\x5d" * 48))     # EncryptedExtensions + Cert + CV + Finished（加密）
    conv.send(cli, rec(23, b"\x1a" * 40))
    conv.send(srv, rec(23, b"\x2b" * 320))    # 应用数据
    return conv.packets


def gen_tls() -> dict:
    ca_cert, ca_key = make_ca()
    p12, server_cert, client_cert = tls12_flow(ca_cert, ca_key, ("10.10.1.5", 51234), ("10.10.2.10", 443), TS0)
    p13 = tls13_flow(("10.10.1.6", 40122), ("10.10.2.10", 443), TS0 + 30, ca_cert, ca_key)
    path = os.path.join(FIXTURES, "tls_session.pcap")
    write_pcap(path, p12 + p13)
    write_pcapng(os.path.join(FIXTURES, "tls_session.pcapng"), p12 + p13)
    return {
        "file": path,
        "sessions": 2,
        "serverSubject": server_cert.subject.rfc4514_string(),
        "clientSubject": client_cert.subject.rfc4514_string(),
    }


# ---------------------------------------------------------------- SSH
def _ssh_str(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _ssh_mpint(raw: bytes) -> bytes:
    v = raw.lstrip(b"\x00")
    if not v:
        return b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return _ssh_str(v)


def ssh_packet(payload: bytes, block: int = 8) -> bytes:
    pad = block - (5 + len(payload)) % block
    if pad < 4:
        pad += block
    total = 4 + 1 + len(payload) + pad
    return struct.pack(">I", total - 4) + bytes([pad]) + payload + bytes(range(1, pad + 1))


def ssh_kexinit(cookie: bytes, kex, hostkey, enc, mac, comp="none") -> bytes:
    body = b"\x14" + cookie
    for lst in (kex, hostkey, enc, enc, mac, mac, comp, comp, "en", "en"):
        body += _ssh_str(lst.encode())
    body += b"\x00" + struct.pack(">I", 0)
    return body


def gen_ssh() -> dict:
    cli, srv = ("10.20.0.9", 55022), ("10.20.0.80", 22)
    conv = TcpConv(cli, srv, TS0 + 60)
    conv.handshake()
    v_c = b"SSH-2.0-OpenSSH_9.6p1"
    v_s = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
    conv.send(cli, v_c + b"\r\n")
    conv.send(srv, v_s + b"\r\n")

    i_c = ssh_kexinit(secrets.token_bytes(16),
                      "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256",
                      "ssh-ed25519,rsa-sha2-256", "aes128-ctr,aes256-ctr", "hmac-sha2-256,hmac-sha1")
    i_s = ssh_kexinit(secrets.token_bytes(16),
                      "curve25519-sha256,diffie-hellman-group14-sha256",
                      "ssh-ed25519", "aes128-ctr,aes256-gcm@openssh.com", "hmac-sha2-256")

    host_key = ed25519.Ed25519PrivateKey.generate()
    hk_raw = host_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    k_s = _ssh_str(b"ssh-ed25519") + _ssh_str(hk_raw)

    client_priv = x25519.X25519PrivateKey.generate()
    server_priv = x25519.X25519PrivateKey.generate()
    q_c = client_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    q_s = server_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    shared = client_priv.exchange(server_priv.public_key())          # 32 字节，小端
    k_mpint = _ssh_mpint(shared[::-1])

    h_input = (_ssh_str(v_c) + _ssh_str(v_s) + _ssh_str(i_c) + _ssh_str(i_s) + _ssh_str(k_s)
               + _ssh_str(q_c) + _ssh_str(q_s) + k_mpint)
    exchange_hash = hashlib.sha256(h_input).digest()
    sig = host_key.sign(exchange_hash)
    sig_blob = _ssh_str(b"ssh-ed25519") + _ssh_str(sig)

    init = b"\x1e" + _ssh_str(q_c)
    reply = b"\x1f" + _ssh_str(k_s) + _ssh_str(q_s) + _ssh_str(sig_blob)

    conv.send(cli, ssh_packet(i_c))
    conv.send(srv, ssh_packet(i_s))
    conv.send(cli, ssh_packet(init))
    conv.send(srv, ssh_packet(reply))
    conv.send(cli, ssh_packet(b"\x15"))
    conv.send(srv, ssh_packet(b"\x15"))

    path = os.path.join(FIXTURES, "ssh_session.pcap")
    write_pcap(path, conv.packets)
    return {
        "file": path,
        "kexSecret": shared[::-1].hex(),
        "hostKeyFingerprintPrefix": "SHA256:",
        "clientVersion": v_c.decode(),
        "serverVersion": v_s.decode(),
        "negotiatedKex": "curve25519-sha256",
        "negotiatedEnc": "aes128-ctr",
        "negotiatedMac": "hmac-sha2-256",
    }


# ---------------------------------------------------------------- IPSec / IKEv2
def ike_payload(ptype: int, body: bytes, nxt: int = 0) -> bytes:
    return bytes([nxt, 0]) + struct.pack(">H", 4 + len(body)) + body


def ike_msg(init_spi: bytes, resp_spi: bytes, exchange: int, flags: int, msg_id: int,
            payloads: list[tuple[int, bytes]]) -> bytes:
    chain = b""
    for idx, (ptype, body) in enumerate(payloads):
        nxt = payloads[idx + 1][0] if idx + 1 < len(payloads) else 0
        chain += ike_payload(ptype, body, nxt)
    header = (init_spi + resp_spi + bytes([payloads[0][0] if payloads else 0, 0x20, exchange, flags])
              + struct.pack(">I", msg_id) + struct.pack(">I", 28 + len(chain)))
    return header + chain


def ike_transform(tt: int, tid: int, attrs: list[tuple[int, int]], last: int = 1) -> bytes:
    body = b""
    for k, v in attrs:
        body += struct.pack(">HH", 0x8000 | k, v)
    body = bytes([last, 0]) + struct.pack(">H", 0) + bytes([tt, 0]) + struct.pack(">H", tid) + body
    body = bytearray(body)
    body[2:4] = struct.pack(">H", len(body))
    return bytes(body)


def ike_proposal(transforms: list[bytes], proto: int = 1) -> bytes:
    body = b"".join(transforms)
    head = bytes([1, 0, 0, 0]) + bytes([1, proto, 0, len(transforms)])
    out = bytearray(head + body)
    out[2:4] = struct.pack(">H", len(out))
    return bytes(out)


def ike_sa(transforms: list[bytes]) -> bytes:
    return ike_proposal(transforms)


def gen_ipsec() -> dict:
    cli, srv = ("10.30.0.2", 500), ("10.30.0.1", 500)
    init_spi = secrets.token_bytes(8)
    resp_spi = secrets.token_bytes(8)
    t = TS0 + 120
    packets = []

    enc = ike_transform(1, 12, [(14, 256)])
    prf = ike_transform(2, 3, [])
    integ = ike_transform(3, 12, [])
    dh = ike_transform(4, 14, [])
    life = ike_transform(11, 1, [(12, 28800)])
    sa_req = ike_sa([enc, prf, integ, dh, life])
    sa_resp = ike_sa([ike_transform(1, 12, [(14, 256)]),
                      ike_transform(2, 3, []),
                      ike_transform(3, 12, []),
                      ike_transform(4, 14, []),
                      ike_transform(11, 1, [(12, 3600)])])
    ke = struct.pack(">HH", 14, 0) + secrets.token_bytes(256)
    nonce_c = secrets.token_bytes(32)
    nonce_s = secrets.token_bytes(32)

    req1 = ike_msg(init_spi, b"\x00" * 8, 34, 0x08, 0, [(33, sa_req), (34, ke), (40, nonce_c)])
    res1 = ike_msg(init_spi, resp_spi, 34, 0x20, 0, [(33, sa_resp), (34, ke), (40, nonce_s)])

    ca_cert, ca_key = make_ca("IPSec Test Root CA")
    client_cert, _ = make_leaf("ipsec-client", ca_cert, ca_key)
    server_cert, _ = make_leaf("ipsec-server", ca_cert, ca_key)

    idi = b"\x02" + b"client@ipsec.test"
    idr = b"\x02" + b"vpn.ipsec.test"
    auth_sig = b"\x01" + secrets.token_bytes(256)
    cert_c = b"\x01" + der(client_cert)
    cert_s = b"\x01" + der(server_cert)

    req2 = ike_msg(init_spi, resp_spi, 35, 0x08, 1,
                   [(35, idi), (37, cert_c), (39, auth_sig), (46, secrets.token_bytes(64))])
    res2 = ike_msg(init_spi, resp_spi, 35, 0x20, 1,
                   [(36, idr), (37, cert_s), (39, auth_sig)])

    for i, (src, dst, body) in enumerate([
        (cli, srv, req1), (srv, cli, res1), (cli, srv, req2), (srv, cli, res2),
    ]):
        packets.append((t + i * 0.01, eth_ip_udp(src[0], dst[0], src[1], dst[1], body)))

    path = os.path.join(FIXTURES, "ipsec_ikev2.pcap")
    write_pcap(path, packets)
    return {
        "file": path,
        "initiatorSPI": init_spi.hex(),
        "responderSPI": resp_spi.hex(),
        "clientSubject": client_cert.subject.rfc4514_string(),
        "serverSubject": server_cert.subject.rfc4514_string(),
        "encAlgorithm": "AES-CBC",
        "encKeyLength": 256,
    }


def gen_ipsec_v1() -> dict:
    """IKEv1 主模式（身份保护）二进制样例：SA / KE / Nonce 三个载荷，双向。"""
    cli, srv = ("10.31.0.2", 500), ("10.31.0.1", 500)
    ic = secrets.token_bytes(8)
    rc = secrets.token_bytes(8)
    t = TS0 + 160

    def payload(ptype: int, body: bytes, nxt: int = 0) -> bytes:
        return bytes([nxt, 0]) + struct.pack(">H", 4 + len(body)) + body

    def msg(exchange: int, flags: int, mid: int, items: list[tuple[int, bytes]]) -> bytes:
        chain = b""
        for i, (pt, body) in enumerate(items):
            chain += payload(pt, body, items[i + 1][0] if i + 1 < len(items) else 0)
        hdr = ic + (rc if flags & 0x01 else b"\x00" * 8) + bytes([items[0][0], 0x10, exchange, flags])
        hdr += struct.pack(">II", mid, 28 + len(chain))
        return hdr + chain

    def transform(tt: int, tid: int, attrs: list[tuple[int, int]], last: int = 0) -> bytes:
        body = b"".join(struct.pack(">HH", 0x8000 | k, v) for k, v in attrs)
        out = bytearray(bytes([last, 0]) + struct.pack(">H", 0) + bytes([tt, 0]) + struct.pack(">H", tid) + body)
        out[2:4] = struct.pack(">H", len(out))
        return bytes(out)

    ts = (transform(1, 3, [(14, 168)], 0) + transform(2, 2, [], 0)
          + transform(3, 2, [], 0) + transform(4, 2, [], 1))
    prop = bytearray(b"\x00\x00\x00\x00" + bytes([1, 1, 0, 4]) + ts)
    prop[2:4] = struct.pack(">H", len(prop))
    sa = struct.pack(">II", 1, 1) + bytes(prop)      # DOI=IPSEC(1), Situation=IDENTITY(1)
    ke = secrets.token_bytes(128)                    # MODP-1024 密钥素材
    nonce = secrets.token_bytes(16)

    req = msg(2, 0x00, 0, [(1, sa), (4, ke), (10, nonce)])
    res = msg(2, 0x01, 0, [(1, sa), (4, secrets.token_bytes(128)), (10, secrets.token_bytes(16))])

    packets = [(t, eth_ip_udp(cli[0], srv[0], cli[1], srv[1], req)),
               (t + 0.01, eth_ip_udp(srv[0], cli[0], srv[1], cli[1], res))]
    path = os.path.join(FIXTURES, "ipsec_ikev1.pcap")
    write_pcap(path, packets)
    return {
        "file": path,
        "initiatorSPI": ic.hex(),
        "responderSPI": rc.hex(),
        "clientNonce": nonce.hex(),
        "protocol": "IKEv1",
    }


# ---------------------------------------------------------------- UKey
def ccid_block(mtype: int, seq: int, data: bytes, slot: int = 0) -> bytes:
    return (bytes([mtype]) + struct.pack("<I", len(data))
            + bytes([slot, seq & 0xFF, 0x00, 0x00, 0x00]) + data)


def gen_ukey() -> dict:
    ca_cert, ca_key = make_ca("UKey Test Root CA")
    cert, _ = make_leaf("ukey-user", ca_cert, ca_key)
    cert_der = der(cert)
    aid = bytes.fromhex("A000000063000017")
    t = TS0 + 200
    packets = []

    atr = bytes.fromhex("3B9F95803FC7A08031E073FE211B67")
    packets.append((t, usbpcap_frame(ccid_block(0x65, 0, b""))))
    packets.append((t + 0.01, usbpcap_frame(ccid_block(0x80, 0, atr), endpoint=0x81)))
    packets.append((t + 0.02, usbpcap_frame(ccid_block(0x6F, 0, b"\x00\xA4\x04\x00" + bytes([len(aid)]) + aid))))

    sel_resp = b"\x6F\x1A\x84\x08" + aid + b"Feitian ePass3003 GM" + b"\x90\x00"
    packets.append((t + 0.03, usbpcap_frame(ccid_block(0x80, 0, sel_resp), endpoint=0x81)))
    packets.append((t + 0.04, usbpcap_frame(ccid_block(0x6F, 1, b"\x00\xC0\x00\x00\x20"))))
    packets.append((t + 0.05, usbpcap_frame(ccid_block(0x80, 1, b"\x6F\x00\x90\x00"), endpoint=0x81)))
    packets.append((t + 0.06, usbpcap_frame(ccid_block(0x6F, 2, b"\x00\xB0\x00\x00" + bytes([min(len(cert_der), 0xFF)])))))
    packets.append((t + 0.07, usbpcap_frame(ccid_block(0x80, 2, cert_der + b"\x90\x00"), endpoint=0x81)))

    path = os.path.join(FIXTURES, "ukey_ccid.pcap")
    write_pcap(path, packets, linktype=249)
    return {
        "file": path,
        "vendor": "飞天诚信",
        "subject": cert.subject.rfc4514_string(),
        "atr": atr.hex().upper(),
        "apduCommands": ["SELECT", "GET RESPONSE", "READ BINARY"],
    }


# ---------------------------------------------------------------- 入口
def main() -> dict:
    os.makedirs(FIXTURES, exist_ok=True)
    info = {
        "tls": gen_tls(),
        "ssh": gen_ssh(),
        "ipsec": gen_ipsec(),
        "ipsecV1": gen_ipsec_v1(),
        "ukey": gen_ukey(),
    }
    with open(os.path.join(FIXTURES, "expectations.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, ensure_ascii=False, indent=2)
    for key, val in info.items():
        print("%-6s -> %s (%d bytes)" % (key, os.path.basename(val["file"]), os.path.getsize(val["file"])))
    return info


def emit_samples(info: dict | None = None) -> str:
    info = info or json.load(open(os.path.join(FIXTURES, "expectations.json"), encoding="utf-8"))
    out = []
    for key in ("tls", "ssh", "ipsec", "ipsecV1", "ukey"):
        raw = open(info[key]["file"], "rb").read()
        b64 = base64.b64encode(raw).decode()
        out.append("  // %s: %d bytes" % (key, len(raw)))
        out.append("  const %sPcap = '%s';" % (key.upper(), b64))
    return "\n".join(out)


if __name__ == "__main__":
    result = main()
    if "--emit-samples" in sys.argv:
        print(emit_samples(result))
