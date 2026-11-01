"""数字证书相关实现（纯本地计算）。

覆盖：
    * X.509 证书解析 / 格式逐项校验 / 证书链构建与验证
    * CRL 解析、CRL 签名验证与证书吊销状态查询
    * OCSP 响应离线解析与签名验证（不做任何网络请求）
    * SM2 / RSA 密钥与 CSR 生成、本地 CA 签发、PKCS#12 打包
    * ASN.1 DER 树形解析

签名与验签全部为真实运算：
    SM2 —— gmssl（SM3 with SM2，默认用户标识 1234567812345678）
    RSA —— cryptography（PKCS#1 v1.5 / PSS）
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import os
import re
import secrets
import threading
from typing import Any

from asn1crypto import algos as aalgos
from asn1crypto import core as acore
from asn1crypto import crl as acrl
from asn1crypto import csr as acsr
from asn1crypto import keys as akeys
from asn1crypto import x509 as ax509
from cryptography import x509 as cx509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    pkcs12,
)
from cryptography.x509 import ocsp as cocsp
from gmssl import sm2 as gmsm2
from gmssl import sm3 as gmsm3

from .asn1 import parse_der
from .asn1 import to_tree as _asn1_to_tree
from .common import ToolError, parse_bytes

UTC = dt.timezone.utc

# --------------------------------------------------------------------------- #
# OID 映射
# --------------------------------------------------------------------------- #
OID_SM2_CURVE = "1.2.156.10197.1.301"
OID_EC_PUBKEY = "1.2.840.10045.2.1"
OID_RSA = "1.2.840.113549.1.1.1"

# asn1crypto 默认不认识 SM2 公钥算法 OID（GM/T 0009 要求 SPKI 直接使用
# 1.2.156.10197.1.301），这里注册为 EC 族，使其可解析 SM2 证书/CSR/公钥。
akeys.PublicKeyAlgorithmId._map.setdefault(OID_SM2_CURVE, "ec")
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"

SIG_ALGS = {
    "1.2.840.113549.1.1.2": ("MD2withRSA", "MD2", "RSA"),
    "1.2.840.113549.1.1.4": ("MD5withRSA", "MD5", "RSA"),
    "1.2.840.113549.1.1.5": ("SHA1withRSA", "SHA1", "RSA"),
    "1.2.840.113549.1.1.11": ("SHA256withRSA", "SHA256", "RSA"),
    "1.2.840.113549.1.1.12": ("SHA384withRSA", "SHA384", "RSA"),
    "1.2.840.113549.1.1.13": ("SHA512withRSA", "SHA512", "RSA"),
    OID_RSASSA_PSS: ("RSASSA-PSS", "SHA256", "RSA"),
    "1.2.840.10045.4.1": ("SHA1withECDSA", "SHA1", "EC"),
    "1.2.840.10045.4.3.2": ("SHA256withECDSA", "SHA256", "EC"),
    "1.2.840.10045.4.3.3": ("SHA384withECDSA", "SHA384", "EC"),
    "1.2.840.10045.4.3.4": ("SHA512withECDSA", "SHA512", "EC"),
    "1.2.156.10197.1.501": ("SM3withSM2", "SM3", "SM2"),
    "1.2.156.10197.1.504": ("SM3withRSA", "SM3", "RSA"),
    "1.3.101.112": ("Ed25519", "-", "ED25519"),
}

PUB_ALGS = {
    OID_RSA: "RSA",
    OID_RSASSA_PSS: "RSA",
    OID_EC_PUBKEY: "EC",
    OID_SM2_CURVE: "SM2",
    "1.3.101.112": "Ed25519",
}

CURVES = {
    OID_SM2_CURVE: "SM2",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.3.132.0.10": "secp256k1",
}

EXT_NAMES = {
    "2.5.29.9": "主体目录属性",
    "2.5.29.14": "主体密钥标识",
    "2.5.29.15": "密钥用法",
    "2.5.29.16": "私钥使用期",
    "2.5.29.17": "主体备用名",
    "2.5.29.18": "颁发者备用名",
    "2.5.29.19": "基本约束",
    "2.5.29.30": "名称约束",
    "2.5.29.31": "CRL 分发点",
    "2.5.29.32": "证书策略",
    "2.5.29.33": "策略映射",
    "2.5.29.35": "颁发者密钥标识",
    "2.5.29.36": "策略约束",
    "2.5.29.37": "扩展密钥用法",
    "2.5.29.46": " freshestCRL",
    "2.5.29.54": "抑制任意策略",
    "1.3.6.1.5.5.7.1.1": "颁发机构信息访问",
    "1.3.6.1.5.5.7.1.11": "主题信息访问",
    "1.3.6.1.5.5.7.1.24": "TLS 特性",
    "1.3.6.1.5.5.7.48.1.5": "OCSP 无检查",
    "2.16.840.1.113730.1.1": "Netscape 证书类型",
    "1.3.6.1.4.1.11129.2.4.2": "SCT 列表",
    "1.3.6.1.4.1.311.20.2": "微软证书模板",
}
EXT_NAMES["2.5.29.46"] = "freshestCRL"

ATTR_ABBR = {
    "common_name": "CN",
    "country_name": "C",
    "state_or_province_name": "ST",
    "locality_name": "L",
    "organization_name": "O",
    "organizational_unit_name": "OU",
    "email_address": "Email",
    "serial_number": "SerialNumber",
    "domain_component": "DC",
    "street_address": "Street",
    "postal_code": "PostalCode",
    "business_category": "BusinessCategory",
    "jurisdiction_country_name": "JurisdictionC",
    "organizational_identifier": "OID",
    "2.5.4.97": "OID",
}

REASON_TEXT = {
    "unspecified": "未指定",
    "key_compromise": "密钥泄露",
    "ca_compromise": "CA 私钥泄露",
    "affiliation_changed": "隶属关系变更",
    "superseded": "证书被取代",
    "cessation_of_operation": "停止使用",
    "certificate_hold": "证书暂扣",
    "remove_from_crl": "从 CRL 移除",
    "privilege_withdrawn": "权限撤销",
    "aa_compromise": "AA 私钥泄露",
}

PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Za-z0-9 #\-]+)-----([A-Za-z0-9+/=\s\r\n]*)-----END \1-----", re.S
)
DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "local_ca",
)


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def pem_encode(der: bytes, label: str = "CERTIFICATE") -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def split_boxes(text: str, fmt: str | None = None) -> tuple[str, list[bytes]]:
    """把用户输入（PEM / Base64 / HEX / 多段）转成 DER 列表。"""
    raw = (text or "").strip()
    if not raw:
        raise ToolError("请输入需要处理的数据")
    if "-----BEGIN" in raw:
        out: list[bytes] = []
        for m in PEM_BLOCK.finditer(raw):
            body = re.sub(r"\s+", "", m.group(2))
            try:
                out.append(base64.b64decode(body + "=" * ((-len(body)) % 4)))
            except (binascii.Error, ValueError):
                raise ToolError("PEM 内容不是合法的 Base64")
        if not out:
            raise ToolError("未找到有效的 PEM 数据块")
        return "PEM", out
    f = (fmt or "AUTO").upper()
    if f in ("PEM", "AUTO"):
        for candidate in ("BASE64", "HEX"):
            try:
                return candidate, [parse_bytes(raw, candidate)]
            except ToolError:
                continue
        raise ToolError("无法识别输入格式，请使用 PEM、Base64 或十六进制")
    data = parse_bytes(raw, f)
    if not data:
        raise ToolError("输入数据为空")
    return f, [data]


def split_der_stream(data: bytes) -> list[bytes]:
    """把连续拼接的 DER 元素拆成多个。"""
    out: list[bytes] = []
    off = 0
    while off < len(data) and data[off] != 0x00:
        try:
            node = parse_der(data[off:])
        except ToolError:
            break
        total = node.header_len + node.length
        if total <= 0 or off + total > len(data):
            break
        out.append(data[off : off + total])
        off += total
    return out or [data]


def _dec(v: Any) -> Any:
    return v.chosen if isinstance(v, acore.Choice) else v


def datetime_to_text(value: dt.datetime | None) -> str:
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def name_to_dict(name: ax509.Name) -> dict[str, Any]:
    fields: dict[str, str] = {}
    records: list[dict[str, str]] = []
    parts: list[str] = []
    for rdn in name.chosen:
        for atv in rdn:
            try:
                key = atv["type"].native
            except Exception:
                key = atv["type"].dotted
            try:
                val = atv["value"].native
            except Exception:
                val = ""
            if not isinstance(val, str):
                val = str(val)
            abbr = ATTR_ABBR.get(key, key if "." in key else key.upper())
            records.append({"type": abbr, "name": key, "value": val})
            fields.setdefault(key, val)
            parts.append(f"{abbr}={val}")
    # RFC 4514 展示习惯：由后向前（CN 在前）
    return {"text": ", ".join(reversed(parts)), "fields": fields, "items": records, "der": name.dump()}


def _digest_hex(data: bytes, algo: str) -> str:
    algo = algo.upper()
    if algo == "SM3":
        return gmsm3.sm3_hash(list(data))
    return hashlib.new(algo.lower(), data).hexdigest()


def fingerprints(der: bytes) -> dict[str, str]:
    return {
        "SHA256": _digest_hex(der, "SHA256"),
        "SHA1": _digest_hex(der, "SHA1"),
        "MD5": _digest_hex(der, "MD5"),
        "SM3": _digest_hex(der, "SM3"),
    }


def _fmt_fp(hexstr: str) -> str:
    return ":".join(hexstr[i : i + 2].upper() for i in range(0, len(hexstr), 2))


# --------------------------------------------------------------------------- #
# X.509 解析
# --------------------------------------------------------------------------- #
def _ext_summary(ext: ax509.Extension) -> dict[str, Any]:
    oid = ext["extn_id"].dotted
    name = EXT_NAMES.get(oid)
    if not name:
        try:
            name = ext["extn_id"].native
        except Exception:
            name = oid
    critical = bool(ext["critical"].native)
    try:
        parsed = ext["extn_value"].parsed
        native = parsed.native
        brief = _native_brief(native)
    except Exception:
        try:
            native = ext["extn_value"].native
            brief = _native_brief(native)
        except Exception:
            native = None
            brief = ""
    if not brief:
        raw = ext["extn_value"].dump()
        brief = raw.hex() if len(raw) <= 32 else raw[:32].hex() + "…"
    return {"oid": oid, "name": name, "critical": critical, "brief": brief, "native": native}


def _native_brief(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, dt.datetime):
        return datetime_to_text(value)
    if isinstance(value, dict):
        return "; ".join(f"{k}={_native_brief(v)}" for k, v in value.items() if v is not None)
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_native_brief(v) for v in value)
    return str(value)


def parse_cert(der: bytes) -> dict[str, Any]:
    """解析单张 X.509 证书，返回结构化信息（解析失败抛 ToolError）。"""
    if not der:
        raise ToolError("证书数据为空")
    try:
        cert = ax509.Certificate.load(der)
        tbs = cert["tbs_certificate"]
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"证书解析失败：{exc.__class__.__name__}")

    info: dict[str, Any] = {"der": der, "pem": pem_encode(der), "length": len(der)}

    # 版本 / 序列号
    try:
        version = tbs["version"].native
    except Exception:
        version = "v1"
    info["version"] = version
    serial_int = int(tbs["serial_number"].native)
    serial_hex = format(serial_int, "X")
    if len(serial_hex) % 2:
        serial_hex = "0" + serial_hex
    info["serial"] = serial_hex
    info["serial_dec"] = serial_int
    info["serial_bytes"] = len(tbs["serial_number"].contents)

    # 名称
    info["subject"] = name_to_dict(cert.subject)
    info["issuer"] = name_to_dict(cert.issuer)
    info["subject_der"] = info["subject"]["der"]
    info["issuer_der"] = info["issuer"]["der"]

    # 有效期
    validity = tbs["validity"]
    nb_raw = validity["not_before"]
    na_raw = validity["not_after"]
    info["not_before"] = nb_raw.native
    info["not_after"] = na_raw.native
    info["not_before_text"] = datetime_to_text(nb_raw.native)
    info["not_after_text"] = datetime_to_text(na_raw.native)
    info["not_before_type"] = type(nb_raw.chosen).__name__
    info["not_after_type"] = type(na_raw.chosen).__name__
    info["not_before_raw"] = nb_raw.chosen.contents.hex()
    info["not_after_raw"] = na_raw.chosen.contents.hex()

    # 签名算法
    outer_oid = cert["signature_algorithm"]["algorithm"].dotted
    inner_oid = ""

    # 公钥
    pki = cert.public_key
    pub_oid = pki["algorithm"]["algorithm"].dotted
    curve_oid = ""
    try:
        params = pki["algorithm"]["parameters"]
        if params is not None and not isinstance(params, acore.Null):
            if isinstance(params, acore.ObjectIdentifier):
                curve_oid = params.dotted
            elif isinstance(params, acore.Choice):
                chosen = params.chosen
                if isinstance(chosen, acore.ObjectIdentifier):
                    curve_oid = chosen.dotted
    except Exception:
        curve_oid = ""
    pub_alg = PUB_ALGS.get(pub_oid, pub_oid)
    if pub_alg == "EC" and curve_oid == OID_SM2_CURVE:
        pub_alg = "SM2"
    if pub_alg == "EC":
        pub_alg = "ECDSA"
    key_bits = 0
    pub_hex = ""
    try:
        raw_key = pki["public_key"].native
        if isinstance(raw_key, (bytes, bytearray)):
            pub_hex = bytes(raw_key).hex()
            key_bits = len(raw_key) * 8
    except Exception:
        pass
    if pub_alg == "SM2":
        key_bits = 256
    elif pub_alg in ("RSA",):
        key_bits = _rsa_bits(der)
    elif pub_alg == "ECDSA":
        key_bits = {"P-256": 256, "P-384": 384, "P-521": 521}.get(CURVES.get(curve_oid, ""), key_bits or 0)
    info.update(
        {
            "sig_oid": outer_oid,
            "sig_alg": sig_alg_name(outer_oid),
            "pub_oid": pub_oid,
            "pub_alg": pub_alg,
            "curve": CURVES.get(curve_oid, "") if curve_oid else "",
            "curve_oid": curve_oid,
            "key_bits": key_bits,
            "pub_hex": pub_hex,
            "spki": pki.dump(),
        }
    )

    # 签名字节，用于验签
    inner_oid = cert["tbs_certificate"]["signature"]["algorithm"].dotted
    info["tbs_sig_oid"] = inner_oid
    info["sig_alg_tbs"] = sig_alg_name(inner_oid)
    info["sig_matches_tbs"] = inner_oid == outer_oid
    info["signature"] = cert["signature_value"].native
    info["tbs"] = tbs.dump()

    # 扩展
    exts: list[dict[str, Any]] = []
    try:
        raw_exts = tbs["extensions"]
        if raw_exts is not None:
            exts = [_ext_summary(e) for e in raw_exts]
    except Exception:
        exts = []
    info["extensions"] = exts
    info["ext_count"] = len(exts)

    def _native_of(oid: str) -> Any:
        for e in exts:
            if e["oid"] == oid:
                return e["native"]
        return None

    bc = _native_of("2.5.29.19")
    if isinstance(bc, dict):
        info["is_ca"] = bool(bc.get("ca"))
        info["path_len"] = bc.get("path_len_constraint")
    else:
        info["is_ca"] = False
        info["path_len"] = None

    ku = _native_of("2.5.29.15")
    if isinstance(ku, (set, list, tuple)):
        info["key_usage"] = sorted(str(k) for k in ku)
    elif ku is None:
        info["key_usage"] = []
    else:
        info["key_usage"] = [str(ku)]

    eku = _native_of("2.5.29.37")
    if isinstance(eku, (list, tuple, set)):
        info["eku"] = [str(k) for k in eku]
    elif eku:
        info["eku"] = [str(eku)]
    else:
        info["eku"] = []

    san = _native_of("2.5.29.17")
    san_items: list[str] = []
    if isinstance(san, (list, tuple)):
        for item in san:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                san_items.append(f"{item[0]}:{item[1]}")
            else:
                san_items.append(str(item))
    info["san"] = san_items

    ski = _native_of("2.5.29.14")
    info["ski"] = bytes(ski).hex().upper() if isinstance(ski, (bytes, bytearray)) else ""
    aki = _native_of("2.5.29.35")
    if isinstance(aki, dict):
        keyid = aki.get("key_identifier")
        info["aki"] = bytes(keyid).hex().upper() if isinstance(keyid, (bytes, bytearray)) else ""
    else:
        info["aki"] = ""

    info["crl_urls"] = _urls_of(info, "2.5.29.31")
    info["ocsp_urls"] = _aia_ocsp(info)

    info["self_signed"] = (
        cert.subject.dump() == cert.issuer.dump()
    )
    info["fingerprints"] = fingerprints(der)
    info["sha256"] = _fmt_fp(info["fingerprints"]["SHA256"])
    info["sha1"] = _fmt_fp(info["fingerprints"]["SHA1"])
    info["sm3"] = _fmt_fp(info["fingerprints"]["SM3"])
    info["md5"] = _fmt_fp(info["fingerprints"]["MD5"])

    now = dt.datetime.now(UTC)
    info["days_left"] = int((info["not_after"] - now).total_seconds() // 86400)
    info["expired"] = info["not_after"] < now
    info["not_yet_valid"] = info["not_before"] > now
    return info


def _rsa_bits(der: bytes) -> int:
    try:
        key = serialization.load_der_public_key(
            ax509.Certificate.load(der)["tbs_certificate"]["subject_public_key_info"].dump()
        )
        return getattr(key, "key_size", 0)
    except Exception:
        return 0


def _urls_of(info: dict[str, Any], oid: str) -> list[str]:
    urls: list[str] = []
    for e in info.get("extensions", []):
        if e["oid"] != oid:
            continue
        native = e.get("native")
        if isinstance(native, list):
            for point in native:
                if isinstance(point, dict):
                    name = point.get("distribution_point")
                    if isinstance(name, dict):
                        full = name.get("full_name")
                        if isinstance(full, list):
                            for fn in full:
                                if isinstance(fn, dict) and fn.get("uniform_resource_identifier"):
                                    urls.append(str(fn["uniform_resource_identifier"]))
    return urls


def _aia_ocsp(info: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for e in info.get("extensions", []):
        if e["oid"] != "1.3.6.1.5.5.7.1.1":
            continue
        native = e.get("native")
        if isinstance(native, (list, tuple)):
            for acc in native:
                if not isinstance(acc, dict):
                    continue
                method = str(acc.get("access_method", "")).lower()
                if method not in ("ocsp", "1.3.6.1.5.5.7.48.1"):
                    continue
                loc = acc.get("access_location")
                if isinstance(loc, dict):
                    uri = loc.get("uniform_resource_identifier")
                    if uri:
                        urls.append(str(uri))
                elif isinstance(loc, str) and loc:
                    urls.append(loc)
    return urls


def sig_alg_name(oid: str) -> str:
    item = SIG_ALGS.get(oid)
    if item:
        return item[0]
    return oid


def load_certs(text: str, fmt: str | None = None, name: str = "证书") -> list[dict[str, Any]]:
    kind, blobs = split_boxes(text, fmt)
    ders: list[bytes] = []
    for blob in blobs:
        if blob[:1] == b"\x30":
            ders.extend(split_der_stream(blob))
        else:
            raise ToolError(f"{name}数据不是有效的 DER 编码（首字节不是 SEQUENCE）")
    certs: list[dict[str, Any]] = []
    for der in ders:
        try:
            certs.append(parse_cert(der))
        except ToolError:
            continue
    if not certs:
        raise ToolError(f"未能从输入中解析出有效{name}，请确认是 X.509 证书")
    for c in certs:
        c["input_format"] = kind
    return certs


# --------------------------------------------------------------------------- #
# 签名 / 验签
# --------------------------------------------------------------------------- #
def _hash_obj(hash_name: str) -> hashes.HashAlgorithm:
    table = {
        "MD5": hashes.MD5,
        "SHA1": hashes.SHA1,
        "SHA224": hashes.SHA224,
        "SHA256": hashes.SHA256,
        "SHA384": hashes.SHA384,
        "SHA512": hashes.SHA512,
    }
    if hash_name == "SM3" and hasattr(hashes, "SM3"):
        return hashes.SM3()
    cls = table.get(hash_name)
    if not cls:
        raise ToolError(f"不支持的摘要算法：{hash_name}")
    return cls()


def sm2_sign(priv_hex: str, pub_hex: str, data: bytes) -> bytes:
    signer = gmsm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, asn1=True)
    sig_hex = signer.sign_with_sm3(data)
    if not sig_hex:
        raise ToolError("SM2 签名运算失败，请重试")
    return bytes.fromhex(sig_hex)


def sm2_verify(pub_hex: str, signature: bytes, data: bytes) -> bool:
    verifier = gmsm2.CryptSM2(private_key="", public_key=pub_hex, asn1=True)
    try:
        return bool(verifier.verify_with_sm3(signature.hex(), data))
    except Exception:
        return False


def verify_signature(data: bytes, signature: bytes, sig_oid: str, spki_der: bytes, pub_hex: str = "") -> tuple[bool, str]:
    """用公钥验证 data 的签名，返回 (是否通过, 说明)。"""
    algo = SIG_ALGS.get(sig_oid)
    if not algo:
        return False, f"暂不支持的签名算法 OID：{sig_oid}"
    name, hash_name, family = algo
    if family == "SM2":
        if not pub_hex:
            return False, "缺少 SM2 公钥"
        ok = sm2_verify(pub_hex, signature, data)
        return ok, "SM3withSM2 签名验证" + ("通过" if ok else "未通过")
    if family == "ECDSA":
        try:
            key = serialization.load_der_public_key(spki_der)
            key.verify(signature, data, ec.ECDSA(_hash_obj(hash_name)))
            return True, f"{name} 签名验证通过"
        except InvalidSignature:
            return False, f"{name} 签名验证未通过"
        except Exception as exc:  # noqa: BLE001
            return False, f"{name} 签名验证失败：{exc.__class__.__name__}"
    if family == "RSA":
        try:
            key = serialization.load_der_public_key(spki_der)
        except Exception:
            return False, "公钥无法解析，无法验证 RSA 签名"
        try:
            if sig_oid == OID_RSASSA_PSS:
                key.verify(
                    signature,
                    data,
                    padding.PSS(mgf=padding.MGF1(_hash_obj(hash_name)), salt_length=32),
                    _hash_obj(hash_name),
                )
            else:
                key.verify(signature, data, padding.PKCS1v15(), _hash_obj(hash_name))
            return True, f"{name} 签名验证通过"
        except InvalidSignature:
            return False, f"{name} 签名验证未通过"
        except Exception as exc:  # noqa: BLE001
            return False, f"{name} 签名验证失败：{exc.__class__.__name__}"
    return False, f"暂不支持的签名算法：{name}"


# --------------------------------------------------------------------------- #
# 证书格式逐项校验
# --------------------------------------------------------------------------- #
def _item(name: str, value: str, info_msg: str, valid: int) -> dict[str, Any]:
    return {"name": name, "value": value, "infoMsg": info_msg, "valid": valid}


def _weak_sig(sig_name: str) -> bool:
    return any(x in sig_name for x in ("MD5", "SHA1", "MD2"))


def format_items(cert: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    now = dt.datetime.now(UTC)

    # 1 证书格式
    items.append(
        _item(
            "证书格式",
            f"{cert.get('input_format', 'DER')} · {cert['length']} 字节",
            "X.509 证书结构解析成功",
            2,
        )
    )

    # 2 版本
    ver = cert["version"]
    if ver == "v3":
        items.append(_item("证书版本", "V3", "使用 v3 版本，支持扩展项", 2))
    elif ver == "v2":
        items.append(_item("证书版本", "V2", "RFC 5280 建议使用 v3 版本", 1))
    else:
        items.append(_item("证书版本", (ver or "v1").upper(), "v1 证书不支持扩展项，不符合 RFC 5280 建议", 0))

    # 3 序列号
    serial = cert["serial"]
    serial_bit = cert["serial_dec"].bit_length()
    if cert["serial_dec"] <= 0:
        items.append(_item("序列号", serial, "序列号必须为正整数", 0))
    elif cert["serial_bytes"] > 20:
        items.append(_item("序列号", serial, "序列号长度超过 20 字节，不符合 RFC 5280", 0))
    elif serial_bit < 64:
        items.append(_item("序列号", serial, f"序列号仅 {serial_bit} 位，建议使用 64 位以上随机数", 1))
    else:
        items.append(_item("序列号", serial, f"{serial_bit} 位，符合唯一性要求", 2))

    # 4 签名算法
    sig_name = cert["sig_alg"]
    if not cert["sig_matches_tbs"]:
        items.append(
            _item("签名算法", sig_name, f"内外签名算法不一致（TBS 为 {cert['sig_alg_tbs']}），不符合规范", 0)
        )
    elif cert["sig_oid"] not in SIG_ALGS:
        items.append(_item("签名算法", sig_name, "未识别的签名算法 OID", 0))
    elif _weak_sig(sig_name):
        items.append(_item("签名算法", sig_name, "摘要算法强度不足，不建议在生产环境使用", 1))
    else:
        items.append(_item("签名算法", sig_name, "签名算法强度符合要求", 2))

    # 5 颁发者 / 6 主题
    if cert["issuer"]["text"]:
        items.append(_item("颁发者", cert["issuer"]["text"], "颁发者可分辨名称解析成功", 2))
    else:
        items.append(_item("颁发者", "（空）", "颁发者名称不能为空", 0))
    if cert["subject"]["text"]:
        items.append(_item("使用者", cert["subject"]["text"], "使用者可分辨名称解析成功", 2))
    else:
        items.append(_item("使用者", "（空）", "使用者名称不能为空", 0))

    # 7 公钥算法与长度
    pub_desc = cert["pub_alg"]
    if cert["curve"]:
        pub_desc += f"（{cert['curve']} 曲线）"
    pub_desc += f" · {cert['key_bits']} 位"
    if cert["pub_alg"] == "RSA":
        if cert["key_bits"] >= 2048:
            items.append(_item("公钥算法", pub_desc, "RSA 密钥长度符合要求", 2))
        elif cert["key_bits"] >= 1024:
            items.append(_item("公钥算法", pub_desc, "RSA 1024 位强度不足，建议 2048 位以上", 1))
        else:
            items.append(_item("公钥算法", pub_desc, "RSA 密钥长度过短，不符合安全要求", 0))
    elif cert["pub_alg"] == "SM2":
        items.append(_item("公钥算法", pub_desc, "SM2 椭圆曲线公钥（256 位），符合 GM/T 0015", 2))
    elif cert["pub_alg"] == "ECDSA":
        bits = cert["key_bits"]
        items.append(
            _item("公钥算法", pub_desc, "椭圆曲线公钥长度符合要求" if bits >= 256 else "曲线强度不足", 2 if bits >= 256 else 1)
        )
    else:
        items.append(_item("公钥算法", pub_desc, "非常用公钥算法，仅作解析展示", 1))

    pub_der = cert.get("spki", b"")
    pub_text = pub_der.hex().upper()
    items.append(
        _item(
            "公钥值",
            (pub_text[:256] + "…") if len(pub_text) > 256 else pub_text,
            f"SubjectPublicKeyInfo，共 {len(pub_der)} 字节",
            2,
        )
    )

    # 8 有效期
    nb, na = cert["not_before"], cert["not_after"]
    span = f"{cert['not_before_text']} ~ {cert['not_after_text']}"
    if na <= nb:
        items.append(_item("有效期", span, "失效时间早于生效时间，证书非法", 0))
    elif now < nb:
        items.append(_item("有效期", span, f"证书尚未生效（还差 {(nb - now).days} 天）", 0))
    elif now > na:
        items.append(_item("有效期", span, f"证书已过期（已过期 {abs(cert['days_left'])} 天）", 0))
    else:
        items.append(_item("有效期", span, f"当前处于有效期内，剩余 {cert['days_left']} 天", 2))

    # 9 时间编码
    nb_t, na_t = cert["not_before_type"], cert["not_after_type"]
    bad_time = []
    for label, value, kind in (("notBefore", nb, nb_t), ("notAfter", na, na_t)):
        year = value.year
        if kind == "UTCTime" and year >= 2050:
            bad_time.append(f"{label} 年份 {year} 应使用 GeneralizedTime")
        if kind == "GeneralizedTime" and 1950 <= year < 2050:
            bad_time.append(f"{label} 年份 {year} 应使用 UTCTime")
    if bad_time:
        items.append(_item("时间格式", f"{nb_t} / {na_t}", "；".join(bad_time) + "（RFC 5280 4.1.2.5）", 0))
    else:
        items.append(_item("时间格式", f"{nb_t} / {na_t}", "时间编码符合 RFC 5280 要求", 2))

    # 10 密钥用法
    ku = cert["key_usage"]
    ku_text = ", ".join(ku) if ku else "（未声明）"
    if cert["is_ca"]:
        if not ku:
            items.append(_item("密钥用法", ku_text, "CA 证书缺少 keyUsage 扩展，不符合要求", 0))
        elif "key_cert_sign" not in ku:
            items.append(_item("密钥用法", ku_text, "CA 证书 keyUsage 未包含 keyCertSign", 0))
        else:
            items.append(_item("密钥用法", ku_text, "CA 证书密钥用法正确", 2))
    else:
        if not ku:
            items.append(_item("密钥用法", ku_text, "缺少 keyUsage 扩展，建议声明", 1))
        elif "digital_signature" in ku or "key_encipherment" in ku:
            items.append(_item("密钥用法", ku_text, "终端证书密钥用法符合要求", 2))
        else:
            items.append(_item("密钥用法", ku_text, "keyUsage 未包含签名或加密用途，请确认", 1))

    # 11 扩展密钥用法
    eku = cert["eku"]
    if cert["is_ca"]:
        items.append(_item("扩展密钥用法", ", ".join(eku) if eku else "不适用", "CA 证书通常无需 EKU", 2))
    elif eku:
        items.append(_item("扩展密钥用法", ", ".join(eku), "已声明扩展密钥用法", 2))
    else:
        items.append(_item("扩展密钥用法", "（未声明）", "终端证书建议声明 EKU（serverAuth/clientAuth）", 1))

    # 12 基本约束
    if cert["is_ca"]:
        pl = cert["path_len"]
        items.append(
            _item(
                "基本约束",
                f"CA=TRUE, pathLen={'-' if pl is None else pl}",
                "CA 证书基本约束正确",
                2,
            )
        )
    else:
        bc = next((e for e in cert["extensions"] if e["oid"] == "2.5.29.19"), None)
        if bc is None:
            items.append(_item("基本约束", "（未声明）", "终端证书缺少 basicConstraints 扩展", 1))
        elif not bc["critical"]:
            items.append(_item("基本约束", "CA=FALSE", "basicConstraints 应为关键扩展（critical）", 1))
        else:
            items.append(_item("基本约束", "CA=FALSE（critical）", "终端证书基本约束正确", 2))

    # 13 主体备用名
    if cert["san"]:
        items.append(_item("主体备用名", ", ".join(cert["san"][:6]), f"共 {len(cert['san'])} 项 SAN", 2))
    elif cert["is_ca"]:
        items.append(_item("主体备用名", "不适用", "CA 证书无需 SAN", 2))
    else:
        cn = cert["subject"]["fields"].get("common_name", "")
        if cn:
            items.append(_item("主体备用名", "（未声明）", "仅依赖 CN 标识身份，RFC 6125 建议使用 SAN", 1))
        else:
            items.append(_item("主体备用名", "（未声明）", "缺少 SAN 且无 CN，证书无法标识身份", 0))

    # 14 密钥标识
    if cert["ski"] and cert["aki"]:
        items.append(_item("密钥标识", f"SKI={cert['ski'][:16]}… / AKI={cert['aki'][:16]}…", "主体与颁发者密钥标识齐全", 2))
    elif cert["ski"]:
        items.append(_item("密钥标识", f"SKI={cert['ski'][:16]}…", "缺少 AKI，建议补充以支持链构建", 1))
    else:
        items.append(_item("密钥标识", "（未声明）", "缺少 SKI/AKI 扩展", 1))

    # 15 扩展项
    ext_names = ", ".join(f"{e['name']}" for e in cert["extensions"]) or "（无）"
    items.append(_item("扩展项", ext_names, f"共 {cert['ext_count']} 个扩展", 2))

    # 16 签名值验证（自签证书才能独立校验）
    if cert["self_signed"]:
        ok, msg = verify_signature(cert["tbs"], cert["signature"], cert["sig_oid"], cert["spki"], cert["pub_hex"])
        items.append(_item("签名验证", "通过" if ok else "未通过", msg + "（自签证书）", 2 if ok else 0))
    else:
        items.append(_item("签名验证", "待验证", "非自签证书，需在“证书链验证”中用上级证书公钥验证", 1))

    # 17 指纹
    items.append(_item("SHA256 指纹", cert["sha256"], "SHA-256 摘要", 2))
    items.append(_item("SM3 指纹", cert["sm3"], "GB/T 32905 SM3 摘要", 2))
    return items


def summarize(items: list[dict[str, Any]]) -> tuple[str, str]:
    bad = [i for i in items if i["valid"] == 0]
    warn = [i for i in items if i["valid"] == 1]
    if bad:
        status = "error"
        summary = f"存在 {len(bad)} 项不符合：" + "、".join(i["name"] for i in bad[:5])
    elif warn:
        status = "partial"
        summary = f"存在 {len(warn)} 项部分符合：" + "、".join(i["name"] for i in warn[:5])
    else:
        status = "success"
        summary = "全部检查项均符合要求"
    return status, summary


def cert_info_view(cert: dict[str, Any]) -> dict[str, Any]:
    """给前端展示用的精简证书信息（去掉二进制字段）。"""
    return {
        "version": cert["version"],
        "serial": cert["serial"],
        "subject": cert["subject"]["text"],
        "subjectFields": cert["subject"]["fields"],
        "issuer": cert["issuer"]["text"],
        "notBefore": cert["not_before_text"],
        "notAfter": cert["not_after_text"],
        "sigAlg": cert["sig_alg"],
        "sigOid": cert["sig_oid"],
        "pubAlg": cert["pub_alg"],
        "curve": cert["curve"],
        "keyBits": cert["key_bits"],
        "selfSigned": cert["self_signed"],
        "isCa": cert["is_ca"],
        "pathLen": cert["path_len"],
        "keyUsage": cert["key_usage"],
        "eku": cert["eku"],
        "san": cert["san"],
        "ski": cert["ski"],
        "aki": cert["aki"],
        "crlUrls": cert["crl_urls"],
        "ocspUrls": cert["ocsp_urls"],
        "daysLeft": cert["days_left"],
        "expired": cert["expired"],
        "length": cert["length"],
        "sha256": cert["sha256"],
        "sm3": cert["sm3"],
        "fingerprintSm3": cert["fingerprints"]["SM3"],
        "fingerprintSha256": cert["fingerprints"]["SHA256"],
        "extensions": [
            {"oid": e["oid"], "name": e["name"], "critical": e["critical"], "brief": e["brief"]}
            for e in cert["extensions"]
        ],
    }


# --------------------------------------------------------------------------- #
# 证书链
# --------------------------------------------------------------------------- #
def _issuer_matches(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    if child.get("issuer_der") and parent.get("subject_der"):
        return child["issuer_der"] == parent["subject_der"]
    return child["issuer"]["text"] == parent["subject"]["text"]


def chain_node_items(
    child: dict[str, Any], parent: dict[str, Any] | None, is_root: bool, ca_below: int = 0
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    items.append(_item("证书上传", "已上传", "节点已上传证书", 2))
    items.append(_item("证书解析", "通过", "证书可以正常解析：" + (child["subject"]["text"] or "（空）"), 2))
    if is_root:
        if child["self_signed"]:
            items.append(_item("根证书自签", "是", "主题与颁发者一致，为自签根证书", 2))
        else:
            items.append(_item("根证书自签", "否", "根节点证书主题与颁发者不一致", 0))
        ok, msg = verify_signature(child["tbs"], child["signature"], child["sig_oid"], child["spki"], child["pub_hex"])
        items.append(_item("根证书签名", "通过" if ok else "未通过", msg + "（自签校验）", 2 if ok else 0))
        if child["is_ca"]:
            items.append(_item("CA 约束", "CA=TRUE", "根证书具备 CA 能力", 2))
        else:
            items.append(_item("CA 约束", "CA=FALSE", "根证书未声明 basicConstraints CA:TRUE", 0))
        if child["expired"] or child["not_yet_valid"]:
            items.append(
                _item("有效期", f"{child['not_before_text']} ~ {child['not_after_text']}", "根证书不在有效期内", 0)
            )
        else:
            items.append(
                _item("有效期", f"{child['not_before_text']} ~ {child['not_after_text']}", f"剩余 {child['days_left']} 天", 2)
            )
        return items

    assert parent is not None
    if _issuer_matches(child, parent):
        items.append(_item("颁发者匹配", f"{child['issuer']['text']} = 上级主题", "下级证书颁发者与上级证书主题一致", 2))
    else:
        items.append(
            _item(
                "颁发者匹配",
                f"{child['issuer']['text']} ≠ {parent['subject']['text']}",
                "下级证书颁发者与上级证书主题不一致，链关系错误",
                0,
            )
        )

    ok, msg = verify_signature(child["tbs"], child["signature"], child["sig_oid"], parent["spki"], parent["pub_hex"])
    if not ok and parent["pub_alg"] != child["sig_alg"].startswith("SM3"):
        msg += "（请确认签名算法与上级公钥是否匹配）"
    items.append(_item("签名验证", "通过" if ok else "未通过", msg, 2 if ok else 0))

    if parent["is_ca"]:
        items.append(_item("上级 CA 约束", "CA=TRUE", "上级证书具备签发能力", 2))
    else:
        items.append(_item("上级 CA 约束", "CA=FALSE", "上级证书不是 CA，不能签发下级证书", 0))

    if "key_cert_sign" in parent["key_usage"] or not parent["key_usage"]:
        items.append(
            _item(
                "上级密钥用法",
                ", ".join(parent["key_usage"]) or "（未声明）",
                "上级证书可用于签发证书" if parent["key_usage"] else "上级证书未声明 keyUsage，按 CA 处理",
                2 if parent["key_usage"] else 1,
            )
        )
    else:
        items.append(_item("上级密钥用法", ", ".join(parent["key_usage"]), "上级证书 keyUsage 不含 keyCertSign", 0))

    # 路径长度约束：pathLenConstraint = 允许的下级 CA 证书数量（RFC 5280 4.2.1.9）
    if parent["is_ca"] and parent["path_len"] is not None:
        limit = int(parent["path_len"])
        if ca_below > limit:
            items.append(
                _item(
                    "路径长度",
                    f"pathLen={limit}，其下 CA 证书 {ca_below} 张",
                    "下级 CA 证书数量超过上级 pathLenConstraint",
                    0,
                )
            )
        else:
            items.append(
                _item("路径长度", f"pathLen={limit}，其下 CA 证书 {ca_below} 张", "满足路径长度约束", 2)
            )
    else:
        items.append(_item("路径长度", "无限制", "上级证书未设置 pathLenConstraint", 2))

    if child["not_before"] < parent["not_before"] - dt.timedelta(seconds=60) or child["not_after"] > parent["not_after"] + dt.timedelta(seconds=60):
        items.append(
            _item(
                "有效期包含",
                f"{child['not_before_text'][:10]} ~ {child['not_after_text'][:10]}",
                "下级证书有效期超出上级证书有效期范围",
                1,
            )
        )
    else:
        items.append(
            _item(
                "有效期包含",
                f"{child['not_before_text'][:10]} ~ {child['not_after_text'][:10]}",
                "下级证书有效期在上级有效期内",
                2,
            )
        )

    if child["expired"]:
        items.append(_item("证书有效期", f"剩余 {child['days_left']} 天", "证书已过期", 0))
    elif child["not_yet_valid"]:
        items.append(_item("证书有效期", "尚未生效", "证书尚未生效", 0))
    else:
        items.append(_item("证书有效期", f"剩余 {child['days_left']} 天", "证书处于有效期内", 2))
    return items


def order_certs(ders: list[bytes]) -> list[tuple[bytes, int | None]]:
    """把一组证书按 根→终端 排序，返回 [(der, parent_index)]。"""
    parsed = [parse_cert(d) for d in ders]
    n = len(parsed)
    parent: list[int | None] = [None] * n
    for i, child in enumerate(parsed):
        for j, cand in enumerate(parsed):
            if i == j:
                continue
            if _issuer_matches(child, cand):
                if child["self_signed"] and i == j:
                    continue
                # 优先选择 CA 证书，其次自签证书
                if parent[i] is None or (cand["is_ca"] and not parsed[parent[i]]["is_ca"]):
                    parent[i] = j
    # 自签证书不应被自己指向
    for i, cert in enumerate(parsed):
        if cert["self_signed"]:
            parent[i] = None
    # 检测环
    for i in range(n):
        seen = set()
        cur = i
        while parent[cur] is not None:
            if cur in seen:
                parent[cur] = None
                break
            seen.add(cur)
            cur = parent[cur]
    # 计算深度：根为 0
    depth: list[int] = [0] * n
    for _ in range(n):
        changed = False
        for i in range(n):
            p = parent[i]
            if p is not None and depth[i] < depth[p] + 1:
                depth[i] = depth[p] + 1
                changed = True
        if not changed:
            break
    order = sorted(range(n), key=lambda i: (depth[i], i))
    return [(ders[i], parent[i]) for i in order]


def check_chain(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    """nodes: [{nodeId, parentId, name, cert(原始文本), certFormat}]"""
    if not nodes:
        raise ToolError("请先添加证书节点")
    parsed: dict[str, dict[str, Any] | None] = {}
    errors: dict[str, str] = {}
    for node in nodes:
        nid = str(node.get("nodeId") or node.get("id") or "")
        text = (node.get("cert") or "").strip()
        if not text:
            parsed[nid] = None
            errors[nid] = "未提供证书内容"
            continue
        try:
            certs = load_certs(text, node.get("certFormat"), "证书")
            parsed[nid] = certs[0]
        except ToolError as exc:
            parsed[nid] = None
            errors[nid] = str(exc)

    parent_of: dict[str, str | None] = {}
    children: dict[str | None, list[str]] = {}
    ids = [str(n.get("nodeId") or n.get("id") or "") for n in nodes]
    for node, nid in zip(nodes, ids):
        pid = node.get("parentId")
        pid = str(pid) if pid not in (None, "") else None
        if pid is not None and pid not in ids:
            pid = None
        parent_of[nid] = pid
        children.setdefault(pid, []).append(nid)

    depth: dict[str, int] = {}

    def _walk(nid: str, level: int) -> None:
        depth[nid] = level
        for c in children.get(nid, []):
            if depth.get(c, -1) < level + 1:
                _walk(c, level + 1)

    for root in children.get(None, []):
        _walk(root, 0)

    def _count_ca_desc(nid: str) -> int:
        total = 0
        for c in children.get(nid, []) or []:
            cert_c = parsed.get(c)
            if cert_c and cert_c.get("is_ca"):
                total += 1
            total += _count_ca_desc(c)
        return total

    ca_below = {nid: _count_ca_desc(nid) for nid in ids}

    node_results: list[dict[str, Any]] = []
    passed = True
    problems: list[str] = []
    for node, nid in zip(nodes, ids):
        name = node.get("name") or nid
        cert = parsed.get(nid)
        if cert is None:
            items = [_item("证书解析", "失败", errors.get(nid, "证书解析失败"), 0)]
            node_results.append(
                {
                    "nodeId": nid,
                    "parentId": node.get("parentId"),
                    "name": name,
                    "uploaded": bool((node.get("cert") or "").strip()),
                    "formatParsed": False,
                    "chainPassed": False,
                    "chainResults": items,
                    "chainSummary": "证书解析失败",
                    "chainStatus": "error",
                    "status": "error",
                    "formatResults": items,
                }
            )
            passed = False
            problems.append(f"{name} 解析失败")
            continue
        cert["_depth"] = depth.get(nid, 0)
        pid = parent_of.get(nid)
        parent_cert = parsed.get(pid) if pid else None
        items = chain_node_items(cert, parent_cert, parent_cert is None, ca_below.get(pid or "", 0))
        status, summary = summarize(items)
        if status == "error":
            passed = False
            problems.append(f"{name}：" + "、".join(i["name"] for i in items if i["valid"] == 0))
        node_results.append(
            {
                "nodeId": nid,
                "parentId": pid,
                "name": name,
                "uploaded": True,
                "formatParsed": True,
                "chainPassed": status != "error",
                "chainResults": items,
                "chainSummary": summary,
                "chainStatus": status,
                "status": status,
                "formatResults": format_items(cert),
                "subject": cert["subject"]["text"],
                "issuer": cert["issuer"]["text"],
            }
        )

    total = len([c for c in parsed.values() if c])
    if passed:
        message = f"证书链验证通过：共 {total} 张证书，签名关系与根证书自签校验均通过"
    else:
        message = "证书链验证未通过：" + "；".join(problems[:4])
    return {
        "passed": passed,
        "message": message,
        "nodeResults": node_results,
        "total": total,
        "nodes": [
            {
                "nodeId": nid,
                "parentId": parent_of.get(nid),
                "name": node.get("name") or nid,
                "subject": (parsed[nid] or {}).get("subject", {}).get("text", ""),
                "issuer": (parsed[nid] or {}).get("issuer", {}).get("text", ""),
                "selfSigned": bool((parsed[nid] or {}).get("self_signed")),
            }
            for node, nid in zip(nodes, ids)
        ],
    }


def chain_from_certs(text: str, fmt: str | None = None) -> dict[str, Any]:
    """从多张证书文本自动构建链并验证。"""
    kind, blobs = split_boxes(text, fmt)
    ders: list[bytes] = []
    for blob in blobs:
        if blob[:1] == b"\x30":
            ders.extend(split_der_stream(blob))
        else:
            raise ToolError("证书数据不是有效的 DER 编码")
    if len(ders) < 1:
        raise ToolError("未提供证书")
    ordered = order_certs(ders)
    # order_certs 返回的顺序是按深度排序后的列表，需把 parent 下标映射到新位置
    pos: dict[int, int] = {}
    result_nodes = []
    for new_idx, (der, parent_idx) in enumerate(ordered):
        old_idx = next((k for k, d in enumerate(ders) if d == der), None)
        if old_idx is not None:
            pos[old_idx] = new_idx
        result_nodes.append((new_idx, der, parent_idx))
    nodes = []
    for idx, der, parent_idx in result_nodes:
        parent_id = None
        if parent_idx is not None:
            parent_id = f"auto-{pos.get(parent_idx, parent_idx)}"
        nodes.append(
            {
                "nodeId": f"auto-{idx}",
                "parentId": parent_id,
                "name": f"证书 {idx + 1}",
                "cert": pem_encode(der),
                "certFormat": "PEM",
            }
        )
    result = check_chain(nodes)
    result["inputFormat"] = kind
    return result


# --------------------------------------------------------------------------- #
# CRL
# --------------------------------------------------------------------------- #
def parse_crl(der: bytes) -> dict[str, Any]:
    try:
        cl = acrl.CertificateList.load(der)
        tbs = cl["tbs_cert_list"]
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"CRL 解析失败：{exc.__class__.__name__}")
    info: dict[str, Any] = {"der": der, "pem": pem_encode(der, "X509 CRL"), "length": len(der)}
    info["issuer"] = name_to_dict(cl.issuer)
    info["issuer_der"] = info["issuer"]["der"]
    info["this_update"] = tbs["this_update"].native
    info["next_update"] = tbs["next_update"].native if tbs["next_update"] is not None else None
    info["this_update_text"] = datetime_to_text(info["this_update"])
    info["next_update_text"] = datetime_to_text(info["next_update"])
    sig_oid = cl["signature_algorithm"]["algorithm"].dotted
    info["sig_oid"] = sig_oid
    info["sig_alg"] = sig_alg_name(sig_oid)
    info["tbs_sig_oid"] = tbs["signature"]["algorithm"].dotted
    info["signature"] = cl["signature"].native
    info["tbs"] = tbs.dump()
    try:
        version = tbs["version"].native
    except Exception:
        version = "v1"
    info["version"] = f"v{version + 1}" if isinstance(version, int) else str(version)

    entries: list[dict[str, Any]] = []
    raw_entries = tbs["revoked_certificates"]
    if raw_entries is not None:
        for entry in raw_entries:
            serial = int(entry["user_certificate"].native)
            hexserial = format(serial, "X")
            if len(hexserial) % 2:
                hexserial = "0" + hexserial
            reason = ""
            try:
                ext_list = entry["crl_entry_extensions"]
                if ext_list is not None:
                    for e in ext_list:
                        if e["extn_id"].native == "crl_reason":
                            reason = e["extn_value"].parsed.native
            except Exception:
                reason = ""
            entries.append(
                {
                    "serial": hexserial,
                    "serialDec": serial,
                    "revocationDate": datetime_to_text(entry["revocation_date"].native),
                    "reason": REASON_TEXT.get(reason, reason or "未指定"),
                }
            )
    info["entries"] = entries
    info["entry_count"] = len(entries)

    exts: list[dict[str, Any]] = []
    try:
        raw_exts = tbs["crl_extensions"]
        if raw_exts is not None:
            exts = [_ext_summary(e) for e in raw_exts]
    except Exception:
        exts = []
    info["extensions"] = exts
    info["crl_number"] = None
    info["aki"] = ""
    for e in exts:
        if e["oid"] == "2.5.29.20":
            info["crl_number"] = e["native"]
        if e["oid"] == "2.5.29.35" and isinstance(e["native"], dict):
            kid = e["native"].get("key_identifier")
            if isinstance(kid, (bytes, bytearray)):
                info["aki"] = bytes(kid).hex().upper()
    info["fingerprintSha256"] = _fmt_fp(_digest_hex(der, "SHA256"))
    info["fingerprintSm3"] = _fmt_fp(_digest_hex(der, "SM3"))
    return info


def build_crl(
    ca_family: str = "SM2",
    entries: list[dict[str, Any]] | None = None,
    days: int = 7,
    crl_number: int | None = None,
) -> bytes:
    """用本地 CA 生成 CRL（供测试与本地演示使用）。

    entries: [{"serial": int|hexstr, "reason": "key_compromise", "date": datetime}]
    """
    return crl_with_ca(load_local_ca(ca_family), entries, days, crl_number)


def crl_with_ca(
    ca: dict[str, Any],
    entries: list[dict[str, Any]] | None = None,
    days: int = 7,
    crl_number: int | None = None,
) -> bytes:
    """用给定的 CA（key + cert_der）签发 CRL。"""
    ca_cert = parse_cert(ca["cert_der"])
    family = ca.get("family") or ca["key"]["algorithm"]
    if family == "SM2":
        sig_oid, hash_name = "1.2.156.10197.1.501", "SM3"
    else:
        sig_oid, hash_name = "1.2.840.113549.1.1.11", "SHA256"
    now = dt.datetime.now(UTC).replace(microsecond=0)
    revoked = []
    for item in entries or []:
        serial = item.get("serial")
        if isinstance(serial, str):
            serial = int(serial, 16)
        revoked.append(
            {
                "user_certificate": int(serial),
                "revocation_date": _time_obj(item.get("date") or now),
                "crl_entry_extensions": [
                    {"extn_id": "crl_reason", "critical": False, "extn_value": item.get("reason") or "key_compromise"}
                ],
            }
        )
    exts = [
        {"extn_id": "2.5.29.35", "critical": False, "extn_value": {"key_identifier": bytes.fromhex(ca_cert["ski"])}},
        {"extn_id": "2.5.29.20", "critical": False, "extn_value": crl_number if crl_number is not None else 1},
    ]
    tbs = acrl.TbsCertList(
        {
            "version": 1,
            "signature": aalgos.SignedDigestAlgorithm({"algorithm": sig_oid}),
            "issuer": ax509.Certificate.load(ca["cert_der"]).subject,
            "this_update": _time_obj(now),
            "next_update": _time_obj(now + dt.timedelta(days=max(1, days))),
            "revoked_certificates": revoked or None,
            "crl_extensions": acrl.TBSCertListExtensions(exts),
        }
    )
    signature = _sign(tbs.dump(), ca["key"], sig_oid, hash_name)
    result = acrl.CertificateList(
        {
            "tbs_cert_list": tbs,
            "signature_algorithm": aalgos.SignedDigestAlgorithm({"algorithm": sig_oid}),
            "signature": acore.OctetBitString(signature),
        }
    )
    return result.dump()


def crl_info_view(crl: dict[str, Any]) -> dict[str, Any]:
    return {
        "issuer": crl["issuer"]["text"],
        "version": crl["version"],
        "thisUpdate": crl["this_update_text"],
        "nextUpdate": crl["next_update_text"],
        "sigAlg": crl["sig_alg"],
        "entryCount": crl["entry_count"],
        "crlNumber": crl["crl_number"],
        "aki": crl["aki"],
        "fingerprintSm3": crl["fingerprintSm3"],
        "fingerprintSha256": crl["fingerprintSha256"],
        "extensions": [{"name": e["name"], "critical": e["critical"], "brief": e["brief"]} for e in crl["extensions"]],
        "entries": crl["entries"],
    }


def check_crl_validity(
    crl_text: str,
    crl_fmt: str | None,
    base_cert_text: str | None = None,
    base_cert_fmt: str | None = None,
) -> dict[str, Any]:
    kind, blobs = split_boxes(crl_text, crl_fmt)
    crl = None
    last_err = None
    for blob in blobs:
        try:
            crl = parse_crl(blob)
            break
        except ToolError as exc:
            last_err = exc
    if crl is None:
        raise ToolError(str(last_err or "CRL 解析失败"))

    items: list[dict[str, Any]] = []
    now = dt.datetime.now(UTC)
    items.append(_item("CRL 格式", f"{kind} · {crl['length']} 字节 · {crl['version']}", "CRL 结构解析成功", 2))
    items.append(_item("颁发者", crl["issuer"]["text"], "CRL 颁发者可分辨名称解析成功", 2))

    if crl["this_update"] > now + dt.timedelta(minutes=10):
        items.append(_item("本次更新时间", crl["this_update_text"], "本次更新时间晚于当前时间，请检查签发方时钟", 1))
    else:
        items.append(_item("本次更新时间", crl["this_update_text"], "本次更新时间正常", 2))

    if crl["next_update"] is None:
        items.append(_item("下次更新时间", "（未声明）", "CRL 未声明 nextUpdate，无法判断新鲜度", 1))
    elif crl["next_update"] < now:
        items.append(_item("下次更新时间", crl["next_update_text"], "CRL 已过期，请获取最新 CRL", 0))
    else:
        items.append(
            _item(
                "下次更新时间",
                crl["next_update_text"],
                f"CRL 仍在有效期内（剩余 {max(0, (crl['next_update'] - now).days)} 天）",
                2,
            )
        )

    items.append(_item("吊销条目", f"{crl['entry_count']} 条", "吊销列表统计完成", 2))
    if crl["crl_number"] is not None:
        items.append(_item("CRL 编号", str(crl["crl_number"]), "已声明 CRL 序列号", 2))
    else:
        items.append(_item("CRL 编号", "（未声明）", "建议声明 CRL Number 扩展以便比对版本", 1))

    base: dict[str, Any] | None = None
    if base_cert_text and base_cert_text.strip():
        base = load_certs(base_cert_text, base_cert_fmt, "上级证书")[0]
        if crl.get("issuer_der") and base.get("subject_der") and crl["issuer_der"] == base["subject_der"] or (
            not (crl.get("issuer_der") and base.get("subject_der")) and crl["issuer"]["text"] == base["subject"]["text"]
        ):
            items.append(_item("颁发者匹配", crl["issuer"]["text"], "CRL 颁发者与上级证书主题一致", 2))
            ok, msg = verify_signature(crl["tbs"], crl["signature"], crl["sig_oid"], base["spki"], base["pub_hex"])
            items.append(_item("CRL 签名验证", "通过" if ok else "未通过", msg, 2 if ok else 0))
        else:
            items.append(
                _item(
                    "颁发者匹配",
                    f"{crl['issuer']['text']} ≠ {base['subject']['text']}",
                    "CRL 颁发者与所提供证书主题不一致",
                    0,
                )
            )
            items.append(_item("CRL 签名验证", "跳过", "颁发者不匹配，签名验证无意义", 0))
    else:
        items.append(_item("CRL 签名验证", "未验证", "未提供上级证书，无法验证 CRL 签名", 1))

    status, summary = summarize(items)
    valid = status != "error"
    return {
        "valid": valid,
        "status": status,
        "msg": "CRL 有效性验证通过：" + summary if valid else "CRL 有效性验证未通过：" + summary,
        "items": items,
        "crl": crl_info_view(crl),
        "baseCert": cert_info_view(base) if base else None,
        "baseInput": "未提供上级证书" if base is None else "上级证书已解析",
    }


def _norm_serial(text: str) -> str:
    s = re.sub(r"[\s:]+", "", (text or "")).upper()
    s = re.sub(r"^0X", "", s)
    return s.lstrip("0") or "0"


def check_cert_status_crl(cert_text: str, cert_fmt: str | None, crl_text: str, crl_fmt: str | None) -> dict[str, Any]:
    cert = load_certs(cert_text, cert_fmt, "证书")[0]
    kind, blobs = split_boxes(crl_text, crl_fmt)
    crl = None
    last_err = None
    for blob in blobs:
        try:
            crl = parse_crl(blob)
            break
        except ToolError as exc:
            last_err = exc
    if crl is None:
        raise ToolError(str(last_err or "CRL 解析失败"))

    items: list[dict[str, Any]] = []
    items.append(_item("证书解析", cert["subject"]["text"], f"序列号 {cert['serial']}", 2))
    items.append(_item("CRL 解析", crl["issuer"]["text"], f"{crl['entry_count']} 条吊销记录", 2))

    issuer_match = (
        crl["issuer_der"] == cert["issuer_der"]
        if crl.get("issuer_der") and cert.get("issuer_der")
        else crl["issuer"]["text"] == cert["issuer"]["text"]
    )
    if issuer_match:
        items.append(_item("颁发者匹配", crl["issuer"]["text"], "CRL 颁发者与证书颁发者一致，该 CRL 适用于本证书", 2))
    else:
        items.append(
            _item(
                "颁发者匹配",
                f"{crl['issuer']['text']} ≠ {cert['issuer']['text']}",
                "CRL 颁发者与证书颁发者不一致，CRL 不适用于本证书",
                0,
            )
        )

    if cert["self_signed"]:
        ok, msg = verify_signature(crl["tbs"], crl["signature"], crl["sig_oid"], cert["spki"], cert["pub_hex"])
        items.append(_item("CRL 签名", "通过" if ok else "未通过", msg + "（自签证书自身公钥）", 2 if ok else 0))
    else:
        items.append(_item("CRL 签名", "未验证", "证书非自签，需上级 CA 公钥才能验证 CRL 签名", 1))

    if crl["next_update"] is not None and crl["next_update"] < dt.datetime.now(UTC):
        items.append(_item("CRL 新鲜度", crl["next_update_text"], "CRL 已过期，结论仅供参考", 1))
    else:
        items.append(_item("CRL 新鲜度", crl["next_update_text"], "CRL 仍在有效期内", 2))

    serial = _norm_serial(cert["serial"])
    hit = next((e for e in crl["entries"] if _norm_serial(e["serial"]) == serial), None)
    if hit:
        items.append(_item("吊销状态", "已吊销", f"序列号 {cert['serial']} 于 {hit['revocationDate']} 吊销，原因：{hit['reason']}", 0))
        revoked = True
        revoke_msg = f"证书已吊销：序列号 {cert['serial']}，吊销时间 {hit['revocationDate']}，原因 {hit['reason']}"
    else:
        items.append(_item("吊销状态", "未吊销", f"CRL 中未找到序列号 {cert['serial']}", 2))
        revoked = False
        revoke_msg = f"证书未被吊销：CRL 中不存在序列号 {cert['serial']}"

    status, summary = summarize(items)
    verify_ok = issuer_match
    verify_msg = "证书与 CRL 颁发者匹配，CRL 可用于该证书" if issuer_match else "CRL 颁发者与证书颁发者不一致，验证未通过"
    return {
        "revoked": revoked,
        "crlVerifyResult": verify_ok,
        "crlVerifyMsg": verify_msg,
        "crlRevokeMsg": revoke_msg,
        "status": status,
        "items": items,
        "crlInfo": crl_info_view(crl),
        "certInfo": cert_info_view(cert),
    }


# --------------------------------------------------------------------------- #
# OCSP（离线解析 / 验证，绝不联网）
# --------------------------------------------------------------------------- #
OFFLINE_OCSP_HINT = "离线版不支持联网查询 OCSP，请粘贴 OCSP 响应（DER / Base64 / PEM）后再验证"


def check_cert_status_ocsp(
    cert_text: str | None,
    cert_fmt: str | None,
    response_text: str | None,
    response_fmt: str | None,
    address: str | None = None,
) -> dict[str, Any]:
    if not (response_text or "").strip():
        if (address or "").strip():
            raise ToolError(OFFLINE_OCSP_HINT)
        raise ToolError(OFFLINE_OCSP_HINT)

    kind, blobs = split_boxes(response_text, response_fmt)
    der = blobs[0]
    if "-----BEGIN" in (response_text or ""):
        kind = "PEM"
    try:
        resp = cocsp.load_der_ocsp_response(der)
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"OCSP 响应解析失败：{exc.__class__.__name__}（离线版仅支持 DER/Base64 编码的 OCSP 响应）")

    if resp.response_status != cocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ToolError(f"OCSP 响应状态为 {resp.response_status.name}，未能提供证书状态")

    items: list[dict[str, Any]] = []
    items.append(_item("响应状态", "SUCCESSFUL", "OCSP 响应结构解析成功", 2))

    cert = None
    if (cert_text or "").strip():
        cert = load_certs(cert_text, cert_fmt, "证书")[0]
        try:
            resp_serial = _norm_serial(format(resp.serial_number, "X"))
        except Exception:
            resp_serial = ""
        if resp_serial and resp_serial == _norm_serial(cert["serial"]):
            items.append(_item("序列号匹配", format(resp.serial_number, "X"), "响应中的序列号与证书一致", 2))
        else:
            items.append(
                _item(
                    "序列号匹配",
                    f"响应 {resp_serial or '未知'} / 证书 {cert['serial']}",
                    "OCSP 响应序列号与所提供的证书不一致",
                    0,
                )
            )

    # 响应签名验证：候选签名者 = 响应内嵌证书 + 所提供的证书
    candidates: list[Any] = list(resp.certificates or [])
    if cert is not None:
        try:
            candidates.append(cx509.load_der_x509_certificate(cert["der"]))
        except Exception:
            pass
    responder = None
    sig_ok = False
    sig_msg = "无法验证响应签名：响应中未包含可用于验证的签名者证书"
    hash_alg = resp.signature_hash_algorithm
    tbs_bytes = getattr(resp, "tbs_response_bytes", None) or getattr(resp, "tbs_response_data", None) or b""
    for candidate in candidates:
        for pad in (padding.PKCS1v15(), padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=hash_alg.digest_size)):
            try:
                candidate.public_key().verify(resp.signature, tbs_bytes, pad, hash_alg)
                responder = candidate
                sig_ok = True
                break
            except InvalidSignature:
                continue
            except Exception:
                break
        if sig_ok:
            break
        try:
            candidate.public_key().verify(resp.signature, tbs_bytes, ec.ECDSA(hash_alg))
            responder = candidate
            sig_ok = True
            break
        except Exception:
            continue
    if sig_ok:
        sig_msg = "OCSP 响应签名验证通过（签名者：" + responder.subject.rfc4514_string() + "）"
    elif candidates:
        sig_msg = "OCSP 响应签名验证未通过：响应签名与签名者公钥不匹配（或使用了 SM2 等本地不支持验证的算法）"
    items.append(_item("响应签名", "通过" if sig_ok else "未通过", sig_msg, 2 if sig_ok else 0))

    now = dt.datetime.now(UTC)
    this_update = _aware(getattr(resp, "this_update_utc", None) or resp.this_update)
    next_update = _aware(getattr(resp, "next_update_utc", None) or resp.next_update)
    if this_update and this_update > now + dt.timedelta(minutes=10):
        items.append(_item("本次更新时间", datetime_to_text(this_update), "响应时间晚于当前时间", 1))
    else:
        items.append(_item("本次更新时间", datetime_to_text(this_update), "响应时间正常", 2))
    if next_update is None:
        items.append(_item("下次更新时间", "（未声明）", "响应未声明 nextUpdate", 1))
    elif next_update < now:
        items.append(_item("下次更新时间", datetime_to_text(next_update), "响应已过期，请重新获取", 0))
    else:
        items.append(
            _item("下次更新时间", datetime_to_text(next_update), f"响应剩余有效期 {max(0, (next_update - now).days)} 天", 2)
        )

    status = resp.certificate_status
    revoked = status == cocsp.OCSPCertStatus.REVOKED
    if status == cocsp.OCSPCertStatus.GOOD:
        state_text, state_msg, valid = "GOOD", "证书状态正常（good）", 2
    elif revoked:
        rev_time = datetime_to_text(_aware(resp.revocation_time_utc)) if resp.revocation_time_utc else "未知"
        reason = resp.revocation_reason.name if resp.revocation_reason else "未指定"
        state_text = "REVOKED"
        state_msg = f"证书已吊销，吊销时间 {rev_time}，原因 {reason}"
        valid = 0
    else:
        state_text, state_msg, valid = "UNKNOWN", "OCSP 响应方不认识该证书（unknown）", 1
    items.append(_item("证书状态", state_text, state_msg, valid))

    item_status, summary = summarize(items)
    return {
        "ocspVerifyResult": bool(sig_ok and item_status != "error"),
        "ocspVerifyMsg": sig_msg if not sig_ok else ("证书状态：" + state_text),
        "ocspStatus": state_text,
        "ocspStatusMsg": state_msg,
        "revoked": revoked,
        "status": item_status,
        "summary": summary,
        "items": items,
        "ocspInfo": {
            "responseStatus": resp.response_status.name,
            "certificateStatus": state_text,
            "serial": format(resp.serial_number, "X") if resp.serial_number is not None else "",
            "thisUpdate": datetime_to_text(this_update),
            "nextUpdate": datetime_to_text(next_update),
            "producedAt": datetime_to_text(_aware(getattr(resp, "produced_at_utc", None) or resp.produced_at)),
            "responder": responder.subject.rfc4514_string() if responder is not None else "",
            "signatureAlg": sig_alg_name(resp.signature_algorithm_oid.dotted_string),
            "cachedThisUpdate": datetime_to_text(this_update),
            "extensionOids": [e.oid.dotted_string for e in (resp.extensions or [])],
            "inputFormat": kind,
        },
    }


def build_ocsp_response(
    cert_pem: str, ca_family: str = "RSA", status: str = "GOOD", days: int = 1, include_responder: bool = True
) -> bytes:
    """用本地 CA 生成 OCSP 响应（仅 RSA，供离线演示与测试使用）。"""
    ca = load_local_ca(ca_family)
    if ca["family"] != "RSA":
        raise ToolError("本地生成 OCSP 响应仅支持 RSA CA（SM2 响应需外部 OCSP 服务签发）")
    leaf = cx509.load_pem_x509_certificate(cert_pem.encode())
    issuer = cx509.load_pem_x509_certificate(ca["cert_pem"].encode())
    key = serialization.load_pem_private_key(ca["key"]["key_pem"].encode(), password=None)
    now = dt.datetime.now(UTC).replace(microsecond=0)
    revoked = str(status).upper() == "REVOKED"
    builder = cocsp.OCSPResponseBuilder().add_response(
        cert=leaf,
        issuer=issuer,
        algorithm=hashes.SHA1(),
        cert_status=cocsp.OCSPCertStatus.REVOKED if revoked else cocsp.OCSPCertStatus.GOOD,
        this_update=now,
        next_update=now + dt.timedelta(days=max(1, days)),
        revocation_time=(now - dt.timedelta(hours=2)) if revoked else None,
        revocation_reason=cx509.ReasonFlags.key_compromise if revoked else None,
    )
    builder = builder.responder_id(cocsp.OCSPResponderEncoding.NAME, issuer)
    if include_responder:
        builder = builder.certificates([issuer])
    resp = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return resp.public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- #
# 密钥 / CSR / 本地 CA / 签发
# --------------------------------------------------------------------------- #
def _sm2_pub_from_priv(priv_hex: str) -> str:
    helper = gmsm2.CryptSM2(private_key=priv_hex, public_key="")
    pub = helper._kg(int(priv_hex, 16), gmsm2.default_ecc_table["g"])  # noqa: SLF001
    if not pub or len(pub) != 128:
        raise ToolError("SM2 公钥推导失败")
    return pub


def gen_sm2_keypair() -> dict[str, str]:
    while True:
        priv = secrets.token_hex(32)
        n = int(gmsm2.default_ecc_table["n"], 16)
        if 1 <= int(priv, 16) < n - 1:
            break
    pub = _sm2_pub_from_priv(priv)
    return {"private": priv, "public": pub}


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_seq(*items: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(items))


def _der_int(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _der_tlv(0x02, value.to_bytes(length, "big", signed=True))


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append((part & 0x7F) | 0x80)
            part >>= 7
        body.extend(reversed(chunk))
    return _der_tlv(0x06, bytes(body))


def _der_octet(data: bytes) -> bytes:
    return _der_tlv(0x04, data)


def _der_bits(data: bytes, unused: int = 0) -> bytes:
    return _der_tlv(0x03, bytes([unused]) + data)


def _sm2_private_key_info(priv_hex: str, pub_hex: str) -> bytes:
    ec_priv = _der_seq(
        _der_int(1),
        _der_octet(bytes.fromhex(priv_hex)),
        _der_tlv(0xA0, _der_oid(OID_SM2_CURVE)),
        _der_tlv(0xA1, _der_bits(bytes.fromhex(pub_hex))),
    )
    alg = _der_seq(_der_oid(OID_EC_PUBKEY), _der_oid(OID_SM2_CURVE))
    return _der_seq(_der_int(0), alg, _der_octet(ec_priv))


def _sm2_public_key_info(pub_hex: str) -> bytes:
    # BIT STRING 内容必须为 04||X||Y（65 字节）。
    if not pub_hex.upper().startswith("04"):
        pub_hex = "04" + pub_hex
    # RFC 5480 形式：id-ecPublicKey + SM2 曲线 OID 参数（OpenSSL/BouncyCastle
    # 通用兼容写法；公钥点必须带 04 前缀，否则无法解码）。
    alg = _der_seq(_der_oid(OID_EC_PUBKEY), _der_oid(OID_SM2_CURVE))
    return _der_seq(alg, _der_bits(bytes.fromhex(pub_hex)))


def keypair(algorithm: str, key_length: int = 2048) -> dict[str, Any]:
    algorithm = (algorithm or "SM2").upper()
    if algorithm == "SM2":
        kp = gen_sm2_keypair()
        spki = _sm2_public_key_info(kp["public"])
        pkcs8 = _sm2_private_key_info(kp["private"], kp["public"])
        return {
            "algorithm": "SM2",
            "bits": 256,
            "spki": spki,
            "spki_pem": pem_encode(spki, "PUBLIC KEY"),
            "private_hex": kp["private"],
            "private_pem": pem_encode(pkcs8, "PRIVATE KEY"),
            "public_hex": kp["public"],
            "key_obj": None,
        }
    if algorithm == "RSA":
        size = int(key_length or 2048)
        if size not in (1024, 2048, 3072, 4096):
            raise ToolError("RSA 密钥长度仅支持 1024 / 2048 / 3072 / 4096 位")
        key = rsa.generate_private_key(public_exponent=65537, key_size=size)
        spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        pkcs8 = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return {
            "algorithm": "RSA",
            "bits": size,
            "spki": spki,
            "spki_pem": pem_encode(spki, "PUBLIC KEY"),
            "private_hex": "",
            "private_pem": pem_encode(pkcs8, "PRIVATE KEY"),
            "public_hex": "",
            "key_obj": key,
        }
    raise ToolError("仅支持 SM2 / RSA 算法")


def make_name(cn: str, c: str = "", st: str = "", loc: str = "", o: str = "", ou: str = "", email: str = "") -> ax509.Name:
    fields: dict[str, str] = {}
    cn = (cn or "").strip()
    c = (c or "").strip().upper()
    if not cn:
        raise ToolError("请输入主题名称/CN 项")
    if len(cn) > 64:
        raise ToolError("主题名称/CN 项最多 64 个字符")
    fields["common_name"] = cn
    if c:
        if len(c) != 2 or not c.isalpha():
            raise ToolError("国家/C 必须为 2 位字母代码（如 CN）")
        fields["country_name"] = c
    for key, val in (
        ("state_or_province_name", st),
        ("locality_name", loc),
        ("organization_name", o),
        ("organizational_unit_name", ou),
    ):
        val = (val or "").strip()
        if val:
            if len(val) > 64:
                raise ToolError(f"{key} 最多 64 个字符")
            fields[key] = val
    email = (email or "").strip()
    if email:
        if "@" not in email:
            raise ToolError("邮箱格式不正确")
        fields["email_address"] = email
    return ax509.Name.build(fields)


def _sig_alg_obj(algorithm: str, sign_alg: str) -> tuple[str, str]:
    """返回 (签名 OID, 摘要名)。"""
    if (algorithm or "SM2").upper() == "SM2":
        return "1.2.156.10197.1.501", "SM3"
    table = {
        "SHA256WITHRSA": ("1.2.840.113549.1.1.11", "SHA256"),
        "SHA384WITHRSA": ("1.2.840.113549.1.1.12", "SHA384"),
        "SHA512WITHRSA": ("1.2.840.113549.1.1.13", "SHA512"),
        "SHA1WITHRSA": ("1.2.840.113549.1.1.5", "SHA1"),
        "MD5WITHRSA": ("1.2.840.113549.1.1.4", "MD5"),
        "SM3WITHRSA": ("1.2.156.10197.1.504", "SM3"),
    }
    key = (sign_alg or "SHA256withRSA").upper().replace("-", "").replace("_", "")
    if key not in table:
        raise ToolError("不支持的签名算法，请选择 SHA256withRSA / SHA384withRSA / SHA512withRSA / SM3withRSA")
    return table[key]


def _sign(tbs: bytes, key: dict[str, Any], sig_oid: str, hash_name: str) -> bytes:
    if key["algorithm"] == "SM2":
        return sm2_sign(key["private_hex"], key["public_hex"], tbs)
    key_obj = key["key_obj"]
    if sig_oid == "1.2.156.10197.1.504":
        if not hasattr(hashes, "SM3"):
            raise ToolError("当前 OpenSSL 不支持 SM3，无法使用 SM3withRSA")
        return key_obj.sign(tbs, padding.PKCS1v15(), hashes.SM3())
    if sig_oid == OID_RSASSA_PSS:
        return key_obj.sign(tbs, padding.PSS(mgf=padding.MGF1(_hash_obj(hash_name)), salt_length=32), _hash_obj(hash_name))
    return key_obj.sign(tbs, padding.PKCS1v15(), _hash_obj(hash_name))


def _time_obj(value: dt.datetime) -> ax509.Time:
    value = value.astimezone(UTC).replace(microsecond=0)
    if 1950 <= value.year < 2050:
        return ax509.Time({"utc_time": value})
    return ax509.Time({"generalized_time": value})


def _serial() -> int:
    while True:
        value = secrets.randbits(127)
        if value > 0:
            return value


def build_certificate(
    subject: ax509.Name,
    subject_spki: bytes,
    issuer: ax509.Name,
    issuer_key: dict[str, Any],
    not_before: dt.datetime,
    not_after: dt.datetime,
    extensions: list[ax509.Extension],
    sig_oid: str,
    hash_name: str,
    serial: int | None = None,
) -> bytes:
    sig_alg = aalgos.SignedDigestAlgorithm({"algorithm": sig_oid})
    pki = akeys.PublicKeyInfo.load(subject_spki)
    tbs = ax509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": serial if serial is not None else _serial(),
            "signature": sig_alg,
            "issuer": issuer,
            "validity": {"not_before": _time_obj(not_before), "not_after": _time_obj(not_after)},
            "subject": subject,
            "subject_public_key_info": pki,
            "extensions": ax509.Extensions(extensions),
        }
    )
    signature = _sign(tbs.dump(), issuer_key, sig_oid, hash_name)
    cert = ax509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": sig_alg,
            "signature_value": acore.OctetBitString(signature),
        }
    )
    return cert.dump()


def _key_identifier(spki: bytes, pub_hex: str) -> bytes:
    if pub_hex:
        point = bytes.fromhex(pub_hex)
        return gmsm3.sm3_hash_bytes(point) if hasattr(gmsm3, "sm3_hash_bytes") else bytes.fromhex(gmsm3.sm3_hash(list(point)))[:20]
    return hashlib.sha1(spki).digest()


def gen_csr(params: dict[str, Any]) -> dict[str, Any]:
    algorithm = (params.get("algorithm") or "SM2").upper()
    key = keypair(algorithm, params.get("keyLength") or 2048)
    subject = make_name(
        params.get("cnitem"),
        params.get("citem"),
        params.get("sitem"),
        params.get("litem"),
        params.get("oitem"),
        params.get("ouitem"),
        params.get("emailAddress"),
    )
    sig_oid, hash_name = _sig_alg_obj(algorithm, params.get("signAlg") or "SHA256withRSA")
    sig_alg = aalgos.SignedDigestAlgorithm({"algorithm": sig_oid})
    info = acsr.CertificationRequestInfo(
        {
            "version": 0,
            "subject": subject,
            "subject_pk_info": akeys.PublicKeyInfo.load(key["spki"]),
            "attributes": [],
        }
    )
    signature = _sign(info.dump(), key, sig_oid, hash_name)
    req = acsr.CertificationRequest(
        {
            "certification_request_info": info,
            "signature_algorithm": sig_alg,
            "signature": acore.OctetBitString(signature),
        }
    )
    der = req.dump()
    csr = acsr.CertificationRequest.load(der)
    return {
        "csr": pem_encode(der, "CERTIFICATE REQUEST"),
        "csrDer": base64.b64encode(der).decode(),
        "privateKey": key["private_pem"],
        "publicKey": key["spki_pem"],
        "algorithm": key["algorithm"],
        "keyBits": key["bits"],
        "signAlg": sig_alg_name(sig_oid),
        "subject": subject.native_to_text() if hasattr(subject, "native_to_text") else name_to_dict(subject)["text"],
        "signatureValid": verify_signature(
            csr["certification_request_info"].dump(),
            csr["signature"].native,
            sig_oid,
            key["spki"],
            key["public_hex"],
        )[0],
        "sm3": _fmt_fp(_digest_hex(der, "SM3")),
        "sha256": _fmt_fp(_digest_hex(der, "SHA256")),
    }


def _ext_base_constraints(is_ca: bool, path_len: int | None) -> ax509.Extension:
    return ax509.Extension(
        {
            "extn_id": "2.5.29.19",
            "critical": True,
            "extn_value": {"ca": is_ca, "path_len_constraint": path_len if is_ca else None},
        }
    )


def _ext_key_usage(is_ca: bool) -> ax509.Extension:
    usage = {"digital_signature"}
    if is_ca:
        usage |= {"key_cert_sign", "crl_sign"}
    else:
        usage |= {"key_encipherment", "non_repudiation"}
    return ax509.Extension({"extn_id": "2.5.29.15", "critical": True, "extn_value": usage})


# ------------------------------- 本地 CA ----------------------------------- #
_CA_LOCK = threading.Lock()
_CA_CACHE: dict[str, dict[str, Any]] = {}


def ca_dir(family: str) -> str:
    return os.path.join(DATA_DIR, family.lower())


def load_local_ca(family: str = "SM2") -> dict[str, Any]:
    family = family.upper()
    with _CA_LOCK:
        if family in _CA_CACHE:
            return _CA_CACHE[family]
        path = ca_dir(family)
        cert_path = os.path.join(path, "ca_cert.pem")
        key_path = os.path.join(path, "ca_key.pem")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            with open(cert_path, "r", encoding="utf-8") as fh:
                cert_pem = fh.read()
            with open(key_path, "r", encoding="utf-8") as fh:
                key_pem = fh.read()
            der = _pem_to_der(cert_pem)
            if family == "SM2":
                priv_hex = _sm2_priv_from_pem(key_pem)
                key = {
                    "algorithm": "SM2",
                    "private_hex": priv_hex,
                    "public_hex": _sm2_pub_from_priv(priv_hex),
                    "key_obj": None,
                    "spki_pem": "",
                }
                key["spki"] = _sm2_public_key_info(key["public_hex"])
                key["key_pem"] = key_pem
            else:
                key_obj = serialization.load_pem_private_key(key_pem.encode(), password=None)
                key = {
                    "algorithm": "RSA",
                    "key_obj": key_obj,
                    "private_hex": "",
                    "public_hex": "",
                    "spki": key_obj.public_key().public_bytes(
                        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                    ),
                    "key_pem": key_pem,
                }
            ca = {
                "family": family,
                "cert_der": der,
                "cert_pem": cert_pem,
                "key": key,
                "path": path,
                "created": False,
            }
            _CA_CACHE[family] = ca
            return ca
        ca = _create_local_ca(family)
        _CA_CACHE[family] = ca
        return ca


def _pem_to_der(pem_text: str) -> bytes:
    body = re.sub(r"-----[^-]+-----", "", pem_text)
    body = re.sub(r"\s+", "", body)
    return base64.b64decode(body + "=" * ((-len(body)) % 4))


def _sm2_priv_from_pem(key_pem: str) -> str:
    der = _pem_to_der(key_pem)
    node = parse_der(der)
    # PrivateKeyInfo -> OCTET STRING -> ECPrivateKey -> privateKey
    try:
        octet = node.children[2]
        ec = parse_der(octet.value)
        priv = ec.children[1].value
        return priv.hex()
    except Exception:  # noqa: BLE001
        raise ToolError("SM2 私钥文件解析失败")


def _create_local_ca(family: str) -> dict[str, Any]:
    path = ca_dir(family)
    os.makedirs(path, exist_ok=True)
    key = keypair("SM2" if family == "SM2" else "RSA", 2048)
    cn = "CipherBox 本地根 CA（SM2）" if family == "SM2" else "CipherBox 本地根 CA（RSA）"
    subject = ax509.Name.build(
        {
            "country_name": "CN",
            "organization_name": "CipherBox Offline Toolkit",
            "organizational_unit_name": "Local CA",
            "common_name": cn,
        }
    )
    ski = _key_identifier(key["spki"], key["public_hex"])
    if family == "SM2":
        sig_oid, hash_name = "1.2.156.10197.1.501", "SM3"
    else:
        sig_oid, hash_name = "1.2.840.113549.1.1.11", "SHA256"
    exts = [
        ax509.Extension({"extn_id": "2.5.29.19", "critical": True, "extn_value": {"ca": True, "path_len_constraint": 1}}),
        ax509.Extension(
            {"extn_id": "2.5.29.15", "critical": True, "extn_value": {"key_cert_sign", "crl_sign", "digital_signature"}}
        ),
        ax509.Extension({"extn_id": "2.5.29.14", "critical": False, "extn_value": ski}),
        ax509.Extension(
            {"extn_id": "2.5.29.35", "critical": False, "extn_value": {"key_identifier": ski}}
        ),
    ]
    now = dt.datetime.now(UTC)
    der = build_certificate(
        subject=subject,
        subject_spki=key["spki"],
        issuer=subject,
        issuer_key=key,
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=3650),
        extensions=exts,
        sig_oid=sig_oid,
        hash_name=hash_name,
    )
    cert_pem = pem_encode(der)
    key_pem = key["private_pem"]
    tmp_cert = os.path.join(path, ".ca_cert.pem.tmp")
    tmp_key = os.path.join(path, ".ca_key.pem.tmp")
    with open(tmp_cert, "w", encoding="utf-8") as fh:
        fh.write(cert_pem)
    with open(tmp_key, "w", encoding="utf-8") as fh:
        fh.write(key_pem)
    try:
        os.chmod(tmp_key, 0o600)
    except OSError:
        pass
    os.replace(tmp_cert, os.path.join(path, "ca_cert.pem"))
    os.replace(tmp_key, os.path.join(path, "ca_key.pem"))
    return {
        "family": family,
        "cert_der": der,
        "cert_pem": cert_pem,
        "key": {**key, "key_pem": key_pem},
        "path": path,
        "created": True,
    }


def ca_info(family: str = "SM2") -> dict[str, Any]:
    ca = load_local_ca(family)
    cert = parse_cert(ca["cert_der"])
    return {
        "family": ca["family"],
        "subject": cert["subject"]["text"],
        "issuer": cert["issuer"]["text"],
        "serial": cert["serial"],
        "notBefore": cert["not_before_text"],
        "notAfter": cert["not_after_text"],
        "sigAlg": cert["sig_alg"],
        "keyBits": cert["key_bits"],
        "sm3": cert["sm3"],
        "sha256": cert["sha256"],
        "certPem": ca["cert_pem"],
        "path": ca["path"],
        "selfSigned": cert["self_signed"],
        "signatureValid": verify_signature(
            cert["tbs"], cert["signature"], cert["sig_oid"], cert["spki"], cert["pub_hex"]
        )[0],
    }


CERT_TYPES = {
    "CA": "CA中间证书",
    "SSL": "SSL证书",
    "USER": "用户证书",
}


def _build_leaf_extensions(
    cert_type: str, cn: str, ski: bytes, aki: bytes, san: list[str], email: str
) -> list[ax509.Extension]:
    cert_type = (cert_type or "SSL").upper()
    exts: list[ax509.Extension] = []
    if cert_type == "CA":
        exts.append(_ext_base_constraints(True, 0))
        exts.append(_ext_key_usage(True))
    else:
        exts.append(_ext_base_constraints(False, None))
        usage = {"digital_signature", "key_encipherment"}
        if cert_type == "USER":
            usage |= {"non_repudiation"}
        exts.append(ax509.Extension({"extn_id": "2.5.29.15", "critical": True, "extn_value": usage}))
        eku = ["server_auth", "client_auth"] if cert_type == "SSL" else ["client_auth", "email_protection"]
        exts.append(ax509.Extension({"extn_id": "2.5.29.37", "critical": False, "extn_value": eku}))
        general: list[Any] = []
        if cert_type == "SSL":
            hosts = san or ([cn] if cn else [])
            for host in hosts:
                host = host.strip()
                if not host:
                    continue
                if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
                    general.append(ax509.GeneralName({"ip_address": host}))
                else:
                    general.append(ax509.GeneralName({"dns_name": host}))
        else:
            mails = san or ([email] if email else [])
            for mail in mails:
                if mail and "@" in mail:
                    general.append(ax509.GeneralName({"rfc822_name": mail}))
        if general:
            exts.append(
                ax509.Extension(
                    {"extn_id": "2.5.29.17", "critical": False, "extn_value": ax509.GeneralNames(general)}
                )
            )
    exts.append(ax509.Extension({"extn_id": "2.5.29.14", "critical": False, "extn_value": ski}))
    exts.append(ax509.Extension({"extn_id": "2.5.29.35", "critical": False, "extn_value": {"key_identifier": aki}}))
    if cert_type == "SSL" and cn:
        exts.append(
            ax509.Extension(
                {
                    "extn_id": "1.3.6.1.5.5.7.1.1",
                    "critical": False,
                    "extn_value": ax509.AuthorityInfoAccessSyntax(
                        [
                            ax509.AccessDescription(
                                {
                                    "access_method": "ocsp",
                                    "access_location": ax509.GeneralName(
                                        {"uniform_resource_identifier": "http://ocsp.cipherbox.local/"}
                                    ),
                                }
                            )
                        ]
                    ),
                }
            )
        )
    return exts


def _parse_csr(text: str, fmt: str | None = None) -> dict[str, Any]:
    kind, blobs = split_boxes(text, fmt)
    last = None
    for blob in blobs:
        try:
            req = acsr.CertificationRequest.load(blob)
            return {"req": req, "der": blob, "format": kind}
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise ToolError(f"CSR 解析失败：{last.__class__.__name__ if last else '未知错误'}")


def issue_certificate(params: dict[str, Any]) -> dict[str, Any]:
    cert_type = (params.get("certType") or "SSL").upper()
    if cert_type not in CERT_TYPES:
        raise ToolError("证书类型仅支持 CA / SSL / USER")
    months = int(params.get("months") or 12)
    if months < 1 or months > 120:
        raise ToolError("有效期（月）需在 1 ~ 120 之间")

    csr_text = (params.get("csr") or "").strip()
    key = None
    if csr_text:
        parsed = _parse_csr(csr_text, params.get("csrFormat"))
        req = parsed["req"]
        info = req["certification_request_info"]
        subject = info["subject"]
        spki = info["subject_pk_info"].dump()
        alg_oid = info["subject_pk_info"]["algorithm"]["algorithm"].dotted
        algorithm = "SM2" if alg_oid in (OID_EC_PUBKEY, OID_SM2_CURVE) and _spki_is_sm2(spki) else "RSA"
        sig_oid = req["signature_algorithm"]["algorithm"].dotted
        pub_for_verify = ""
        if algorithm == "SM2":
            pub_for_verify = akeys.PublicKeyInfo.load(spki)["public_key"].native.hex()
        ok, msg = verify_signature(
            info.dump(), req["signature"].native, sig_oid, spki, pub_for_verify
        )
        if not ok:
            raise ToolError(f"CSR 自签名验证未通过，拒绝签发（{msg}）")
        key = {
            "algorithm": algorithm,
            "spki": spki,
            "private_pem": "",
            "public_hex": pub_for_verify,
            "private_hex": "",
            "key_obj": None,
            "bits": 2048 if algorithm == "RSA" else 256,
            "source": "CSR",
        }
        subject_fields = name_to_dict(subject)["fields"]
        cn = subject_fields.get("common_name", "")
        email = subject_fields.get("email_address", "")
    else:
        algorithm = (params.get("algorithm") or "SM2").upper()
        key = keypair(algorithm, params.get("keyLength") or 2048)
        key["source"] = "内置生成"
        subject = make_name(
            params.get("cnitem"),
            params.get("citem"),
            params.get("sitem"),
            params.get("litem"),
            params.get("oitem"),
            params.get("ouitem"),
            params.get("emailAddress"),
        )
        subject_fields = name_to_dict(subject)["fields"]
        cn = subject_fields.get("common_name", "")
        email = subject_fields.get("email_address", "")

    ca = load_local_ca("SM2" if key["algorithm"] == "SM2" else "RSA")
    ca_cert = parse_cert(ca["cert_der"])
    if key["algorithm"] == "SM2":
        sig_oid, hash_name = "1.2.156.10197.1.501", "SM3"
    else:
        sig_oid, hash_name = _sig_alg_obj("RSA", params.get("signAlg") or "SHA256withRSA")
    ski = _key_identifier(key["spki"], key.get("public_hex", ""))
    aki = bytes.fromhex(ca_cert["ski"]) if ca_cert["ski"] else _key_identifier(ca["key"]["spki"], ca["key"].get("public_hex", ""))
    san_raw = params.get("san") or ""
    if isinstance(san_raw, (list, tuple)):
        san_list = [str(s).strip() for s in san_raw if str(s).strip()]
    else:
        san_list = [s.strip() for s in re.split(r"[,\s;]+", str(san_raw)) if s.strip()]
    exts = _build_leaf_extensions(cert_type, cn, ski, aki, san_list, email)

    now = dt.datetime.now(UTC).replace(microsecond=0)
    not_after = _add_months(now, months)
    der = build_certificate(
        subject=subject,
        subject_spki=key["spki"],
        issuer=ax509.Name.load_bytes(ca["cert_der"]) if False else ax509.Certificate.load(ca["cert_der"]).subject,
        issuer_key=ca["key"],
        not_before=now - dt.timedelta(minutes=5),
        not_after=not_after,
        extensions=exts,
        sig_oid=sig_oid,
        hash_name=hash_name,
    )
    issued = parse_cert(der)
    ok, msg = verify_signature(
        issued["tbs"], issued["signature"], issued["sig_oid"], ca_cert["spki"], ca_cert["pub_hex"]
    )
    if not ok:
        raise ToolError("签发后的证书自检失败，请重试")

    chain_pem = pem_encode(der) + ca["cert_pem"]
    result: dict[str, Any] = {
        "cert": pem_encode(der),
        "certDer": base64.b64encode(der).decode(),
        "chain": chain_pem,
        "caCert": ca["cert_pem"],
        "certType": CERT_TYPES[cert_type],
        "algorithm": key["algorithm"],
        "keyBits": key["bits"],
        "signAlg": sig_alg_name(sig_oid),
        "subject": issued["subject"]["text"],
        "issuer": issued["issuer"]["text"],
        "serial": issued["serial"],
        "notBefore": issued["not_before_text"],
        "notAfter": issued["not_after_text"],
        "sm3": issued["sm3"],
        "sha256": issued["sha256"],
        "keySource": key["source"],
        "signatureValid": ok,
        "signatureMsg": msg,
        "privateKey": key.get("private_pem", ""),
        "publicKey": pem_encode(key["spki"], "PUBLIC KEY"),
        "caFamily": ca["family"],
    }
    if params.get("withPfx"):
        result.update(_build_pfx(der, key, ca, params.get("pfxPassword") or ""))
    return result


def _spki_is_sm2(spki: bytes) -> bool:
    try:
        pki = akeys.PublicKeyInfo.load(spki)
        alg = pki["algorithm"]["algorithm"].dotted
        if alg == OID_SM2_CURVE:
            return True
        params = pki["algorithm"]["parameters"]
        chosen = params.chosen if isinstance(params, acore.Choice) else params
        if isinstance(chosen, acore.ObjectIdentifier) and chosen.dotted == OID_SM2_CURVE:
            return True
    except Exception:
        return False
    return False


def _add_months(base: dt.datetime, months: int) -> dt.datetime:
    year = base.year + (base.month - 1 + months) // 12
    month = (base.month - 1 + months) % 12 + 1
    day = min(base.day, 28)
    return base.replace(year=year, month=month, day=day)


def build_pfx(cert_pem: str, key_pem: str, ca_pem: str = "", password: str = "", name: str = "cipherbox") -> dict[str, Any]:
    if not key_pem.strip():
        raise ToolError("缺少私钥，无法生成 PFX（提交 CSR 签发的场景请使用自己持有的私钥打包）")
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception:  # noqa: BLE001
        raise ToolError("PKCS#12 打包失败：当前 cryptography 不支持该私钥类型（SM2 私钥无法打包）")
    cert = cx509.load_pem_x509_certificate(cert_pem.encode())
    cas = []
    if ca_pem.strip():
        for block in PEM_BLOCK.finditer(ca_pem):
            body = re.sub(r"\s+", "", block.group(2))
            try:
                cas.append(cx509.load_der_x509_certificate(base64.b64decode(body + "=" * ((-len(body)) % 4))))
            except Exception:
                continue
    enc = BestAvailableEncryption(password.encode()) if password else NoEncryption()
    try:
        der = pkcs12.serialize_key_and_certificates(
            name=name.encode()[:60], key=key, cert=cert, cas=cas or None, encryption_algorithm=enc
        )
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"PKCS#12 打包失败：{exc.__class__.__name__}")
    return {
        "pfx": base64.b64encode(der).decode(),
        "pfxBase64": base64.b64encode(der).decode(),
        "pfxLength": len(der),
        "pfxPassword": password,
        "pfxMsg": "PKCS#12 打包成功（DER 的 Base64 文本，可直接另存为 .pfx/.p12）",
    }


def _build_pfx(der: bytes, key: dict[str, Any], ca: dict[str, Any], password: str) -> dict[str, Any]:
    if key["algorithm"] != "RSA":
        return {
            "pfx": "",
            "pfxMsg": (
                "当前离线环境的 cryptography（OpenSSL）不支持 SM2 私钥的 PKCS#12 打包，已提供 PEM 格式私钥与证书；"
                "如需 PFX 可用 OpenSSL 3 转换：openssl pkcs12 -export -inkey key.pem -in cert.pem -certfile ca.pem -out cert.pfx"
            ),
        }
    result = build_pfx(
        pem_encode(der),
        key.get("private_pem", ""),
        ca["cert_pem"],
        password or "",
        name="cipherbox",
    )
    return result


# --------------------------------------------------------------------------- #
# ASN.1
# --------------------------------------------------------------------------- #
def asn1_tree(text: str, fmt: str | None = None) -> dict[str, Any]:
    kind, blobs = split_boxes(text, fmt)
    der = blobs[0]
    try:
        node = parse_der(der)
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"ASN.1 解析失败：{exc.__class__.__name__}")
    tree = _asn1_to_tree(node)
    _decorate_asn1(tree)
    return {
        "tree": tree,
        "format": kind,
        "length": len(der),
        "nodes": _count_nodes(tree),
        "depth": _depth(tree),
        "hex": der.hex(),
    }


def _decorate_asn1(tree: dict[str, Any], level: int = 0, index: int = 0) -> None:
    """补充层级与序号信息（原站返回结构中的 level / index 字段）。"""
    tree["level"] = level
    tree["index"] = index
    for idx, child in enumerate(tree.get("children") or []):
        _decorate_asn1(child, level + 1, idx)


def _count_nodes(tree: dict[str, Any]) -> int:
    return 1 + sum(_count_nodes(c) for c in tree.get("children") or [])


def _depth(tree: dict[str, Any]) -> int:
    children = tree.get("children") or []
    if not children:
        return 1
    return 1 + max(_depth(c) for c in children)

# end of module
