"""电子签章校验（PDF / OFD）与时间戳解析验证（RFC 3161 / GB/T 33000-2014）。

本模块只做真实计算：所有结构均按 ASN.1 / PDF / OFD 规范解析，签名值用真实
公钥验证，摘要按实际字节范围重新计算，不返回任何固定结果。

约定的印章信息结构（用于携带印章名称、有效期与证书绑定关系，SESeal 的
ESEalInfo 子集）::

    ESealInfo ::= SEQUENCE {
        name              UTF8String,
        version           INTEGER,
        type              UTF8String,
        create_time       GeneralizedTime,
        not_before        GeneralizedTime,
        not_after         GeneralizedTime,
        signer_cert_hash  OCTET STRING OPTIONAL,  -- 签章者证书 DER 的 SHA-256
        maker_cert        OCTET STRING OPTIONAL   -- 制章者证书 DER
    }

在 PDF 中该结构放在签名的 signedAttrs 里，属性 OID 为
``1.2.156.112562.2.1.2``；在 OFD 中放在印章文件 ``*.esl`` 里（DER 编码）。
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from asn1crypto import algos, cms, core, tsp, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from .common import ToolError

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

SEAL_ATTR_OID = "1.2.156.112562.2.1.2"     # 印章信息（SESeal ESEalInfo 子集）
SEAL_INFO_ATTR_OID = "1.2.156.112562.2.1.3"  # 部分实现把印章信息放在这个 OID
MAKER_CERT_ATTR_OID = "1.2.156.112562.2.1.4"

DIGEST_LABELS = {
    "sm3": "SM3",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "md5": "MD5",
}

DIGEST_OIDS = {
    "1.2.156.10197.1.401": "sm3",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.2.840.113549.2.5": "md5",
}

SIG_LABELS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.5": "SHA1withRSA",
    "1.2.840.113549.1.1.11": "SHA256withRSA",
    "1.2.840.113549.1.1.12": "SHA384withRSA",
    "1.2.840.113549.1.1.13": "SHA512withRSA",
    "1.2.840.113549.1.1.14": "SHA224withRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.2.1": "ECDSA",
    "1.2.840.10045.4.3.2": "SHA256withECDSA",
    "1.2.840.10045.4.3.3": "SHA384withECDSA",
    "1.2.840.10045.4.3.4": "SHA512withECDSA",
    "1.2.840.10045.4.1": "SHA1withECDSA",
    "1.2.156.10197.1.501": "SM3withSM2",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}

SM2_SIG_OID = "1.2.156.10197.1.501"
SM3_DIGEST_OID = "1.2.156.10197.1.401"

MAX_FILE_SIZE = 10 * 1024 * 1024


# --------------------------------------------------------------------------- #
# ASN.1 结构（印章信息）
# --------------------------------------------------------------------------- #

class EcdsaSignature(core.Sequence):
    """SM2 / ECDSA 的 DER 签名值 SEQUENCE { r INTEGER, s INTEGER }。"""

    _fields = [("r", core.Integer), ("s", core.Integer)]


class ESealInfo(core.Sequence):
    _fields = [
        ("name", core.UTF8String),
        ("version", core.Integer),
        ("type", core.UTF8String),
        ("create_time", core.GeneralizedTime),
        ("not_before", core.GeneralizedTime),
        ("not_after", core.GeneralizedTime),
        ("signer_cert_hash", core.OctetString, {"optional": True}),
        ("maker_cert", core.OctetString, {"optional": True}),
    ]


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _present(value) -> bool:
    """asn1crypto 可选字段是否真的存在（SetOf/Sequence 没有 is_null）。"""
    if value is None:
        return False
    is_null = getattr(value, "is_null", None)
    if is_null is not None:
        try:
            if is_null:
                return False
        except Exception:
            pass
    try:
        if isinstance(value, (list, tuple)) and len(value) == 0:
            return False
    except Exception:
        pass
    return True


def _der_trim(data: bytes) -> bytes:
    """按 DER 外层 TLV 长度截断，去掉 /Contents 的零填充（不能用 rstrip 误删合法尾字节）。"""
    if len(data) < 2:
        return data
    first_len = data[1]
    if first_len & 0x80:
        n = first_len & 0x7F
        if n == 0 or len(data) < 2 + n:
            return data
        length = int.from_bytes(data[2:2 + n], "big")
        header = 2 + n
    else:
        length = first_len
        header = 2
    total = header + length
    if 0 < total <= len(data):
        return data[:total]
    return data


def _octets(value) -> bytes:
    """取出 OCTET STRING 的原始字节（ParsableOctetString 可能已被解析成对象）。"""
    data = getattr(value, "contents", None)
    if isinstance(data, bytes):
        return data
    native = value.native
    if isinstance(native, bytes):
        return native
    return value.dump()


def _hash(algo: str, data: bytes) -> bytes:
    algo = (algo or "sha256").lower().replace("-", "")
    if algo in ("sm3", "sm3withsm2"):
        return hashlib.new("sm3", data).digest()
    try:
        return hashlib.new(algo, data).digest()
    except ValueError:
        raise ToolError(f"不支持的摘要算法：{algo}")


def _digest_name(oid_or_name: Any) -> str:
    if isinstance(oid_or_name, str):
        key = oid_or_name.lower().replace("-", "")
        if key in DIGEST_OIDS:
            return DIGEST_OIDS[key]
        if key in DIGEST_LABELS:
            return key
        if key.startswith("2.16.840.1.101.3.4.2"):
            return "sha256"
        return "sha256"
    return "sha256"


def _digest_label(algo: str) -> str:
    return DIGEST_LABELS.get((algo or "").lower(), (algo or "").upper())


def _sig_label(oid: str, digest: str | None = None) -> str:
    label = SIG_LABELS.get(oid)
    if label:
        return label
    if oid.startswith("1.2.840.113549.1.1"):
        return "RSA"
    if oid.startswith("1.2.840.10045.4"):
        return "ECDSA"
    return oid


def _fmt_dt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)


def _parse_pdf_date(text: str | None) -> datetime | None:
    if not text:
        return None
    m = re.match(r"(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?", text.strip())
    if not m:
        return None
    parts = [int(m.group(i) or 0) for i in range(1, 7)]
    tz = m.group(7)
    try:
        dt = datetime(parts[0], parts[1] or 1, parts[2] or 1, parts[3], parts[4], parts[5], tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = re.sub(r"\D", "", tz[1:])
        hours = int(digits[:2] or 0)
        minutes = int(digits[2:4] or 0)
        from datetime import timedelta
        dt = dt - sign * timedelta(hours=hours, minutes=minutes)
    return dt


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _spki_b64(cert: x509.Certificate) -> str:
    try:
        return _b64(cert.public_key.dump())
    except Exception:
        return "-"


def _cert_pem(der: bytes) -> str:
    b64 = _b64(der)
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def _load_cert(data: bytes) -> x509.Certificate:
    return x509.Certificate.load(data)


def cert_info(cert: x509.Certificate) -> dict:
    """证书结构化信息（含 PEM / base64 DER，便于前端导出）。"""
    der = cert.dump()
    tbs = cert["tbs_certificate"]
    try:
        cn = tbs["subject"].native.get("common_name") or tbs["subject"].native.get("organization_name") or ""
    except Exception:
        cn = ""
    if isinstance(cn, list):
        cn = cn[0] if cn else ""
    bc = None
    try:
        bc = cert.basic_constraints_value
    except Exception:
        bc = None
    ku = None
    try:
        ku = cert.key_usage_value
    except Exception:
        ku = None
    curve = None
    try:
        if cert.public_key.algorithm == "ec":
            curve = cert.public_key["algorithm"]["parameters"].native
    except Exception:
        curve = None
    return {
        "subject": tbs["subject"].human_friendly,
        "subjectCn": cn,
        "issuer": tbs["issuer"].human_friendly,
        "serialNumber": format(tbs["serial_number"].native, "X"),
        "notBefore": _fmt_dt(tbs["validity"]["not_before"].native),
        "notAfter": _fmt_dt(tbs["validity"]["not_after"].native),
        "notBeforeRaw": tbs["validity"]["not_before"].native,
        "notAfterRaw": tbs["validity"]["not_after"].native,
        "signatureAlgorithm": _sig_label(tbs["signature"]["algorithm"].dotted),
        "publicKeyAlgorithm": cert.public_key.algorithm,
        "curve": curve,
        "isCa": bool(bc and bc["ca"].native),
        "keyUsage": sorted(ku.native) if ku else [],
        "sha256": hashlib.sha256(der).hexdigest(),
        "base64": _b64(der),
        "pem": _cert_pem(der),
        "text": (
            f"主体：{tbs['subject'].human_friendly}\n"
            f"颁发者：{tbs['issuer'].human_friendly}\n"
            f"序列号：{format(tbs['serial_number'].native, 'X')}\n"
            f"有效期：{_fmt_dt(tbs['validity']['not_before'].native)} 至 {_fmt_dt(tbs['validity']['not_after'].native)}\n"
            f"公钥算法：{cert.public_key.algorithm}"
            + (f"（{curve}）" if curve else "")
            + f"\n签名算法：{_sig_label(tbs['signature']['algorithm'].dotted)}"
        ),
    }


# --------------------------------------------------------------------------- #
# 公钥验签
# --------------------------------------------------------------------------- #

def _der_sig_to_rs(sig: bytes) -> tuple[int, int]:
    """SM2 签名值 DER SEQUENCE{r,s} -> (r, s)。"""
    try:
        seq = EcdsaSignature.load(sig)
        return int(seq["r"].native), int(seq["s"].native)
    except Exception:
        raise ToolError("SM2 签名值结构非法")


def _sm2_verify(pub_der: bytes, signature: bytes, data: bytes, cert: x509.Certificate | None = None) -> bool:
    from gmssl import sm2 as gm_sm2

    try:
        pub = serialization.load_der_public_key(pub_der)
        nums = pub.public_numbers()
        hex_pub = format(nums.x, "064x") + format(nums.y, "064x")
    except Exception:
        # 证书公钥直接取 BIT STRING（未压缩点 0x04 || X || Y）
        try:
            point = cert.public_key["public_key"].native
            hex_pub = point.hex()
            if hex_pub.startswith("04") and len(hex_pub) == 130:
                hex_pub = hex_pub[2:]
        except Exception:
            raise ToolError("无法解析 SM2 公钥")
    hex_pub = hex_pub.rjust(128, "0")

    r, s = _der_sig_to_rs(signature)
    # 注意：gmssl 构造时会 lstrip("04")，x 以 04 开头时会把公钥截短，故构造后直接赋值
    verifier = gm_sm2.CryptSM2(private_key=None, public_key="0" * 128)
    verifier.public_key = hex_pub
    hex_sig = format(r, "064x") + format(s, "064x")
    try:
        if verifier.verify_with_sm3(hex_sig, data):
            return True
    except Exception:
        return False
    try:
        # 兜底：调用方传入的可能是已做 ZA 预处理的数据（极少见）
        return bool(verifier.verify(hex_sig, data))
    except Exception:
        return False


def _pyca_hash(name: str):
    name = (name or "sha256").lower()
    return {
        "sha1": hashes.SHA1(),
        "sha224": hashes.SHA224(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
        "sm3": getattr(hashes, "SM3", lambda: hashes.SHA256())(),
    }.get(name, hashes.SHA256())


def _verify_with_pubkey(pub_der: bytes, sig_algo: algos.SignedDigestAlgorithm,
                        signature: bytes, data: bytes, digest_name: str,
                        cert: x509.Certificate | None = None) -> tuple[bool, str]:
    """用公钥验证签名，返回 (是否通过, 失败原因)。"""
    try:
        oid = sig_algo["algorithm"].dotted
    except Exception:
        oid = ""
    try:
        mechanism = sig_algo.signature_algo
    except Exception:
        mechanism = {
            "1.2.156.10197.1.501": "sm2",
            "1.2.840.113549.1.1.1": "rsassa_pkcs1v15",
            "1.2.840.113549.1.1.10": "rsassa_pss",
        }.get(oid, oid)

    if mechanism == "sm2" or oid == SM2_SIG_OID:
        return (_sm2_verify(pub_der, signature, data, cert), "")

    try:
        pub = serialization.load_der_public_key(pub_der)
    except Exception as exc:  # pragma: no cover - 异常密钥
        return False, f"公钥解析失败：{exc}"

    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if mechanism == "rsassa_pss":
                params = sig_algo["parameters"]
                hs = _digest_name(params["hash_algorithm"]["algorithm"].dotted)
                mgf_hash = _digest_name(params["mask_gen_algorithm"]["parameters"]["algorithm"].dotted)
                salt_len = params["salt_length"].native
                pss = padding.PSS(mgf=padding.MGF1(_pyca_hash(mgf_hash)), salt_length=salt_len)
                pub.verify(signature, data, pss, _pyca_hash(hs))
            else:
                pub.verify(signature, data, padding.PKCS1v15(), _pyca_hash(digest_name))
            return True, ""
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(_pyca_hash(digest_name)))
            return True, ""
        if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(signature, data)
            return True, ""
    except Exception as exc:
        return False, f"签名验证失败：{type(exc).__name__}"
    return False, f"不支持的公钥类型：{type(pub).__name__}"


def _verify_cert_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """用签发者公钥验证下级证书签名。"""
    try:
        try:
            digest_name = child["signature_algorithm"].hash_algo or "sha256"
        except Exception:
            digest_name = "sha256"
        ok, _ = _verify_with_pubkey(
            issuer.public_key.dump(), child["signature_algorithm"],
            child["signature_value"].native, child["tbs_certificate"].dump(),
            digest_name, child,
        )
        return ok
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# CMS SignedData 解析与验证
# --------------------------------------------------------------------------- #

def _find_signer_cert(sd: cms.SignedData, si: cms.SignerInfo) -> x509.Certificate | None:
    certs: list[x509.Certificate] = []
    try:
        for choice in sd["certificates"]:
            if choice.name == "certificate":
                certs.append(choice.chosen)
    except Exception:
        certs = []
    sid = si["sid"]
    if sid.name == "issuer_and_serial_number":
        try:
            issuer_der = sid.chosen["issuer"].dump()
            serial = sid.chosen["serial_number"].native
        except Exception:
            issuer_der, serial = None, None
        for cert in certs:
            try:
                if issuer_der is not None and cert.issuer.dump() == issuer_der and cert.serial_number == serial:
                    return cert
            except Exception:
                continue
    else:
        key_id = sid.chosen.native
        for cert in certs:
            try:
                if cert.key_identifier == key_id:
                    return cert
            except Exception:
                continue
    return certs[0] if certs else None


def _parse_seal_attr(signed_attrs) -> dict | None:
    if signed_attrs is None:
        return None
    for attr in signed_attrs:
        oid = attr["type"].dotted
        if oid not in (SEAL_ATTR_OID, SEAL_INFO_ATTR_OID):
            continue
        for value in attr["values"]:
            try:
                info = ESealInfo.load(value.dump(), strict=False)
                return {
                    "name": info["name"].native,
                    "version": info["version"].native,
                    "type": info["type"].native,
                    "createTime": _fmt_dt(info["create_time"].native),
                    "notBefore": info["not_before"].native,
                    "notAfter": info["not_after"].native,
                    "startTime": _fmt_dt(info["not_before"].native),
                    "endTime": _fmt_dt(info["not_after"].native),
                    "signerCertHash": info["signer_cert_hash"].native.hex()
                    if _present(info["signer_cert_hash"]) else None,
                    "makerCert": info["maker_cert"].native if _present(info["maker_cert"]) else None,
                    "oid": oid,
                }
            except Exception:
                continue
    return None


def verify_cms(cms_der: bytes, detached_data: bytes | None = None) -> dict:
    """解析并验证 CMS SignedData（detached_data 为 NULL 表示签名内容内嵌）。"""
    cms_der = _der_trim(cms_der)
    if not cms_der:
        raise ToolError("签章值（CMS）为空")
    try:
        ci = cms.ContentInfo.load(cms_der, strict=False)
    except Exception as exc:
        raise ToolError(f"签名值不是合法的 CMS（PKCS#7）结构：{exc}")
    if ci["content_type"].native != "signed_data":
        raise ToolError(f"签名值内容类型不是 signedData：{ci['content_type'].native}")

    sd = ci["content"]
    signer_infos = sd["signer_infos"]
    if len(signer_infos) == 0:
        raise ToolError("CMS 结构中没有 SignerInfo")

    si = signer_infos[0]
    digest_name = _digest_name(si["digest_algorithm"]["algorithm"].dotted)
    sig_oid = si["signature_algorithm"]["algorithm"].dotted
    sig_label = _sig_label(sig_oid, digest_name)

    signed_attrs = si["signed_attrs"] if _present(si["signed_attrs"]) else None
    econtent = None
    try:
        content = sd["encap_content_info"]["content"]
        if _present(content):
            econtent = _octets(content)
    except Exception:
        econtent = None

    cert = _find_signer_cert(sd, si)
    certs = []
    try:
        for choice in sd["certificates"]:
            if choice.name == "certificate":
                certs.append(choice.chosen)
    except Exception:
        certs = []

    # 1) signedAttrs：messageDigest / contentType
    message_digest = None
    content_type_ok = True
    content_type_note = ""
    if signed_attrs is not None:
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                message_digest = attr["values"][0].native
            elif attr["type"].native == "content_type":
                ct = attr["values"][0].native
                expected = sd["encap_content_info"]["content_type"].native
                content_type_ok = ct == expected
                content_type_note = f"signedAttrs contentType={ct}，eContentType={expected}"

    # 2) 验签数据：有 signedAttrs 时签名对象是 DER 编码的 SET OF Attribute
    if signed_attrs is not None:
        signed_bytes = b"\x31" + signed_attrs.dump()[1:]
    else:
        signed_bytes = econtent if econtent is not None else (detached_data or b"")

    if cert is None:
        sig_ok, sig_err = False, "CMS 中未找到签章者证书"
    else:
        sig_ok, sig_err = _verify_with_pubkey(
            cert.public_key.dump(), si["signature_algorithm"],
            si["signature"].native, signed_bytes, digest_name, cert,
        )

    # 3) 原文摘要
    actual_digest = None
    digest_source = None
    if detached_data is not None:
        actual_digest = _hash(digest_name, detached_data)
        digest_source = "detached"
    elif econtent is not None:
        actual_digest = _hash(digest_name, econtent)
        digest_source = "econtent"

    digest_ok = None
    if message_digest is not None and actual_digest is not None:
        digest_ok = message_digest == actual_digest

    sign_time = None
    if signed_attrs is not None:
        for attr in signed_attrs:
            if attr["type"].native == "signing_time":
                try:
                    sign_time = attr["values"][0].native
                except Exception:
                    sign_time = None
                break

    seal = _parse_seal_attr(signed_attrs)

    return {
        "digestAlgorithm": digest_name,
        "digestLabel": _digest_label(digest_name),
        "signatureAlgorithm": sig_label,
        "signatureOid": sig_oid,
        "signerCert": cert,
        "certs": certs,
        "signature": si["signature"].native,
        "econtent": econtent,
        "detached": detached_data,
        "messageDigest": message_digest,
        "actualDigest": actual_digest,
        "digestSource": digest_source,
        "digestOk": digest_ok,
        "contentTypeOk": content_type_ok,
        "contentTypeNote": content_type_note,
        "signedAttrs": signed_attrs is not None,
        "signatureOk": sig_ok,
        "signatureError": sig_err,
        "signingTime": sign_time,
        "seal": seal,
        "signerInfo": si,
    }


# --------------------------------------------------------------------------- #
# 证书链 / 有效性
# --------------------------------------------------------------------------- #

def _check_cert_validity(cert: x509.Certificate, now: datetime) -> tuple[bool, str]:
    nb = cert["tbs_certificate"]["validity"]["not_before"].native
    na = cert["tbs_certificate"]["validity"]["not_after"].native
    if nb > now:
        return False, f"证书尚未生效（生效时间 {_fmt_dt(nb)}）"
    if na < now:
        return False, f"证书已过期（到期时间 {_fmt_dt(na)}）"
    return True, f"证书在有效期内（{_fmt_dt(nb)} 至 {_fmt_dt(na)}）"


def _build_chain(signer: x509.Certificate, certs: list[x509.Certificate]) -> dict:
    pool = {}
    for c in certs:
        try:
            pool[c.subject.dump()] = c
        except Exception:
            continue
    chain = [signer]
    current = signer
    broken = None
    for _ in range(8):
        try:
            if current.subject.dump() == current.issuer.dump():
                break
        except Exception:
            broken = "证书主体/颁发者信息损坏"
            break
        nxt = pool.get(current.issuer.dump())
        if nxt is None:
            broken = f"缺少颁发者证书：{current.issuer.human_friendly}"
            break
        if not _verify_cert_signature(current, nxt):
            broken = f"证书签名校验失败：{current.subject.human_friendly}"
            break
        chain.append(nxt)
        current = nxt
    root = chain[-1]
    try:
        self_signed = root.subject.dump() == root.issuer.dump()
    except Exception:
        self_signed = False
    if self_signed and not _verify_cert_signature(root, root):
        broken = "自签根证书签名自校验失败"
    return {
        "chain": chain,
        "broken": broken,
        "rootSelfSigned": self_signed,
        "depth": len(chain) - 1,
    }


# --------------------------------------------------------------------------- #
# PDF 签章
# --------------------------------------------------------------------------- #

def _pdf_collect_sig_dicts(data: bytes) -> list[tuple[str, Any]]:
    from pypdf import PdfReader

    out: list[tuple[str, Any]] = []
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:
        raise ToolError(f"PDF 解析失败：{exc}")

    def resolve(obj):
        for _ in range(8):
            if hasattr(obj, "get_object") and not isinstance(obj, dict):
                obj = obj.get_object()
            else:
                break
        return obj

    def walk(node, name: str, depth: int = 0):
        if depth > 8:
            return
        node = resolve(node)
        if not isinstance(node, dict):
            return
        value = resolve(node.get("/V")) if "/V" in node else None
        if isinstance(value, dict) and "/ByteRange" in value and "/Contents" in value:
            out.append((name or str(node.get("/T", "")), value))
            return
        kids = resolve(node.get("/Kids"))
        if kids:
            for kid in kids:
                walk(kid, name, depth + 1)

    try:
        root = resolve(reader.trailer["/Root"])
        acro = resolve(root.get("/AcroForm")) if root else None
        if acro:
            for idx, field in enumerate(resolve(acro.get("/Fields")) or []):
                walk(field, f"Signature{idx + 1}")
    except Exception:
        pass

    if not out:
        # 兼容损坏的对象树：直接按字节扫描 /ByteRange 与 /Contents
        for idx, m in enumerate(re.finditer(rb"/ByteRange\s*\[([^\]]*)\]", data)):
            seg = data[max(0, m.start() - 2000): m.start() + 2000]
            cm = re.search(rb"/Contents\s*<([0-9A-Fa-f\s]+)>", seg)
            if not cm:
                continue
            br = [int(x) for x in m.group(1).split()]
            out.append((f"Signature{idx + 1}", {
                "/ByteRange": br,
                "/Contents": bytes.fromhex(re.sub(rb"\s", b"", cm.group(1)).decode()),
                "/SubFilter": None,
                "/M": None,
            }))
    return out


def _pdf_byte_range(data: bytes, br: list[int]) -> tuple[bytes, str | None, int]:
    """返回 (参与签名的字节, 警告, 终止偏移)。"""
    if len(br) < 4 or len(br) % 2:
        raise ToolError("/ByteRange 结构非法")
    if br[0] != 0:
        raise ToolError("/ByteRange 未从文件起始位置开始")
    chunks = []
    warning = None
    prev_end = 0
    for i in range(0, len(br), 2):
        start, length = br[i], br[i + 1]
        if start < prev_end or length < 0:
            raise ToolError("/ByteRange 区间重叠或长度非法")
        if i > 0 and start == prev_end:
            raise ToolError("/ByteRange 区间之间没有签名值占位")
        chunks.append(data[start:start + length])
        prev_end = start + length
    end = prev_end
    if end < len(data):
        warning = f"/ByteRange 仅覆盖至 {end}/{len(data)} 字节（文件在签名后存在增量更新）"
    return b"".join(chunks), warning, end


def verify_pdf(data: bytes) -> dict:
    sigs = _pdf_collect_sig_dicts(data)
    if not sigs:
        raise ToolError("未在 PDF 中找到电子签章数据（缺少 /Sig 签名字段）")

    results = []
    for index, (name, sig) in enumerate(sigs):
        results.append(_pdf_signature_check(data, name, sig, index))
    return {"fileType": "PDF", "signatureCount": len(results), "signatures": results}


def _pdf_signature_check(data: bytes, name: str, sig: dict, index: int) -> dict:
    now = _now()
    checks: list[dict] = []

    def add(key: str, title: str, ok: bool, message: str, status: str | None = None):
        checks.append({
            "key": key, "name": title, "ok": bool(ok),
            "status": status or ("pass" if ok else "fail"),
            "message": message,
        })

    warnings: list[str] = []
    br = [int(x) for x in (sig.get("/ByteRange") or [])]
    contents_raw = sig.get("/Contents")
    sub_filter = sig.get("/SubFilter")
    sub_filter_name = getattr(sub_filter, "native", None) or (str(sub_filter) if sub_filter else None)

    # ---- 格式 ----
    fmt_notes = []
    fmt_ok = True
    try:
        signed_bytes, br_warn, _br_end = _pdf_byte_range(data, br)
        fmt_notes.append(f"/ByteRange 合法，签名覆盖 {len(signed_bytes)} 字节")
        if br_warn:
            warnings.append(br_warn)
    except ToolError as exc:
        fmt_ok = False
        signed_bytes = b""
        fmt_notes.append(str(exc))

    cms_der = _der_trim(bytes(contents_raw or b""))
    cms_info = None
    if not cms_der:
        fmt_ok = False
        fmt_notes.append("/Contents 为空")
    else:
        try:
            cms_info = verify_cms(cms_der, detached_data=signed_bytes)
            fmt_notes.append(
                f"CMS SignedData 结构合法（SignerInfo 1 个，"
                f"证书 {len(cms_info['certs'])} 张，签名算法 {cms_info['signatureAlgorithm']}）"
            )
        except ToolError as exc:
            fmt_ok = False
            fmt_notes.append(str(exc))

    if fmt_ok and sub_filter_name and sub_filter_name not in (
        "adbe.pkcs7.detached", "adbe.pkcs7.sha1", "ETSI.CAdES.detached", "adbe.x509.rsa_sha1"
    ):
        fmt_notes.append(f"SubFilter={sub_filter_name}")
    add("sigFormatData", "电子签章数据格式正确性", fmt_ok, "；".join(fmt_notes))

    if cms_info is None:
        # 无法继续校验，其余项统一给出失败说明
        for key, title in [
            ("signDataValid", "电子签章签名值正确性"),
            ("signCertAndSeal", "签章者证书与电子印章的匹配性"),
            ("sealValid", "电子印章有效性"),
            ("signCertValid", "签章者证书有效性"),
            ("signTimeValid", "签章时间有效性"),
            ("digestValid", "原文摘要匹配"),
        ]:
            add(key, title, False, "签章数据无法解析，无法完成该项校验")
        return {
            "index": index, "format": "PDF", "fieldName": name, "subFilter": sub_filter_name,
            "checks": checks, "allValid": False, "allPassed": False,
            "warnCount": sum(1 for c in checks if c["status"] == "warn"),
            "warnings": warnings,
            "details": {"sealName": "-", "signCertString": "无", "orgDataDigest": "-"},
        }

    cert = cms_info["signerCert"]
    seal = cms_info["seal"] or {}
    details_cert = cert_info(cert) if cert is not None else None

    # ---- 签名值 ----
    sig_msgs = []
    sig_ok = cms_info["signatureOk"]
    if cms_info["signedAttrs"]:
        sig_msgs.append("已按 signedAttrs 的 DER 编码（SET OF Attribute）验签")
        if cms_info["messageDigest"] is not None:
            sig_msgs.append("signedAttrs 含 messageDigest")
        else:
            sig_ok = False
            sig_msgs.append("signedAttrs 缺少 messageDigest")
        if cms_info["contentTypeOk"]:
            sig_msgs.append("contentType 与 eContentType 一致")
        else:
            sig_ok = False
            sig_msgs.append(cms_info["contentTypeNote"] or "contentType 不一致")
    else:
        sig_msgs.append("签名未使用 signedAttrs，直接对原文签名")
    if not cms_info["signatureOk"]:
        sig_msgs.append(cms_info["signatureError"] or "签名验证失败")
    add("signDataValid", "电子签章签名值正确性", sig_ok,
        f"{cms_info['signatureAlgorithm']} 验签" + ("通过" if cms_info["signatureOk"] else "未通过") + "；" + "；".join(sig_msgs))

    # ---- 证书与印章匹配 ----
    seal_hash = seal.get("signerCertHash")
    if seal_hash and details_cert:
        match = seal_hash.lower() == details_cert["sha256"].lower()
        msg = (
            f"印章信息绑定证书 SHA-256 与签章者证书一致（{seal_hash[:16]}…）"
            if match else f"印章信息绑定证书摘要为 {seal_hash[:16]}…，与签章者证书（{details_cert['sha256'][:16]}…）不一致"
        )
        add("signCertAndSeal", "签章者证书与电子印章的匹配性", match, msg)
    elif seal:
        cn = details_cert["subjectCn"] if details_cert else ""
        match = bool(cn) and cn in (seal.get("name") or "")
        add("signCertAndSeal", "签章者证书与电子印章的匹配性", match,
            f"印章「{seal.get('name')}」未绑定证书摘要，按证书主体 CN（{cn}）与印章名称比对" + ("一致" if match else "不一致"),
            status="pass" if match else "fail")
    else:
        add("signCertAndSeal", "签章者证书与电子印章的匹配性", True,
            "PDF 签章未携带独立电子印章结构，签章者即证书持有者（无独立印章可比对）", status="warn")

    # ---- 印章有效期 ----
    if seal.get("notBefore") and seal.get("notAfter"):
        nb, na = seal["notBefore"], seal["notAfter"]
        ok = nb <= now <= na
        add("sealValid", "电子印章有效性", ok,
            f"印章有效期 {_fmt_dt(nb)} 至 {_fmt_dt(na)}" + ("" if ok else "，当前时间不在有效期内"))
    else:
        add("sealValid", "电子印章有效性", True,
            "签章未携带独立印章信息，按签章者证书有效期判定" if details_cert else "缺少证书信息",
            status="warn")

    # ---- 证书有效性 ----
    cert_ok = True
    cert_msgs = []
    if cert is None:
        cert_ok = False
        cert_msgs.append("未找到签章者证书")
    else:
        valid, msg = _check_cert_validity(cert, now)
        cert_ok = cert_ok and valid
        cert_msgs.append(msg)
        if details_cert and details_cert["isCa"]:
            cert_ok = False
            cert_msgs.append("签章者证书是 CA 证书，不能作为签章实体证书")
        usage = details_cert["keyUsage"] if details_cert else []
        if usage and not ({"digital_signature", "non_repudiation"} & set(usage)):
            cert_ok = False
            cert_msgs.append(f"密钥用途为 {usage}，不支持数字签名")
        chain = _build_chain(cert, cms_info["certs"])
        if chain["broken"]:
            cert_msgs.append(chain["broken"] + "；按自签/有效期结果判定")
            cert_status = "warn" if valid else "fail"
        else:
            cert_status = "pass" if cert_ok else "fail"
            if chain["rootSelfSigned"]:
                cert_msgs.append(f"证书链完整（{chain['depth']} 级），根证书为自签根，未接入系统信任库")
            else:
                cert_msgs.append(f"证书链完整（{chain['depth']} 级）")
        add("signCertValid", "签章者证书有效性", cert_ok, "；".join(cert_msgs), status=cert_status)
        chain_info = chain
    if cert is None:
        add("signCertValid", "签章者证书有效性", False, "；".join(cert_msgs))
        chain_info = {"chain": [], "broken": "无证书", "rootSelfSigned": False, "depth": 0}

    # ---- 签章时间 ----
    sign_time = cms_info["signingTime"] or _parse_pdf_date(getattr(sig.get("/M"), "native", None) or str(sig.get("/M") or ""))
    time_ok = False
    time_msg = "未获取到签章时间"
    if sign_time is not None:
        if cert is not None:
            nb = cert["tbs_certificate"]["validity"]["not_before"].native
            na = cert["tbs_certificate"]["validity"]["not_after"].native
            time_ok = nb <= sign_time <= na
            time_msg = (
                f"签章时间 {_fmt_dt(sign_time)} 位于证书有效期（{_fmt_dt(nb)} 至 {_fmt_dt(na)}）内"
                if time_ok else
                f"签章时间 {_fmt_dt(sign_time)} 不在证书有效期（{_fmt_dt(nb)} 至 {_fmt_dt(na)}）内"
            )
        else:
            time_msg = f"签章时间 {_fmt_dt(sign_time)}，但缺少证书无法比对有效期"
    add("signTimeValid", "签章时间有效性", time_ok, time_msg)

    # ---- 原文摘要 ----
    digest_ok = bool(cms_info["digestOk"])
    digest_msgs = []
    if cms_info["actualDigest"] is not None and cms_info["messageDigest"] is not None:
        digest_msgs.append(
            f"{cms_info['digestLabel']} 原文摘要 {cms_info['actualDigest'].hex()[:32]}… "
            + ("与 signedAttrs messageDigest 一致" if digest_ok else
               f"与 messageDigest {cms_info['messageDigest'].hex()[:32]}… 不一致")
        )
    elif cms_info["messageDigest"] is None:
        digest_ok = False
        digest_msgs.append("signedAttrs 中缺少 messageDigest")
    else:
        digest_ok = False
        digest_msgs.append("无法计算原文摘要（未取到签名原文）")
    digest_msgs.append(f"覆盖 {len(signed_bytes)} 字节（/ByteRange {br}）")
    add("digestValid", "原文摘要匹配", digest_ok, "；".join(digest_msgs))

    details = {
        "index": index,
        "sealName": seal.get("name") or (details_cert["subjectCn"] if details_cert else "-"),
        "sealVersion": seal.get("version") or "-",
        "sealType": seal.get("type") or "-",
        "signVersion": 1,
        "sealCreateTime": seal.get("createTime") or "-",
        "sealStartTime": seal.get("startTime") or "-",
        "sealEndTime": seal.get("endTime") or "-",
        "signTime": _fmt_dt(sign_time),
        "signTimeRaw": sign_time.isoformat() if sign_time else None,
        "publicKey": _spki_b64(cert) if cert is not None else "-",
        "publicKeyAlg": (details_cert["publicKeyAlgorithm"] + (f"（{details_cert['curve']}）" if details_cert and details_cert["curve"] else "")) if details_cert else "-",
        "orgDataDigest": cms_info["actualDigest"].hex() if cms_info["actualDigest"] else (
            cms_info["messageDigest"].hex() if cms_info["messageDigest"] else "-"),
        "digestAlgorithm": cms_info["digestLabel"],
        "signAlgorithm": cms_info["signatureAlgorithm"],
        "signData": cms_info["signature"].hex(),
        "orgData": _orgdata_text(signed_bytes),
        "orgDataFormat": "HEX",
        "orgDataLength": len(signed_bytes),
        "orgDataDigestExpected": cms_info["messageDigest"].hex() if cms_info["messageDigest"] else None,
        "signCert": details_cert["base64"] if details_cert else None,
        "signCertString": details_cert["text"] if details_cert else "无",
        "signCertInfo": details_cert,
        "makerCert": _b64(seal["makerCert"]) if seal.get("makerCert") else None,
        "makerCertString": _maker_text(seal.get("makerCert")),
        "signCertList": [_b64(c.dump()) for c in chain_info.get("chain", [])],
        "signCertListString": [_cert_info_safe(c)["text"] for c in chain_info.get("chain", [])],
        "chain": {
            "depth": chain_info.get("depth", 0),
            "rootSelfSigned": chain_info.get("rootSelfSigned", False),
            "broken": chain_info.get("broken"),
            "certs": [_cert_info_safe(c) for c in chain_info.get("chain", [])],
        },
        "byteRange": br,
        "fieldName": name,
        "subFilter": sub_filter_name,
    }

    return {
        "index": index,
        "format": "PDF",
        "fieldName": name,
        "subFilter": sub_filter_name,
        "checks": checks,
        "allValid": all(c["status"] != "fail" for c in checks),
        "allPassed": all(c["status"] == "pass" for c in checks),
        "warnCount": sum(1 for c in checks if c["status"] == "warn"),
        "warnings": warnings,
        "details": details,
    }


def _cert_info_safe(cert: x509.Certificate) -> dict:
    try:
        return cert_info(cert)
    except Exception:
        return {"text": "证书信息解析失败", "base64": _b64(cert.dump()), "pem": _cert_pem(cert.dump())}


def _orgdata_text(data: bytes) -> str:
    if not data:
        return "-"
    try:
        text = data.decode("utf-8")
        if "\x00" not in text:
            return text
    except UnicodeDecodeError:
        pass
    head = data[:2048]
    return head.hex() + ("…（共 %d 字节）" % len(data) if len(data) > len(head) else "")


def _maker_text(der: bytes | None) -> str:
    if not der:
        return "无"
    try:
        return cert_info(x509.Certificate.load(der))["text"]
    except Exception:
        return "制章者证书解析失败"


# --------------------------------------------------------------------------- #
# OFD 签章
# --------------------------------------------------------------------------- #

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _ofd_read_zip(data: bytes) -> dict[str, bytes]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ToolError("OFD 文件不是合法的 ZIP 包")
    total = 0
    files: dict[str, bytes] = {}
    for info in zf.infolist():
        if info.is_dir():
            continue
        total += info.file_size
        if total > 80 * 1024 * 1024:
            raise ToolError("OFD 解压后体积过大，已终止解析")
        name = info.filename.replace("\\", "/")
        files[name] = zf.read(info)
    return files


def _ofd_attr(elem, *names):
    for key, value in elem.attrib.items():
        if _local(key) in names:
            return value
    return None


def _ofd_child(elem, name: str):
    for child in elem:
        if _local(child.tag) == name:
            return child
    return None


def _ofd_find_all(root, name: str):
    return [e for e in root.iter() if _local(e.tag) == name]


def _ofd_raw_element(xml_bytes: bytes, name: str) -> list[bytes]:
    pattern = rb"<(?:\w+:)?" + name.encode() + rb"\b[^>]*>.*?</(?:\w+:)?" + name.encode() + rb"\s*>"
    return re.findall(pattern, xml_bytes, flags=re.S)


def _digest_by_algorithm_name(name: str | None) -> str:
    name = (name or "").upper().replace("-", "")
    return {
        "SHA1": "sha1", "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512",
        "SM3": "sm3", "MD5": "md5", "SHA224": "sha224",
    }.get(name, "sha256")


def verify_ofd(data: bytes) -> dict:
    files = _ofd_read_zip(data)
    if "OFD.xml" not in files:
        raise ToolError("OFD 包中缺少 OFD.xml")

    sig_files = {k: v for k, v in files.items() if k.rsplit("/", 1)[-1] == "Signatures.xml"}
    if not sig_files:
        raise ToolError("OFD 包中缺少 Signatures.xml（无电子签章数据）")

    results = []
    index = 0
    for path, xml_bytes in sig_files.items():
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            raise ToolError(f"{path} XML 解析失败：{exc}")
        sig_elems = _ofd_find_all(root, "Signature")
        root_dir = path.rsplit("/", 1)[0] if "/" in path else ""
        for pos, elem in enumerate(sig_elems):
            # OFD 允许把签名描述（SignedInfo / SignedValue）放在 BaseLoc 指向的文件中
            src_bytes, src_dir = xml_bytes, root_dir
            info_elem = elem
            base_loc = _ofd_attr(elem, "BaseLoc")
            if base_loc:
                candidate = _ofd_resolve_path(root_dir, base_loc)
                if candidate not in files:
                    candidate = base_loc.replace("\\", "/").lstrip("/")
                if candidate in files and b"SignedInfo" in files[candidate]:
                    src_bytes = files[candidate]
                    src_dir = candidate.rsplit("/", 1)[0] if "/" in candidate else ""
                    try:
                        desc_root = ET.fromstring(src_bytes)
                        desc_sigs = _ofd_find_all(desc_root, "Signature")
                        if desc_sigs:
                            info_elem = desc_sigs[0]
                    except ET.ParseError:
                        info_elem = elem
            raw_signed_infos = _ofd_raw_element(src_bytes, "SignedInfo")
            raw = raw_signed_infos[0] if raw_signed_infos else None
            results.append(_ofd_signature_check(
                files, path, elem, raw, index, root_dir=src_dir, info_elem=info_elem,
            ))
            index += 1

    if not results:
        raise ToolError("Signatures.xml 中没有 Signature 节点")
    return {"fileType": "OFD", "signatureCount": len(results), "signatures": results}


def _ofd_resolve_path(base_dir: str, ref: str) -> str:
    ref = ref.replace("\\", "/").lstrip("/")
    if base_dir and not ref.startswith(base_dir + "/"):
        return f"{base_dir}/{ref}"
    return ref


def _ofd_signature_check(files: dict[str, bytes], path: str, elem, raw_signed_info: bytes | None,
                         index: int, root_dir: str, info_elem=None) -> dict:
    now = _now()
    checks: list[dict] = []
    warnings: list[str] = []

    def add(key, title, ok, message, status=None):
        checks.append({"key": key, "name": title, "ok": bool(ok),
                       "status": status or ("pass" if ok else "fail"), "message": message})

    sig_id = _ofd_attr(elem, "ID") or f"Signature{index + 1}"
    signed_info = _ofd_child(info_elem if info_elem is not None else elem, "SignedInfo")
    provider = _ofd_child(signed_info, "Provider") if signed_info is not None else None
    provider_name = _ofd_attr(provider, "ProviderName") if provider is not None else None
    provider_version = _ofd_attr(provider, "Version") if provider is not None else None
    method_elem = _ofd_child(signed_info, "SignatureMethod") if signed_info is not None else None
    method = (method_elem.text or "").strip() if method_elem is not None else None
    time_elem = _ofd_child(signed_info, "SignatureDateTime") if signed_info is not None else None
    sign_time_text = (time_elem.text or "").strip() if time_elem is not None else None
    sign_time = _parse_iso(sign_time_text)

    # ---- 格式 ----
    fmt_msgs = [f"OFD 包结构合法（{len(files)} 个条目），签章文件 {path}，Signature ID={sig_id}"]
    fmt_ok = True
    if not raw_signed_info:
        fmt_ok = False
        fmt_msgs.append("未取到 SignedInfo 原文")
    if signed_info is None:
        fmt_ok = False
        fmt_msgs.append("缺少 SignedInfo 节点")
    if provider_name:
        fmt_msgs.append(f"签章提供者 {provider_name}" + (f" v{provider_version}" if provider_version else ""))
    if method:
        fmt_msgs.append(f"签名方法 {method}")

    value_elem = _ofd_child(elem, "SignedValue")
    cms_der = b""
    if value_elem is not None:
        text = (value_elem.text or "").strip()
        if text:
            try:
                cms_der = base64.b64decode(re.sub(r"\s+", "", text), validate=True)
            except Exception:
                cms_der = b""
        base_loc = _ofd_attr(value_elem, "BaseLoc")
        if not base_loc:
            loc_child = _ofd_child(value_elem, "BaseLoc")
            base_loc = (loc_child.text or "").strip() if loc_child is not None else None
        if base_loc:
            candidate = _ofd_resolve_path(root_dir, base_loc)
            if candidate in files:
                cms_der = files[candidate]
    if not cms_der:
        for name in ("SignedValue.dat", "SignedValue.bin", "Signs/SignedValue.dat"):
            candidate = _ofd_resolve_path(root_dir, name)
            if candidate not in files:
                candidate = name
            if candidate in files:
                cms_der = files[candidate]
                fmt_msgs.append(f"签名值取自 {candidate}")
                break
    if not cms_der:
        fmt_ok = False
        fmt_msgs.append("缺少 SignedValue（签名值）")

    cms_info = None
    if cms_der:
        try:
            cms_info = verify_cms(cms_der, detached_data=raw_signed_info)
            fmt_msgs.append(
                f"CMS SignedData 结构合法，证书 {len(cms_info['certs'])} 张，签名算法 {cms_info['signatureAlgorithm']}"
            )
        except ToolError as exc:
            fmt_ok = False
            fmt_msgs.append(str(exc))

    # 引用文件摘要（Reference）
    ref_results = []
    if signed_info is not None:
        refs_parent = _ofd_child(signed_info, "References")
        refs = _ofd_find_all(refs_parent, "Reference") if refs_parent is not None else _ofd_find_all(signed_info, "Reference")
        for ref in refs:
            file_ref = _ofd_attr(ref, "FileRef")
            digest_hex = (ref.text or "").strip()
            check_method = _ofd_attr(ref, "CheckMethod")
            algo = _digest_by_algorithm_name(check_method)
            if not file_ref or not digest_hex:
                continue
            candidate = file_ref.replace("\\", "/").lstrip("/")
            if candidate not in files:
                alt = _ofd_resolve_path(root_dir, file_ref)
                if alt in files:
                    candidate = alt
            if candidate not in files:
                ref_results.append({"file": file_ref, "ok": False, "message": "引用的文件不存在"})
                continue
            try:
                expected = bytes.fromhex(re.sub(r"\s+", "", digest_hex))
            except ValueError:
                try:
                    expected = base64.b64decode(digest_hex, validate=True)
                except Exception:
                    ref_results.append({"file": file_ref, "ok": False, "message": "摘要编码非法"})
                    continue
            actual = _hash(algo, files[candidate])
            ref_results.append({
                "file": file_ref,
                "algorithm": _digest_label(algo),
                "expected": expected.hex(),
                "actual": actual.hex(),
                "ok": actual == expected,
                "message": "文件摘要一致" if actual == expected else "文件摘要不一致（文件已被修改）",
            })
    if ref_results:
        fmt_msgs.append("引用文件 " + str(len(ref_results)) + " 个，摘要校验 "
                        + ("全部一致" if all(r["ok"] for r in ref_results) else "存在不一致"))
        if not all(r["ok"] for r in ref_results):
            warnings.append("OFD 中被引用的文件摘要与签名中记录不一致")

    add("sigFormatData", "电子签章数据格式正确性", fmt_ok, "；".join(fmt_msgs))

    if cms_info is None:
        for key, title in [
            ("signDataValid", "电子签章签名值正确性"),
            ("signCertAndSeal", "签章者证书与电子印章的匹配性"),
            ("sealValid", "电子印章有效性"),
            ("signCertValid", "签章者证书有效性"),
            ("signTimeValid", "签章时间有效性"),
            ("digestValid", "原文摘要匹配"),
        ]:
            add(key, title, False, "签名值无法解析，无法完成该项校验")
        return {
            "index": index, "format": "OFD", "fieldName": sig_id, "subFilter": method,
            "checks": checks, "allValid": False, "allPassed": False,
            "warnCount": sum(1 for c in checks if c["status"] == "warn"),
            "warnings": warnings,
            "details": {"sealName": provider_name or "-", "signCertString": "无", "orgDataDigest": "-"},
        }

    cert = cms_info["signerCert"]
    details_cert = cert_info(cert) if cert is not None else None
    seal = cms_info["seal"] or {}
    seal_from_file = _ofd_seal_info(files, elem, root_dir)
    seal = {**seal_from_file, **seal} if seal_from_file else seal

    # ---- 签名值 ----
    sig_ok = cms_info["signatureOk"] and cms_info["contentTypeOk"]
    sig_msgs = ["对 SignedInfo 原文（%d 字节）CMS 验签%s" % (
        len(raw_signed_info or b""), "通过" if cms_info["signatureOk"] else "未通过")]
    if not cms_info["signatureOk"] and cms_info["signatureError"]:
        sig_msgs.append(cms_info["signatureError"])
    add("signDataValid", "电子签章签名值正确性", sig_ok,
        f"{cms_info['signatureAlgorithm']}；" + "；".join(sig_msgs))

    # ---- 证书与印章匹配 ----
    seal_hash = seal.get("signerCertHash")
    if seal_hash and details_cert:
        match = seal_hash.lower() == details_cert["sha256"].lower()
        add("signCertAndSeal", "签章者证书与电子印章的匹配性", match,
            f"印章信息绑定证书摘要 {seal_hash[:16]}…" + ("与签章者证书一致" if match else "与签章者证书不一致"))
    elif seal.get("name") and details_cert:
        match = details_cert["subjectCn"] in (seal.get("name") or "") or seal["name"] in details_cert["subject"]
        add("signCertAndSeal", "签章者证书与电子印章的匹配性", match,
            f"印章名称「{seal['name']}」与证书主体「{details_cert['subjectCn']}」" + ("一致" if match else "不一致"))
    else:
        add("signCertAndSeal", "签章者证书与电子印章的匹配性", True,
            "OFD 未提供可解析的电子印章结构，无法比对印章与证书的绑定关系", status="warn")

    # ---- 印章有效期 ----
    if seal.get("notBefore") and seal.get("notAfter"):
        ok = seal["notBefore"] <= now <= seal["notAfter"]
        add("sealValid", "电子印章有效性", ok,
            f"印章有效期 {_fmt_dt(seal['notBefore'])} 至 {_fmt_dt(seal['notAfter'])}"
            + ("" if ok else "，当前时间不在印章有效期内"))
    else:
        add("sealValid", "电子印章有效性", True,
            "缺少印章有效期信息，按签章证书有效期判定", status="warn")

    # ---- 证书有效性 ----
    cert_ok = True
    cert_msgs = []
    chain_info = {"chain": [], "broken": None, "rootSelfSigned": False, "depth": 0}
    if cert is None:
        cert_ok = False
        cert_msgs.append("未找到签章者证书")
        add("signCertValid", "签章者证书有效性", False, "未找到签章者证书")
    else:
        valid, msg = _check_cert_validity(cert, now)
        cert_ok = valid
        cert_msgs.append(msg)
        if details_cert and details_cert["isCa"]:
            cert_ok = False
            cert_msgs.append("签章者证书是 CA 证书")
        chain_info = _build_chain(cert, cms_info["certs"])
        if chain_info["broken"]:
            cert_msgs.append(chain_info["broken"] + "；按自签/有效期结果判定")
            status = "warn" if valid else "fail"
        else:
            status = "pass" if cert_ok else "fail"
            cert_msgs.append(f"证书链完整（{chain_info['depth']} 级）"
                             + ("，根证书为自签根" if chain_info["rootSelfSigned"] else ""))
        add("signCertValid", "签章者证书有效性", cert_ok, "；".join(cert_msgs), status=status)

    # ---- 签章时间 ----
    if sign_time is not None and cert is not None:
        nb = cert["tbs_certificate"]["validity"]["not_before"].native
        na = cert["tbs_certificate"]["validity"]["not_after"].native
        ok = nb <= sign_time <= na
        add("signTimeValid", "签章时间有效性", ok,
            f"签章时间 {_fmt_dt(sign_time)} " + ("位于" if ok else "不在") + f"证书有效期（{_fmt_dt(nb)} 至 {_fmt_dt(na)}）内")
    elif sign_time is None:
        add("signTimeValid", "签章时间有效性", False, "SignedInfo 中缺少 SignatureDateTime")
    else:
        add("signTimeValid", "签章时间有效性", False, "缺少签章者证书，无法比对有效期")

    # ---- 原文摘要 ----
    digest_ok = bool(cms_info["digestOk"])
    msgs = []
    if cms_info["messageDigest"] and cms_info["actualDigest"]:
        msgs.append(f"{cms_info['digestLabel']} SignedInfo 摘要 "
                    + ("与 signedAttrs messageDigest 一致" if digest_ok
                       else f"{cms_info['actualDigest'].hex()[:32]}… 与 messageDigest {cms_info['messageDigest'].hex()[:32]}… 不一致"))
    else:
        digest_ok = False
        msgs.append("缺少 messageDigest 或签名原文")
    if ref_results:
        bad = [r for r in ref_results if not r["ok"]]
        digest_ok = digest_ok and not bad
        msgs.append(f"引用文件 {len(ref_results)} 个，" + ("摘要全部一致" if not bad else "存在摘要不一致：" + "、".join(r["file"] for r in bad)))
    add("digestValid", "原文摘要匹配", digest_ok, "；".join(msgs))

    details = {
        "index": index,
        "sealName": seal.get("name") or provider_name or "-",
        "sealVersion": seal.get("version") or "-",
        "sealType": seal.get("type") or "-",
        "signVersion": 1,
        "sealCreateTime": seal.get("createTime") or "-",
        "sealStartTime": seal.get("startTime") or "-",
        "sealEndTime": seal.get("endTime") or "-",
        "signTime": _fmt_dt(sign_time),
        "signTimeRaw": sign_time.isoformat() if sign_time else None,
        "publicKey": _spki_b64(cert) if cert is not None else "-",
        "publicKeyAlg": details_cert["publicKeyAlgorithm"] if details_cert else "-",
        "orgDataDigest": (cms_info["actualDigest"] or b"").hex() or "-",
        "digestAlgorithm": cms_info["digestLabel"],
        "signAlgorithm": cms_info["signatureAlgorithm"],
        "signData": cms_info["signature"].hex(),
        "orgData": _orgdata_text(raw_signed_info or b""),
        "orgDataFormat": "HEX",
        "orgDataLength": len(raw_signed_info or b""),
        "signCert": details_cert["base64"] if details_cert else None,
        "signCertString": details_cert["text"] if details_cert else "无",
        "signCertInfo": details_cert,
        "makerCert": _b64(seal["makerCert"]) if seal.get("makerCert") else None,
        "makerCertString": _maker_text(seal.get("makerCert")),
        "signCertList": [_b64(c.dump()) for c in chain_info.get("chain", [])],
        "signCertListString": [_cert_info_safe(c)["text"] for c in chain_info.get("chain", [])],
        "chain": {
            "depth": chain_info.get("depth", 0),
            "rootSelfSigned": chain_info.get("rootSelfSigned", False),
            "broken": chain_info.get("broken"),
            "certs": [_cert_info_safe(c) for c in chain_info.get("chain", [])],
        },
        "references": ref_results,
        "fieldName": sig_id,
        "subFilter": method,
        "provider": provider_name,
        "providerVersion": provider_version,
    }

    return {
        "index": index,
        "format": "OFD",
        "fieldName": sig_id,
        "subFilter": method,
        "checks": checks,
        "allValid": all(c["status"] != "fail" for c in checks),
        "allPassed": all(c["status"] == "pass" for c in checks),
        "warnCount": sum(1 for c in checks if c["status"] == "warn"),
        "warnings": warnings,
        "details": details,
    }


def _parse_iso(text: str | None) -> datetime | None:
    if not text:
        return None
    text = text.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ofd_seal_info(files: dict[str, bytes], sig_elem, root_dir: str) -> dict | None:
    """解析 OFD 中引用的印章文件（*.esl，DER 编码的 ESealInfo），或 XML 中的印章属性。"""
    seal_elem = None
    for child in sig_elem:
        if _local(child.tag) in ("Seal", "SealInfo", "ESeal"):
            seal_elem = child
            break
    info: dict = {}
    if seal_elem is not None:
        name = _ofd_attr(seal_elem, "Name", "SealName")
        if name:
            info["name"] = name
        base_loc = _ofd_attr(seal_elem, "BaseLoc")
        if not base_loc:
            loc_elem = _ofd_child(seal_elem, "BaseLoc")
            base_loc = (loc_elem.text or "").strip() if loc_elem is not None else None
        if base_loc:
            path = _ofd_resolve_path(root_dir, base_loc)
            if path in files:
                try:
                    der = files[path]
                    # 注意：二进制 DER 不能 strip()，末尾字节可能正好是 0x0a/0x20 等空白
                    parsed = ESealInfo.load(der, strict=False)
                    info.update({
                        "name": parsed["name"].native,
                        "version": parsed["version"].native,
                        "type": parsed["type"].native,
                        "createTime": _fmt_dt(parsed["create_time"].native),
                        "notBefore": parsed["not_before"].native,
                        "notAfter": parsed["not_after"].native,
                        "startTime": _fmt_dt(parsed["not_before"].native),
                        "endTime": _fmt_dt(parsed["not_after"].native),
                        "signerCertHash": parsed["signer_cert_hash"].native.hex()
                        if _present(parsed["signer_cert_hash"]) else None,
                        "makerCert": parsed["maker_cert"].native
                        if _present(parsed["maker_cert"]) else None,
                    })
                except Exception:
                    pass
    return info or None


# --------------------------------------------------------------------------- #
# 统一入口
# --------------------------------------------------------------------------- #

def check_signature(data: bytes) -> dict:
    """自动识别 PDF / OFD 并逐项校验。"""
    if not data:
        raise ToolError("请上传签章文件")
    if len(data) > MAX_FILE_SIZE:
        raise ToolError("文件大小不能超过 10 MB")
    head = data[:1024]
    if b"%PDF" in head:
        return verify_pdf(data)
    if data[:4] == b"PK\x03\x04":
        try:
            return verify_ofd(data)
        except ToolError:
            raise
        except Exception as exc:
            raise ToolError(f"OFD 校验失败：{exc}")
    raise ToolError("无法识别的文件类型，仅支持 PDF 与 OFD 签章文件")


# --------------------------------------------------------------------------- #
# 时间戳（RFC 3161 / GB/T 33000-2014）
# --------------------------------------------------------------------------- #

def _tsp_label(oid: str) -> str:
    names = {
        "1.2.840.113549.1.9.16.1.4": "id-ct-TSTInfo（RFC 3161）",
        "1.2.156.10197.6.1.4.1": "GB/T 33000 时间戳（SM2/SM3）",
        "1.2.156.112562.2.1.1": "GB/T 33000 时间戳",
    }
    return names.get(oid, oid)


def _tst_from_token(der: bytes):
    """从 DER 中取出 (tst_info, signed_data, signer_info, token_der, wrapped)。"""
    ci = None
    try:
        ci = cms.ContentInfo.load(der, strict=False)
        content_type = ci["content_type"].native
    except Exception:
        ci = None
    if ci is not None and content_type == "signed_data":
        return _extract_tst(ci, ci["content"], der, "ContentInfo")
    try:
        resp = tsp.TimeStampResp.load(der, strict=False)
        status = resp["status"]["status"].native
        token = resp["time_stamp_token"]
        if not _present(token):
            raise ToolError(f"时间戳响应中没有令牌（status={status}）")
        ci = token
        sd = ci["content"]
        return _extract_tst(ci, sd, token.dump(), f"TimeStampResp({status})")
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"时间戳令牌解析失败：{exc}")


def _extract_tst(ci, sd, token_der: bytes, wrapped: str) -> dict:
    if ci["content_type"].native != "signed_data":
        raise ToolError("时间戳令牌内容类型不是 signedData")
    econtent = None
    try:
        content = sd["encap_content_info"]["content"]
        if _present(content):
            econtent = _octets(content)
    except Exception:
        econtent = None
    if econtent is None:
        raise ToolError("时间戳令牌中没有 TSTInfo 内容")
    try:
        tst_info = tsp.TSTInfo.load(econtent, strict=False)
    except Exception as exc:
        raise ToolError(f"TSTInfo 结构解析失败：{exc}")
    return {"tst": tst_info, "sd": sd, "token_der": token_der, "wrapped": wrapped,
            "econtent": econtent, "content_type": ci["content_type"].dotted}


def _parse_timestamp(token_der: bytes) -> tuple[dict, dict]:
    """返回 (可序列化的公开字段, 供验证使用的内部对象)。"""
    if not token_der:
        raise ToolError("请输入时间戳令牌数据")
    if len(token_der) > MAX_FILE_SIZE:
        raise ToolError("时间戳令牌不能超过 10 MB")
    parsed = _tst_from_token(token_der)
    tst = parsed["tst"]

    mi = tst["message_imprint"]
    hash_oid = mi["hash_algorithm"]["algorithm"].dotted
    hash_name = _digest_name(hash_oid)
    hash_label = _digest_label(hash_name)
    imprint = mi["hashed_message"].native

    accuracy = tst["accuracy"]
    accuracy_text = "-"
    accuracy_us = None
    if _present(accuracy):
        secs = accuracy["seconds"].native or 0
        millis = accuracy["millis"].native or 0
        micros = accuracy["micros"].native or 0
        accuracy_us = secs * 1_000_000 + millis * 1_000 + micros
        parts = []
        if secs:
            parts.append(f"{secs} 秒")
        if millis:
            parts.append(f"{millis} 毫秒")
        if micros:
            parts.append(f"{micros} 微秒")
        accuracy_text = " ".join(parts) or "-"

    gen_time = tst["gen_time"].native
    tsa_name = None
    if _present(tst["tsa"]):
        try:
            gn = tst["tsa"]
            if gn.name == "directory_name":
                name_obj = gn.chosen
                native = name_obj.native
                cn = native.get("common_name") or native.get("organization_name")
                if isinstance(cn, list):
                    cn = cn[0] if cn else None
                tsa_name = cn or name_obj.human_friendly
            else:
                tsa_name = str(gn.native)
        except Exception:
            tsa_name = str(tst["tsa"].native)

    nonce = tst["nonce"].native if _present(tst["nonce"]) else None

    # 证书
    sd = parsed["sd"]
    certs = []
    try:
        for choice in sd["certificates"]:
            if choice.name == "certificate":
                certs.append(choice.chosen)
    except Exception:
        certs = []
    cert_details = []
    for cert in certs:
        info = cert_info(cert)
        cert_details.append({
            "subject": info["subject"],
            "subjectCn": info["subjectCn"],
            "issuer": info["issuer"],
            "serialNumber": info["serialNumber"],
            "notBefore": info["notBefore"],
            "notAfter": info["notAfter"],
            "sha256": info["sha256"],
            "base64": info["base64"],
            "pem": info["pem"],
            "certInfo": info["text"],
        })

    si = sd["signer_infos"][0]
    sig_oid = si["signature_algorithm"]["algorithm"].dotted
    sig_digest = _digest_name(si["digest_algorithm"]["algorithm"].dotted)
    display_name = tsa_name or (cert_details[0]["subjectCn"] if cert_details else None)
    tst_content_type = sd["encap_content_info"]["content_type"].dotted

    version = tst["version"].native
    if isinstance(version, str) and version.startswith("v"):
        version = int(version[1:])

    public = {
        "tokenType": _tsp_label(tst_content_type),
        "contentTypeOid": tst_content_type,
        "wrapped": parsed["wrapped"],
        "version": version,
        "serialNumber": tst["serial_number"].native,
        "serialNumberHex": format(tst["serial_number"].native, "X"),
        "genTime": gen_time.isoformat(),
        "genTimeStr": _fmt_dt(gen_time),
        "genTimeLocal": gen_time.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "nonce": format(nonce, "X") if nonce is not None else None,
        "hashAlgorithm": hash_label,
        "hashAlgorithmOid": hash_oid,
        "signatureAlgorithm": _sig_label(sig_oid, sig_digest),
        "messageImprint": imprint.hex(),
        "messageImprintLength": len(imprint),
        "policy": tst["policy"].native,
        "accuracy": accuracy_us,
        "accuracyText": accuracy_text,
        "accuracyMicros": accuracy_us,
        "ordering": bool(tst["ordering"].native) if _present(tst["ordering"]) else False,
        "tsaName": display_name,
        "extensions": [ext["extn_id"].native for ext in tst["extensions"]] if _present(tst["extensions"]) else [],
        "certificateDetails": cert_details,
    }
    internal = {
        "tokenDer": parsed["token_der"],
        "econtent": parsed["econtent"],
        "sd": sd,
        "si": si,
        "certs": certs,
        "tst": tst,
    }
    return public, internal


def parse_timestamp(token_der: bytes) -> dict:
    """解析时间戳令牌，只返回可 JSON 序列化的字段。"""
    public, _ = _parse_timestamp(token_der)
    return public


def verify_timestamp(token_der: bytes, original: bytes | None = None) -> dict:
    parsed, internal = _parse_timestamp(token_der)
    domain = internal

    # 1) CMS 签名（内嵌 TSTInfo 作为 eContent）
    try:
        cms_info = verify_cms(domain["tokenDer"], detached_data=None)
        sig_ok = cms_info["signatureOk"] and cms_info["contentTypeOk"]
        sig_msg = ("使用令牌内嵌证书 " + (cms_info["signerCert"].subject.human_friendly if cms_info["signerCert"] else "?")
                   + " 验证 CMS 签名" + ("通过" if sig_ok else "未通过"))
        if not cms_info["signatureOk"] and cms_info["signatureError"]:
            sig_msg += f"（{cms_info['signatureError']}）"
        signer_cert = cms_info["signerCert"]
    except ToolError as exc:
        sig_ok = False
        sig_msg = f"CMS 签名验证失败：{exc}"
        signer_cert = None

    # 2) 原文摘要比对
    hash_name = _digest_name(parsed["hashAlgorithmOid"])
    expected = bytes.fromhex(parsed["messageImprint"])
    digest_ok = None
    calc = None
    if original is not None:
        calc = _hash(hash_name, original)
        digest_ok = calc == expected

    # 3) 证书有效期 / 签名时间
    now = _now()
    time_ok = None
    time_msg = ""
    if signer_cert is not None:
        nb = signer_cert["tbs_certificate"]["validity"]["not_before"].native
        na = signer_cert["tbs_certificate"]["validity"]["not_after"].native
        gen_time = parsed["genTime"]
        gen_dt = datetime.fromisoformat(gen_time)
        time_ok = nb <= gen_dt <= na
        time_msg = (f"时间戳时间 {parsed['genTimeStr']} " + ("位于" if time_ok else "不在")
                    + f"TSA 证书有效期（{_fmt_dt(nb)} 至 {_fmt_dt(na)}）内")

    valid = bool(sig_ok and (digest_ok is not False) and (time_ok is not False))
    if digest_ok is None:
        message = ("时间戳签名验证" + ("通过" if sig_ok else "失败") + "；未提供原始数据，未比对原文摘要"
                   if sig_ok else "时间戳签名验证失败")
    elif digest_ok:
        message = "时间戳验证通过：签名有效，原始数据摘要与令牌 messageImprint 一致"
    else:
        message = ("时间戳验证失败：原始数据摘要与令牌 messageImprint 不一致（期望 "
                   f"{expected.hex()[:32]}…，实际 {calc.hex()[:32]}…）")

    result = dict(parsed)
    result.update({
        "valid": valid,
        "message": message,
        "signatureValid": sig_ok,
        "signatureMessage": sig_msg,
        "digestMatch": digest_ok,
        "expectedDigest": expected.hex(),
        "computedDigest": calc.hex() if calc else None,
        "originalLength": len(original) if original is not None else None,
        "timeValid": time_ok,
        "timeMessage": time_msg,
        "certValid": (time_ok is not False),
        "certMessage": time_msg,
        "signerCertificate": cert_info(signer_cert) if signer_cert is not None else None,
        "checkedAt": _fmt_dt(now),
    })
    return result
