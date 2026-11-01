"""生成电子签章 / 时间戳测试夹具（可复现）。

用法::

    cd /opt/cipherbox && .venv/bin/python tests/make_sig_fixtures.py

生成：
    tests/fixtures/signed.pdf      - pyhanko 真实签名（RSA-2048 / SHA-256，含印章信息 signedAttrs）
    tests/fixtures/signed.ofd      - OFD 包（Signatures.xml + SignedValue.dat + Seal.esl，真实 CMS 签名）
    tests/fixtures/timestamp.tsr   - RFC 3161 时间戳令牌（TSA 自签证书 + 真实 CMS 签名）
    tests/fixtures/gb_timestamp.tsr- GB/T 33000-2014 结构时间戳令牌（SM3 摘要）

所有私钥均为脚本内现场生成（不落盘），因此每次运行夹具内容都会变化，
但结构、签名与校验结论稳定。
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from asn1crypto import algos, cms, core, keys, tsp, x509  # noqa: E402
from cryptography import x509 as cx  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter  # noqa: E402
from pyhanko.sign import signers  # noqa: E402
from pyhanko.sign.attributes import CMSAttributeProvider, SignedAttributeProviderSpec  # noqa: E402
from pyhanko.sign.signers import PdfSignatureMetadata  # noqa: E402
from pyhanko_certvalidator.registry import SimpleCertificateStore  # noqa: E402
from pypdf import PdfWriter  # noqa: E402

from app.core import sig as sigcore  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"

VALID_FROM = datetime(2024, 1, 1, tzinfo=timezone.utc)
VALID_TO = datetime(2036, 1, 1, tzinfo=timezone.utc)
SIGN_TIME = datetime(2026, 6, 1, 9, 30, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# 证书
# --------------------------------------------------------------------------- #

def make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_cert(key, common_name: str, org: str = "CipherBox 测试 CA",
              ca: bool = False, valid_from=VALID_FROM, valid_to=VALID_TO) -> bytes:
    subject = cx.Name([
        cx.NameAttribute(cx.NameOID.COUNTRY_NAME, "CN"),
        cx.NameAttribute(cx.NameOID.ORGANIZATION_NAME, org),
        cx.NameAttribute(cx.NameOID.COMMON_NAME, common_name),
    ])
    builder = (
        cx.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(cx.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(cx.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            cx.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True,
        )
    else:
        builder = builder.add_extension(
            cx.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True,
        ).add_extension(
            cx.ExtendedKeyUsage([cx.oid.ExtendedKeyUsageOID.CODE_SIGNING]), critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _store(certs) -> SimpleCertificateStore:
    return SimpleCertificateStore.from_certs(certs)


def private_key_info(key) -> keys.PrivateKeyInfo:
    return keys.PrivateKeyInfo.load(key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def sign_rsa(key, data: bytes) -> bytes:
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


# --------------------------------------------------------------------------- #
# CMS 构造
# --------------------------------------------------------------------------- #

def build_signed_attrs(content_type: str, digest: bytes, when: datetime,
                       extra: list | None = None) -> cms.CMSAttributes:
    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": [content_type]}),
        cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
        cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": core.UTCTime(when)})]}),
    ]
    attrs.extend(extra or [])
    return cms.CMSAttributes(attrs)


def ess_signing_cert_attr(cert_der: bytes) -> cms.CMSAttribute:
    """ESS signing-certificate-v2（RFC 5035），BouncyCastle 校验时间戳时必需。"""
    ess = tsp.SigningCertificateV2({
        "certs": [{"cert_hash": hashlib.sha256(cert_der).digest()}],
    })
    return cms.CMSAttribute({"type": "signing_certificate_v2", "values": [ess]})


def build_cms(content: bytes | None, content_type: str, digest_algo: str,
              signer_cert: bytes, signer_key, extra_attrs: list | None = None,
              extra_certs: list[bytes] | None = None,
              detached: bool = False) -> bytes:
    """构造一个真实的 CMS SignedData（RSA / PKCS#1 v1.5）。"""
    cert = x509.Certificate.load(signer_cert)
    hasher = hashlib.sha256 if digest_algo == "sha256" else (lambda b: hashlib.new("sm3", b))
    data = content or b""
    digest = hasher(data).digest() if not detached else hasher(data).digest()
    if detached:
        digest = hasher(content or b"").digest() if content else None

    attrs = build_signed_attrs(content_type, digest, SIGN_TIME, extra_attrs)
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": {
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
            }
        }),
        "digest_algorithm": {"algorithm": digest_algo},
        "signed_attrs": attrs,
        "signature_algorithm": {"algorithm": "sha256_rsa" if digest_algo == "sha256" else "sha256_rsa"},
        "signature": b"\x00" * 256,
    })
    tbs = b"\x31" + si["signed_attrs"].dump()[1:]
    si["signature"] = sign_rsa(signer_key, tbs)

    certs = [cms.CertificateChoices({"certificate": cert})]
    for der in (extra_certs or []):
        certs.append(cms.CertificateChoices({"certificate": x509.Certificate.load(der)}))

    encap = {"content_type": content_type}
    if not detached:
        encap["content"] = core.ParsableOctetString(content)

    sd = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [{"algorithm": digest_algo}],
        "encap_content_info": encap,
        "certificates": certs,
        "signer_infos": [si],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


# --------------------------------------------------------------------------- #
# SM2（国密）证书与签名：cryptography 不支持 SM2 曲线，这里用 asn1crypto 手工
# 构造 X.509 证书、用 gmssl 完成 SM2 签名，均按 GB/T 32918 规范编码。
# --------------------------------------------------------------------------- #

SM2_SIG_OID = "1.2.156.10197.1.501"
SM2_CURVE_OID = "1.2.156.10197.1.301"
SM3_OID = "1.2.156.10197.1.401"


def make_sm2_keypair() -> tuple[str, str]:
    from gmssl import sm2 as gm_sm2
    from gmssl import func

    private_hex = func.random_hex(64)
    helper = gm_sm2.CryptSM2(private_key=private_hex, public_key="0" * 128)
    public_hex = helper._kg(int(private_hex, 16), helper.ecc_table["g"])
    # _kg 可能丢掉前导 0，导致 x||y 不足 128 位十六进制，必须补齐
    return private_hex, public_hex.rjust(128, "0")


def _sm2_engine(private_hex: str, public_hex: str):
    from gmssl import sm2 as gm_sm2

    engine = gm_sm2.CryptSM2(private_key=private_hex, public_key="0" * 128)
    # gmssl 构造时会对以 "04" 开头的公钥做 lstrip("04")，这里直接赋值避免截断
    engine.public_key = public_hex.rjust(128, "0")
    return engine


def sm2_sign_der(private_hex: str, public_hex: str, data: bytes) -> bytes:
    engine = _sm2_engine(private_hex, public_hex)
    raw = engine.sign_with_sm3(data)
    return sigcore.EcdsaSignature({
        "r": int(raw[:64], 16),
        "s": int(raw[64:], 16),
    }).dump()


def make_sm2_cert(private_hex: str, public_hex: str, common_name: str,
                  org: str = "CipherBox 测试有限公司") -> bytes:
    spki = keys.PublicKeyInfo({
        "algorithm": keys.PublicKeyAlgorithm({
            "algorithm": "ec",
            "parameters": keys.ECDomainParameters({"named": SM2_CURVE_OID}),
        }),
        "public_key": bytes.fromhex("04" + public_hex.rjust(128, "0")),
    })
    name = x509.Name.build({"common_name": common_name, "organization_name": org})
    tbs = x509.TbsCertificate({
        "version": "v3",
        "serial_number": cx.random_serial_number() >> 8,
        "signature": algos.SignedDigestAlgorithm({"algorithm": SM2_SIG_OID}),
        "issuer": name,
        "subject": name,
        "validity": {
            "not_before": x509.Time({"utc_time": core.UTCTime(VALID_FROM)}),
            "not_after": x509.Time({"utc_time": core.UTCTime(VALID_TO)}),
        },
        "subject_public_key_info": spki,
    })
    signature = sm2_sign_der(private_hex, public_hex, tbs.dump())
    cert = x509.Certificate({
        "tbs_certificate": tbs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": SM2_SIG_OID}),
        "signature_value": core.OctetBitString(signature),
    })
    return cert.dump()


def build_cms_sm2(content: bytes, content_type: str, signer_cert: bytes,
                  private_hex: str, public_hex: str, extra_attrs: list | None = None,
                  extra_certs: list[bytes] | None = None, detached: bool = False) -> bytes:
    """SM3 + SM2 的 CMS SignedData（detached 时签名原文为 SignedInfo）。"""
    cert = x509.Certificate.load(signer_cert)
    digest = hashlib.new("sm3", content).digest()
    attrs = build_signed_attrs(content_type, digest, SIGN_TIME, extra_attrs)
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": {
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
            }
        }),
        "digest_algorithm": {"algorithm": SM3_OID},
        "signed_attrs": attrs,
        "signature_algorithm": {"algorithm": SM2_SIG_OID},
        "signature": b"\x00" * 72,
    })
    tbs = b"\x31" + si["signed_attrs"].dump()[1:]
    si["signature"] = sm2_sign_der(private_hex, public_hex, tbs)

    certs = [cms.CertificateChoices({"certificate": cert})]
    for der in (extra_certs or []):
        certs.append(cms.CertificateChoices({"certificate": x509.Certificate.load(der)}))

    encap = {"content_type": content_type}
    if not detached:
        encap["content"] = core.ParsableOctetString(content)

    sd = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [{"algorithm": SM3_OID}],
        "encap_content_info": encap,
        "certificates": certs,
        "signer_infos": [si],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()



# --------------------------------------------------------------------------- #
# PDF 签章
# --------------------------------------------------------------------------- #

class _SealProvider(CMSAttributeProvider):
    attribute_type = sigcore.SEAL_ATTR_OID

    def __init__(self, seal_der: bytes):
        self.seal_der = seal_der

    async def build_attr_value(self, dry_run=False):
        return None

    async def get_attribute(self, dry_run=False):
        return cms.CMSAttribute({
            "type": self.attribute_type,
            "values": [sigcore.ESealInfo.load(self.seal_der)],
        })


class _SealSpec(SignedAttributeProviderSpec):
    def __init__(self, seal_der: bytes):
        self.seal_der = seal_der

    def signed_attr_providers(self, data_digest, digest_algorithm):
        yield _SealProvider(self.seal_der)


def build_seal(signer_cert: bytes, maker_cert: bytes, name: str = "CipherBox 测试电子印章") -> bytes:
    seal = sigcore.ESealInfo({
        "name": name,
        "version": 1,
        "type": "企业公章",
        "create_time": core.GeneralizedTime(datetime(2025, 1, 10, 8, 0, 0, tzinfo=timezone.utc)),
        "not_before": core.GeneralizedTime(datetime(2025, 1, 10, 8, 0, 0, tzinfo=timezone.utc)),
        "not_after": core.GeneralizedTime(datetime(2035, 1, 10, 8, 0, 0, tzinfo=timezone.utc)),
        "signer_cert_hash": hashlib.sha256(signer_cert).digest(),
        "maker_cert": maker_cert,
    })
    return seal.dump()


def build_signed_pdf() -> bytes:
    base = PdfWriter()
    base.add_blank_page(width=595, height=842)
    buf = io.BytesIO()
    base.write(buf)

    signer_key = make_key()
    maker_key = make_key()
    signer_cert = make_cert(signer_key, "CipherBox 测试签章者", org="CipherBox 测试有限公司", ca=False)
    maker_cert = make_cert(maker_key, "CipherBox 测试制章者", org="CipherBox 测试有限公司", ca=True)

    simple = signers.SimpleSigner(
        signing_cert=x509.Certificate.load(signer_cert),
        signing_key=private_key_info(signer_key),
        cert_registry=_store([x509.Certificate.load(signer_cert)]),
        signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
        embed_roots=True,
    )
    simple.signed_attr_prov_spec = _SealSpec(build_seal(signer_cert, maker_cert))

    writer = IncrementalPdfFileWriter(io.BytesIO(buf.getvalue()))
    meta = PdfSignatureMetadata(field_name="Signature1", md_algorithm="sha256")
    out = io.BytesIO()
    signers.sign_pdf(writer, signature_meta=meta, signer=simple, output=out)
    return out.getvalue()


# --------------------------------------------------------------------------- #
# OFD 签章
# --------------------------------------------------------------------------- #

OFD_NS = "http://www.ofdspec.org/2016"

OFD_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<ofd:OFD xmlns:ofd="{OFD_NS}" DocType="OFD" Version="1.0">
  <ofd:DocBody>
    <ofd:DocInfo>
      <ofd:DocID>cipherbox-fixture-0001</ofd:DocID>
      <ofd:Title>CipherBox 签章测试文件</ofd:Title>
      <ofd:Author>CipherBox</ofd:Author>
    </ofd:DocInfo>
    <ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot>
    <ofd:Signatures>Signs/Signatures.xml</ofd:Signatures>
  </ofd:DocBody>
</ofd:OFD>
"""

OFD_DOCUMENT = f"""<?xml version="1.0" encoding="UTF-8"?>
<ofd:Document xmlns:ofd="{OFD_NS}">
  <ofd:CommonData>
    <ofd:MaxUnitID>3</ofd:MaxUnitID>
    <ofd:PageArea><ofd:PhysicalBox>0 0 210 297</ofd:PhysicalBox></ofd:PageArea>
  </ofd:CommonData>
  <ofd:Pages>
    <ofd:Page ID="2" BaseLoc="Pages/Page_0/Content.xml"/>
  </ofd:Pages>
</ofd:Document>
"""

OFD_CONTENT = f"""<?xml version="1.0" encoding="UTF-8"?>
<ofd:Page xmlns:ofd="{OFD_NS}">
  <ofd:Content>
    <ofd:Layer ID="3">
      <ofd:TextObject ID="4" Boundary="20 20 170 20" Size="10">CipherBox 电子签章测试文档</ofd:TextObject>
    </ofd:Layer>
  </ofd:Content>
</ofd:Page>
"""


def build_signed_ofd() -> bytes:
    signer_priv, signer_pub = make_sm2_keypair()
    maker_priv, maker_pub = make_sm2_keypair()
    signer_cert = make_sm2_cert(signer_priv, signer_pub, "CipherBox OFD 签章者")
    maker_cert = make_sm2_cert(maker_priv, maker_pub, "CipherBox OFD 制章者")
    seal_der = build_seal(signer_cert, maker_cert, "CipherBox OFD 测试印章")

    files = {
        "Doc_0/Document.xml": OFD_DOCUMENT.encode("utf-8"),
        "Doc_0/Pages/Page_0/Content.xml": OFD_CONTENT.encode("utf-8"),
    }

    refs = []
    for name, payload in files.items():
        refs.append(
            f'    <ofd:Reference FileRef="{name}" CheckMethod="SHA256">'
            f'{hashlib.sha256(payload).hexdigest()}</ofd:Reference>'
        )

    signed_info = (
        '<ofd:SignedInfo>\n'
        '  <ofd:Provider ProviderName="CipherBox 测试签章系统" Version="1.0" Company="CipherBox"/>\n'
        '  <ofd:SignatureMethod>SM3withSM2</ofd:SignatureMethod>\n'
        f'  <ofd:SignatureDateTime>{SIGN_TIME.strftime("%Y-%m-%dT%H:%M:%SZ")}</ofd:SignatureDateTime>\n'
        '  <ofd:References>\n'
        + "\n".join(refs) + "\n"
        '  </ofd:References>\n'
        '</ofd:SignedInfo>'
    )
    signed_info_bytes = signed_info.encode("utf-8")

    cms_der = build_cms_sm2(signed_info_bytes, "data", signer_cert, signer_priv, signer_pub, detached=True)
    signatures_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<ofd:Signatures xmlns:ofd="{OFD_NS}">\n'
        '  <ofd:Signature ID="sig1">\n'
        '    ' + signed_info + "\n"
        f'    <ofd:SignedValue>{base64.b64encode(cms_der).decode()}</ofd:SignedValue>\n'
        '    <ofd:Seal BaseLoc="Seal.esl"/>\n'
        '  </ofd:Signature>\n'
        '</ofd:Signatures>\n'
    ).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("OFD.xml", OFD_XML)
        for name, payload in files.items():
            zf.writestr(name, payload)
        zf.writestr("Signs/Signatures.xml", signatures_xml)
        zf.writestr("Signs/SignedValue.dat", cms_der)
        zf.writestr("Signs/Seal.esl", seal_der)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# 时间戳令牌
# --------------------------------------------------------------------------- #

def build_timestamp_token(content: bytes, digest_algo: str = "sha256",
                          policy: str = "1.3.6.1.4.1.55555.1.1",
                          gen_time: datetime | None = None) -> tuple[bytes, bytes]:
    """返回 (token_der, tsa_cert_der)。"""
    gen_time = gen_time or SIGN_TIME
    tsa_key = make_key()
    tsa_cert = make_cert(tsa_key, "CipherBox 测试 TSA", org="CipherBox 测试时间戳服务中心")

    hasher = hashlib.sha256 if digest_algo == "sha256" else (lambda b: hashlib.new("sm3", b))
    digest_alg_id = "sha256" if digest_algo == "sha256" else "1.2.156.10197.1.401"
    imprint = hasher(content).digest()

    tsa_name = x509.Name.build({"common_name": "CipherBox 测试 TSA", "organization_name": "CipherBox 测试时间戳服务中心"})
    tst = tsp.TSTInfo({
        "version": 1,
        "policy": policy,
        "message_imprint": {
            "hash_algorithm": {"algorithm": digest_alg_id},
            "hashed_message": imprint,
        },
        "serial_number": 2026060100001,
        "gen_time": core.GeneralizedTime(gen_time),
        "accuracy": {"seconds": 0, "millis": 100},
        "ordering": False,
        "nonce": 0x5A5A5A5A,
        "tsa": {"directory_name": tsa_name},
    })
    tst_der = tst.dump()

    cert_asn1 = x509.Certificate.load(tsa_cert)
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": {
                "issuer": cert_asn1.issuer,
                "serial_number": cert_asn1.serial_number,
            }
        }),
        "digest_algorithm": {"algorithm": digest_alg_id},
        "signature_algorithm": {"algorithm": "sha256_rsa"},
        "signature": b"\x00" * 256,
    })
    attrs = build_signed_attrs("tst_info", hashlib.sha256(tst_der).digest(), gen_time,
                               extra=[ess_signing_cert_attr(tsa_cert)])
    si["signed_attrs"] = attrs
    si["signature"] = sign_rsa(tsa_key, b"\x31" + si["signed_attrs"].dump()[1:])

    sd = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": digest_alg_id}],
        "encap_content_info": {
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_der),
        },
        "certificates": [cms.CertificateChoices({"certificate": cert_asn1})],
        "signer_infos": [si],
    })
    token = cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()
    return token, tsa_cert


def build_gb_timestamp_token(content: bytes) -> tuple[bytes, bytes]:
    """GB/T 33000-2014 结构：TSTInfo + SM3 摘要 + SM2 签名 + 国密策略 OID。"""
    gen_time = SIGN_TIME
    tsa_priv, tsa_pub = make_sm2_keypair()
    tsa_cert = make_sm2_cert(tsa_priv, tsa_pub, "CipherBox 国密 TSA", org="CipherBox 测试时间戳服务中心")
    imprint = hashlib.new("sm3", content).digest()
    tsa_name = x509.Name.build({"common_name": "CipherBox 国密 TSA", "organization_name": "CipherBox 测试时间戳服务中心"})
    tst = tsp.TSTInfo({
        "version": 1,
        "policy": "1.2.156.10197.6.1.4.1.1",
        "message_imprint": {
            "hash_algorithm": {"algorithm": SM3_OID},
            "hashed_message": imprint,
        },
        "serial_number": 2026060100002,
        "gen_time": core.GeneralizedTime(gen_time),
        "accuracy": {"seconds": 0, "millis": 10},
        "ordering": True,
        "nonce": 0x11223344,
        "tsa": {"directory_name": tsa_name},
    })
    tst_der = tst.dump()
    cert_asn1 = x509.Certificate.load(tsa_cert)
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": {
                "issuer": cert_asn1.issuer,
                "serial_number": cert_asn1.serial_number,
            }
        }),
        "digest_algorithm": {"algorithm": SM3_OID},
        "signature_algorithm": {"algorithm": SM2_SIG_OID},
        "signature": b"\x00" * 72,
    })
    si["signed_attrs"] = build_signed_attrs("tst_info", imprint, gen_time,
                                            extra=[ess_signing_cert_attr(tsa_cert)])
    si["signature"] = sm2_sign_der(tsa_priv, tsa_pub, b"\x31" + si["signed_attrs"].dump()[1:])
    sd = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": SM3_OID}],
        "encap_content_info": {"content_type": "tst_info", "content": core.ParsableOctetString(tst_der)},
        "certificates": [cms.CertificateChoices({"certificate": cert_asn1})],
        "signer_infos": [si],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump(), tsa_cert


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #

def generate_all(write: bool = True) -> dict[str, bytes]:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    pdf = build_signed_pdf()
    ofd = build_signed_ofd()
    ts_token, _ = build_timestamp_token(b"A demo message for timestamp verification.")
    gb_token, _ = build_gb_timestamp_token(b"A demo message for timestamp verification.")

    data = {
        "signed.pdf": pdf,
        "signed.ofd": ofd,
        "timestamp.tsr": ts_token,
        "gb_timestamp.tsr": gb_token,
    }
    if write:
        for name, payload in data.items():
            (FIXTURES / name).write_bytes(payload)
    return data


if __name__ == "__main__":
    data = generate_all()
    for name, payload in data.items():
        print(f"{name}: {len(payload)} bytes")

    # 自检：三个夹具必须被本地实现判定为通过
    for name in ("signed.pdf", "signed.ofd"):
        result = sigcore.check_signature(data[name])
        sig = result["signatures"][0]
        print(f"[{name}] 校验项：", [(c["key"], c["status"]) for c in sig["checks"]])
        assert sig["allValid"], [c for c in sig["checks"] if not c["ok"]]

    parsed = sigcore.parse_timestamp(data["timestamp.tsr"])
    print("[timestamp.tsr] 版本", parsed["version"], "TSA", parsed["tsaName"], "摘要算法", parsed["hashAlgorithm"])
    verified = sigcore.verify_timestamp(data["timestamp.tsr"], b"A demo message for timestamp verification.")
    assert verified["valid"] and verified["signatureValid"] and verified["digestMatch"]
    print("[timestamp.tsr] 验证通过：", verified["message"])
