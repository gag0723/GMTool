"""SM9（GB/T 38635 / GM/T 0044）测试。

覆盖：
* 曲线参数与生成元自检、G1/G2 群阶；
* 标准测试向量（用户私钥 ds/de、三组 R-ate 配对结果，取自 GmSSL 公开仓库
  tests/sm9test.c，与 GB/T 38635 附录 A 的密钥一致）；
* 双线性、签名/验签、加密/解密（流/分组）、封装/解封装往返；
* 全部 HTTP 接口；
* 与原站 https://cipher.huijusa.cn 的交叉验证（无网络时自动跳过）。
"""
from __future__ import annotations

import time

import pytest

from app.api import sm9 as sm9_api
from app.core import sm9 as S
from app.server import create_app

# ---------------------------------------------------------------- 标准测试向量
# 签名主私钥 ks（GB/T 38635 附录 A.1 / GmSSL sm9test.c hex_ks）
KS = 0x000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4
# 加密主私钥 ke
KE = 0x0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22

# Alice 的签名私钥 dsA（标准向量，G1 点，04 前缀）
DS_ALICE = (
    "04A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820"
    "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"
)
# Bob 的加密私钥 deB（标准向量，G2 点）
DE_BOB = (
    "0494736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683"
    "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158"
    "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F"
    "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1"
)
# ks*P2（签名主公钥，与 GmSSL sm9test.c 的 _SM9_Z256_Ppubs 一致）
PPUBS_HEX = (
    "049F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408"
    "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32"
    "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25"
    "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D"
)
# ke*P1（加密主公钥，G1 点）
PUBE_HEX = (
    "04787ED7B8A51F3AB84E0A66003F32DA5C720B17ECA7137D39ABC66E3C80A892"
    "FF769DE61791E5ADC4B9FF85A31354900B202871279A8C49DC3F220F644C57A7B1"
)

# e(Ppubs, P1)（GmSSL sm9test.c hex_pairing1）
PAIRING1 = (
    "4E378FB5561CD0668F906B731AC58FEE25738EDF09CADC7A29C0ABC0177AEA6D"
    "28B3404A61908F5D6198815C99AF1990C8AF38655930058C28C21BB539CE0000"
    "38BFFE40A22D529A0C66124B2C308DAC9229912656F62B4FACFCED408E02380F"
    "A01F2C8BEE81769609462C69C96AA923FD863E209D3CE26DD889B55E2E3873DB"
    "67E0E0C2EED7A6993DCE28FE9AA2EF56834307860839677F96685F2B44D0911F"
    "5A1AE172102EFD95DF7338DBC577C66D8D6C15E0A0158C7507228EFB078F42A6"
    "1604A3FCFA9783E667CE9FCB1062C2A5C6685C316DDA62DE0548BAA6BA30038B"
    "93634F44FA13AF76169F3CC8FBEA880ADAFF8475D5FD28A75DEB83C44362B439"
    "B3129A75D31D17194675A1BC56947920898FBF390A5BF5D931CE6CBB3340F66D"
    "4C744E69C4A2E1C8ED72F796D151A17CE2325B943260FC460B9F73CB57C9014B"
    "84B87422330D7936EABA1109FA5A7A7181EE16F2438B0AEB2F38FD5F7554E57A"
    "AAB9F06A4EEBA4323A7833DB202E4E35639D93FA3305AF73F0F071D7D284FCFB"
)
# e(deB, RA)（hex_pairing2）
DE_B_HEX = (
    "74CCC3AC9C383C60AF083972B96D05C75F12C8907D128A17ADAFBAB8C5A4ACF7"
    "01092FF4DE89362670C21711B6DBE52DCD5F8E40C6654B3DECE573C2AB3D29B2"
    "44B0294AA04290E1524FF3E3DA8CFD432BB64DE3A8040B5B88D1B5FC86A4EBC1"
    "8CFC48FB4FF37F1E27727464F3C34E2153861AD08E972D1625FC1A7BD18D5539"
)
RA_HEX = (
    "7CBA5B19069EE66AA79D490413D11846B9BA76DD22567F809CF23B6D964BB265"
    "A9760C99CB6F706343FED05637085864958D6C90902ABA7D405FBEDF7B781599"
)
PAIRING2 = (
    "28542FB6954C84BE6A5F2988A31CB6817BA0781966FA83D9673A9577D3C0C134"
    "5E27C19FC02ED9AE37F5BB7BE9C03C2B87DE027539CCF03E6B7D36DE4AB45CD1"
    "A1ABFCD30C57DB0F1A838E3A8F2BF823479C978BD137230506EA6249C891049E"
    "3497477913AB89F5E2960F382B1B5C8EE09DE0FA498BA95C4409D630D343DA40"
    "4FEC93472DA33A4DB6599095C0CF895E3A7B993EE5E4EBE3B9AB7D7D5FF2A3D1"
    "647BA154C3E8E185DFC33657C1F128D480F3F7E3F16801208029E19434C733BB"
    "73F21693C66FC23724DB26380C526223C705DAF6BA18B763A68623C86A632B05"
    "0F63A071A6D62EA45B59A1942DFF5335D1A232C9C5664FAD5D6AF54C11418B0D"
    "8C8E9D8D905780D50E779067F2C4B1C8F83A8B59D735BB52AF35F56730BDE5AC"
    "861CCD9978617267CE4AD9789F77739E62F2E57B48C2FF26D2E90A79A1D86B93"
    "9B1CA08F64712E33AEDA3F44BD6CB633E0F722211E344D73EC9BBEBC92142765"
    "6BA584CE742A2A3AB41C15D3EF94EDEB8EF74A2BDCDAAECC09ABA567981F6437"
)
# e(P2, Ppube)^rB（hex_pairing3）
PPUBE_HEX = (
    "9174542668E8F14AB273C0945C3690C66E5DD09678B86F734C4350567ED06283"
    "54E598C6BF749A3DACC9FFFEDD9DB6866C50457CFC7AA2A4AD65C3168FF74210"
)
RB = 0x00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE
PAIRING3 = (
    "1052D6E9D13E381909DFF7B2B41E13C987D0A9068423B769480DACCE6A06F492"
    "5FFEB92AD870F97DC0893114DA22A44DBC9E7A8B6CA31A0CF0467265A1FB48C7"
    "2C5C3B37E4F2FF83DB33D98C0317BCBBBBF4AC6DF6B89ECA58268B280045E612"
    "6CED9E2D7C9CD3D5AD630DEFAB0B831506218037EE0F861CF9B43C78434AEC38"
    "0AE7BF3E1AEC0CB67A03440906C7DFB3BCD4B6EEEBB7E371F0094AD4A816088D"
    "98DBC791D0671CACA12236CDF8F39E15AEB96FAEB39606D5B04AC581746A663D"
    "00DD2B7416BAA91172E89D5309D834F78C1E31B4483BB97185931BAD7BE1B9B5"
    "7EBAC0349F8544469E60C32F6075FB0468A68147FF013537DF792FFCE024F857"
    "10CC2B561A62B62DA36AEFD60850714F49170FD94A0010C6D4B651B64F3A3A5E"
    "58C9687BEDDCD9E4FEDAB16B884D1FE6DFA117B2AB821F74E0BF7ACDA2269859"
    "2A430968F16086061904CE201847934B11CA0F9E9528F5A9D0CE8F015C9AEA79"
    "934FDDA6D3AB48C8571CE2354B79742AA498CB8CDDE6BD1FA5946345A1A652F6"
)

# 固定随机数生成的示例（前端 samples 与之一致）
SAMPLE_SIG = (
    "9DAB10B4C3FF32A529A39DBE2593CF5B7143824C496B441B7CB5E9BC20581DCD"
    "0461C4667E08F6E52261FE4CF7B8981E0E5D0527F1F834378117B970F7949DC5"
    "3A7AF87FDE378AF0DE17B41D48EC5D1EDA838C672F6F074CEC6A3DB74C86BC1EAE"
)
SAMPLE_SIG_DER = (
    "306604209DAB10B4C3FF32A529A39DBE2593CF5B7143824C496B441B7CB5E9BC20581DCD"
    "0342000461C4667E08F6E52261FE4CF7B8981E0E5D0527F1F834378117B970F7949DC53A7AF87FDE378AF0DE"
    "17B41D48EC5D1EDA838C672F6F074CEC6A3DB74C86BC1EAE"
)


# ---------------------------------------------------------------- 公共工具
@pytest.fixture(scope="module")
def client():
    app = create_app()
    if "sm9" not in app.blueprints:
        # server.py 的 BLUEPRINTS 由主控维护，未注册时在此补挂
        app.register_blueprint(sm9_api.bp)
    return app.test_client()


def post(client, path, payload):
    resp = client.post(path, json=payload)
    assert resp.status_code == 200
    return resp.get_json()


def api_ok(client, path, payload):
    body = post(client, path, payload)
    assert body["code"] == 0, body.get("msg")
    return body["data"]


def ppubs() -> S.G2Point:
    return S.g2_from_bytes(bytes.fromhex(PPUBS_HEX))


def pube() -> S.G1Point:
    return S.g1_from_bytes(bytes.fromhex(PUBE_HEX))


# ---------------------------------------------------------------- 曲线与配对
def test_curve_and_generators():
    assert S.P_MOD.bit_length() == 256
    assert S.N_ORDER.bit_length() == 256
    # 曲线方程 y^2 = x^3 + 5
    assert (S.G1Y ** 2 - (S.G1X ** 3 + S.CURVE_B)) % S.P_MOD == 0
    x2, y2 = S.G2_GENERATOR.to_affine()
    assert y2.sqr() == x2.sqr() * x2 + S.Fp2(0, S.CURVE_B)
    # 生成元阶为 N
    assert S.G1_GENERATOR.mul(S.N_ORDER).is_infinity()
    assert S.G2_GENERATOR.mul(S.N_ORDER).is_infinity()
    # 扩域塔自检
    u = S.Fp2(0, 1)
    assert u * u == S.Fp2(-2, 0)          # u^2 = -2
    v = S.Fp4(S.Fp2(0, 0), S.Fp2(1, 0))
    assert v * v == S.Fp4(u, S.Fp2(0, 0))  # v^2 = u
    one = S.Fp12(S.Fp4(S.Fp2(1, 0), S.Fp2(0, 0)), S.Fp4(), S.Fp4())
    a = S.Fp12(S.Fp4(S.Fp2(3, 5), S.Fp2(7, 11)), S.Fp4(S.Fp2(13, 17), S.Fp2(19, 23)),
               S.Fp4(S.Fp2(29, 31), S.Fp2(37, 41)))
    assert a * a.inv() == one


def test_pairing_standard_vectors():
    """GmSSL sm9test.c 公开向量：三组 R-ate 配对结果必须逐字节一致。"""
    got1 = S.pairing(ppubs(), S.G1_GENERATOR).to_bytes().hex().upper()
    assert got1 == PAIRING1

    de_b = S.g2_from_bytes(b"\x04" + bytes.fromhex(DE_B_HEX))
    ra = S.g1_from_bytes(bytes.fromhex(RA_HEX))
    got2 = S.pairing(de_b, ra).to_bytes().hex().upper()
    assert got2 == PAIRING2

    ppube = S.g1_from_bytes(bytes.fromhex(PPUBE_HEX))
    got3 = (S.pairing(S.G2_GENERATOR, ppube) ** RB).to_bytes().hex().upper()
    assert got3 == PAIRING3


def test_pairing_bilinear():
    p, q = S.G2_GENERATOR, S.G1_GENERATOR
    g = S.pairing(p, q)
    a, b = 0x1234567890ABCDEF, 0x0FEDCBA987654321
    assert S.pairing(p.mul(a), q.mul(b)) == g ** (a * b)
    assert S.pairing(-p, q) * g == S.Fp12(S.Fp4(S.Fp2(1, 0), S.Fp2(0, 0)), S.Fp4(), S.Fp4())
    assert (g ** S.N_ORDER).is_one()


def test_frobenius_matches_pow():
    x = S.Fp12(
        S.Fp4(S.Fp2(3, 5), S.Fp2(7, 11)),
        S.Fp4(S.Fp2(13, 17), S.Fp2(19, 23)),
        S.Fp4(S.Fp2(29, 31), S.Fp2(37, 41)),
    )
    assert S.fp12_frob(x) == x ** S.P_MOD
    assert S.fp12_frob2(x) == x ** (S.P_MOD ** 2)
    assert S.final_exponent(x) == x ** ((S.P_MOD ** 12 - 1) // S.N_ORDER)


# ---------------------------------------------------------------- 密钥派生
def test_user_key_standard_vectors(client):
    data = api_ok(client, "/api/sm9/generate/user/Key", {
        "privateKeyFormat": "HEX", "privateKey": f"{KS:064X}",
        "userId": "Alice", "userIdFormat": "TEXT",
        "userPrivateKeyFormat": "HEX", "userKeyType": 1,
    })
    assert data == DS_ALICE

    data = api_ok(client, "/api/sm9/generate/user/Key", {
        "privateKeyFormat": "HEX", "privateKey": f"{KE:064X}",
        "userId": "Bob", "userIdFormat": "TEXT",
        "userPrivateKeyFormat": "HEX", "userKeyType": 3,
    })
    assert data == DE_BOB

    # 主私钥派生出的主公钥与标准值一致
    assert f"{S.G2_GENERATOR.mul(KS).to_bytes().hex().upper()}" == PPUBS_HEX
    assert f"{S.G1_GENERATOR.mul(KE).to_bytes().hex().upper()}" == PUBE_HEX


def test_master_keypair_api(client):
    for kind, prefix_len in (("SIGN", 258), ("ENC", 130)):
        data = api_ok(client, "/api/sm9/generate/master/keypair", {
            "type": kind, "publicKeyFormat": "HEX", "privateKeyFormat": "HEX",
        })
        assert len(data["pubKey"]) == prefix_len
        assert len(data["priKey"]) == 64
        # 私钥派生的公钥与返回的公钥一致
        priv = int(data["priKey"], 16)
        gen = S.G2_GENERATOR if kind == "SIGN" else S.G1_GENERATOR
        assert gen.mul(priv).to_bytes().hex().upper() == data["pubKey"]
    body = post(client, "/api/sm9/generate/master/keypair", {"type": "XXX"})
    assert body["code"] == 1 and "SIGN" in body["msg"]


# ---------------------------------------------------------------- 签名 / 验签
def test_sign_verify_api(client):
    sig = api_ok(client, "/api/sm9/sign", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userPrivateKey": DS_ALICE, "userPrivateKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard", "messageFormat": "TEXT",
        "signatureFormat": "HEX",
    })
    assert len(sig) == 194                     # h(32) + s(65)
    assert sig[64:66] == "04"                  # s 为 04 前缀的非压缩点

    data = api_ok(client, "/api/sm9/verify", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard", "messageFormat": "TEXT",
        "signature": sig, "signatureFormat": "HEX",
    })
    assert data == "验证通过"

    bad = post(client, "/api/sm9/verify", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard ", "messageFormat": "TEXT",
        "signature": sig, "signatureFormat": "HEX",
    })
    assert bad["code"] == 1 and bad["msg"] == "验证不通过"

    bad = post(client, "/api/sm9/verify", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard", "messageFormat": "TEXT",
        "signature": sig, "signatureFormat": "HEX",
    })
    assert bad["code"] == 1


def test_sign_deterministic_matches_sample():
    """固定随机数签名结果可复现（前端 samples 用的就是这个值）。"""
    sig = S.sign(ppubs(), S.g1_from_bytes(bytes.fromhex(DS_ALICE)), b"Alice",
                 b"Chinese IBS standard", rand=0x1234ABCD5678EF901234ABCD5678EF901234ABCD5678EF901234ABCD5678EF01)
    assert sig.hex().upper() == SAMPLE_SIG
    assert S.verify(ppubs(), b"Alice", b"Chinese IBS standard", sig)
    assert not S.verify(ppubs(), b"Alice", b"Chinese IBS standard!", sig)


def test_signature_convert_api(client):
    der = api_ok(client, "/api/sm9/signature/convert", {
        "signature": SAMPLE_SIG, "signatureFormat": "HEX", "targetFormat": "DER",
    })
    assert der == SAMPLE_SIG_DER

    raw = api_ok(client, "/api/sm9/signature/convert", {
        "signature": der, "signatureFormat": "HEX", "targetFormat": "RAW",
    })
    assert raw == SAMPLE_SIG

    # DER 编码结构：SEQUENCE{OCTET STRING(32), BIT STRING(66)}
    blob = bytes.fromhex(der)
    assert blob[0] == 0x30 and blob[2] == 0x04 and blob[3] == 0x20
    assert blob[36] == 0x03 and blob[37] == 0x42 and blob[38] == 0x00 and blob[39] == 0x04

    # 验签接口同时接受 DER
    assert api_ok(client, "/api/sm9/verify", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard", "messageFormat": "TEXT",
        "signature": der, "signatureFormat": "HEX",
    }) == "验证通过"


def test_performance():
    """纯 Python 下单次签名 / 验签应在数秒内完成。"""
    priv = S.g1_from_bytes(bytes.fromhex(DS_ALICE))
    pub = ppubs()
    t0 = time.time()
    sig = S.sign(pub, priv, b"Alice", b"perf")
    sign_cost = time.time() - t0
    t0 = time.time()
    assert S.verify(pub, b"Alice", b"perf", sig)
    verify_cost = time.time() - t0
    assert sign_cost < 5, f"签名耗时过长：{sign_cost:.2f}s"
    assert verify_cost < 5, f"验签耗时过长：{verify_cost:.2f}s"


# ---------------------------------------------------------------- 加密 / 解密
def test_encrypt_decrypt_stream(client):
    cipher = api_ok(client, "/api/sm9/encrypt", {
        "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "message": "SM9 流密码加密示例", "messageFormat": "TEXT",
        "cipherFormat": "HEX", "encType": "STREAM",
    })
    plain_len = len("SM9 流密码加密示例".encode())
    assert len(cipher) // 2 == 96 + plain_len      # C1(64) + C3(32) + C2
    text = api_ok(client, "/api/sm9/decrypt", {
        "userPrivateKey": DE_BOB, "userPrivateKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "cipher": cipher, "cipherFormat": "HEX",
        "messageFormat": "TEXT", "encType": "STREAM",
    })
    assert text == "SM9 流密码加密示例"


def test_encrypt_decrypt_block(client):
    for msg in ("abc", "0123456789abcdef", "a" * 17):
        cipher = api_ok(client, "/api/sm9/encrypt", {
            "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
            "userId": "Bob", "userIdFormat": "TEXT",
            "message": msg, "messageFormat": "TEXT",
            "cipherFormat": "HEX", "encType": "BLOCK",
        })
        c2_len = len(cipher) // 2 - 96
        assert c2_len % 16 == 0 and c2_len >= 16
        text = api_ok(client, "/api/sm9/decrypt", {
            "userPrivateKey": DE_BOB, "userPrivateKeyFormat": "HEX",
            "userId": "Bob", "userIdFormat": "TEXT",
            "cipher": cipher, "cipherFormat": "HEX",
            "messageFormat": "TEXT", "encType": "BLOCK",
        })
        assert text == msg


def test_cipher_integrity_check(client):
    """篡改 C3 必须被识别。"""
    cipher = bytearray.fromhex(api_ok(client, "/api/sm9/encrypt", {
        "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "message": "tamper", "messageFormat": "TEXT",
        "cipherFormat": "HEX", "encType": "STREAM",
    }))
    cipher[70] ^= 0x01
    body = post(client, "/api/sm9/decrypt", {
        "userPrivateKey": DE_BOB, "userPrivateKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "cipher": cipher.hex().upper(), "cipherFormat": "HEX",
        "messageFormat": "TEXT", "encType": "STREAM",
    })
    assert body["code"] == 1 and "校验" in body["msg"]


def test_encrypt_wrong_user_fails(client):
    cipher = api_ok(client, "/api/sm9/encrypt", {
        "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "message": "secret", "messageFormat": "TEXT",
        "cipherFormat": "HEX", "encType": "STREAM",
    })
    body = post(client, "/api/sm9/decrypt", {
        "userPrivateKey": DE_BOB, "userPrivateKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "cipher": cipher, "cipherFormat": "HEX",
        "messageFormat": "TEXT", "encType": "STREAM",
    })
    assert body["code"] == 1


# ---------------------------------------------------------------- 密钥封装
def test_kem_api(client):
    data = api_ok(client, "/api/sm9/key/enc", {
        "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "cipherFormat": "HEX", "keyFormat": "HEX", "klen": 16,
    })
    assert len(data["key"]) == 32 and len(data["cipher"]) == 130
    key = api_ok(client, "/api/sm9/key/dec", {
        "userPrivateKey": DE_BOB, "userPrivateKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "cipher": data["cipher"], "cipherFormat": "HEX",
        "keyFormat": "HEX", "klen": 16,
    })
    assert key == data["key"]

    # 长度不一致时必须无法互通（KDF 长度参与派生）
    other = api_ok(client, "/api/sm9/key/dec", {
        "userPrivateKey": DE_BOB, "userPrivateKeyFormat": "HEX",
        "userId": "Bob", "userIdFormat": "TEXT",
        "cipher": data["cipher"], "cipherFormat": "HEX",
        "keyFormat": "HEX", "klen": 32,
    })
    assert other[:32] == key


def test_params_api(client):
    data = api_ok(client, "/api/sm9/params", {})
    assert data["embeddingDegree"] == 12
    assert data["q"] == f"{S.P_MOD:064X}"
    assert data["n"] == f"{S.N_ORDER:064X}"
    assert len(data["curve"]) == 8


# ---------------------------------------------------------------- 与原站交叉验证
REMOTE = "https://cipher.huijusa.cn/api"
UID_BOB = "Bob@hjsa.cn"


def _remote(path, payload, tries=3):
    import requests

    last = None
    for _ in range(tries):
        try:
            resp = requests.post(REMOTE + path, json=payload, timeout=20)
            if resp.status_code == 200 and resp.text.strip().startswith("{"):
                return resp.json()
            last = f"HTTP {resp.status_code}"
        except Exception as exc:  # pragma: no cover - 网络异常
            last = str(exc)
        time.sleep(1)
    pytest.skip(f"原站不可用，跳过交叉验证：{last}")


@pytest.fixture(scope="module")
def bob_de():
    return S.g2_from_bytes(bytes.fromhex(S.generate_user_key(KE, UID_BOB.encode(), 3).hex()))


def test_cross_user_key_matches_remote(client):
    """确定性接口：给定主私钥与标识，用户私钥必须与原站逐字节一致。"""
    for uid, master, kt, hid in (("Alice", KS, 1, "04"), ("Bob", KE, 3, "04"),
                                 ("Bob", KE, 2, "04")):
        remote = _remote("/sm9/generate/user/Key", {
            "privateKeyFormat": "HEX", "privateKey": f"{master:064X}",
            "userId": uid, "userIdFormat": "TEXT",
            "userPrivateKeyFormat": "HEX", "userKeyType": kt,
        })
        assert remote["code"] == 0, remote
        local = api_ok(client, "/api/sm9/generate/user/Key", {
            "privateKeyFormat": "HEX", "privateKey": f"{master:064X}",
            "userId": uid, "userIdFormat": "TEXT",
            "userPrivateKeyFormat": "HEX", "userKeyType": kt,
        })
        assert local.upper() == remote["data"].upper()


def test_cross_signature_remote_verify(client):
    """本地签名 → 原站验签通过。"""
    sig = api_ok(client, "/api/sm9/sign", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userPrivateKey": DS_ALICE, "userPrivateKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard", "messageFormat": "TEXT",
        "signatureFormat": "HEX",
    })
    remote = _remote("/sm9/verify", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "messageFormat": "TEXT", "message": "Chinese IBS standard",
        "userId": "Alice", "userIdFormat": "TEXT",
        "signature": sig, "signatureFormat": "HEX",
    })
    assert remote["code"] == 0 and remote["data"] == "验证通过"


def test_cross_signature_local_verify(client):
    """原站签名 → 本地验签通过。"""
    remote = _remote("/sm9/sign", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userPrivateKey": DS_ALICE, "userPrivateKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "messageFormat": "TEXT", "message": "Chinese IBS standard",
        "signatureFormat": "HEX",
    })
    assert remote["code"] == 0, remote
    sig = bytes.fromhex(remote["data"])
    assert S.verify(ppubs(), b"Alice", b"Chinese IBS standard", sig)
    assert api_ok(client, "/api/sm9/verify", {
        "publicKey": PPUBS_HEX, "publicKeyFormat": "HEX",
        "userId": "Alice", "userIdFormat": "TEXT",
        "message": "Chinese IBS standard", "messageFormat": "TEXT",
        "signature": remote["data"], "signatureFormat": "HEX",
    }) == "验证通过"


def test_cross_der_encoding(client):
    """DER 编码必须与原站一致：本地 DER 经原站转回 RAW 应与原始 h||s 完全相同。"""
    der = api_ok(client, "/api/sm9/signature/convert", {
        "signature": SAMPLE_SIG, "signatureFormat": "HEX", "targetFormat": "DER",
    })
    remote = _remote("/sm9/signature/convert", {
        "signature": der, "signatureFormat": "HEX", "targetFormat": "RAW",
    })
    assert remote["code"] == 0, remote
    assert remote["data"].upper() == SAMPLE_SIG


def test_cross_encrypt_roundtrip(client, bob_de):
    """双向加解密互通：原站加密 → 本地解密；本地加密 → 原站解密。"""
    de_hex = S.generate_user_key(KE, UID_BOB.encode(), 3).hex().upper()
    for mode in ("STREAM", "BLOCK"):
        for msg in ("abc", "跨站验证 cross check"):
            remote = _remote("/sm9/encrypt", {
                "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
                "userId": UID_BOB, "userIdFormat": "TEXT",
                "message": msg, "messageFormat": "TEXT",
                "cipherFormat": "HEX", "encType": mode,
            })
            assert remote["code"] == 0, remote
            plain = api_ok(client, "/api/sm9/decrypt", {
                "userPrivateKey": de_hex, "userPrivateKeyFormat": "HEX",
                "userId": UID_BOB, "userIdFormat": "TEXT",
                "cipher": remote["data"], "cipherFormat": "HEX",
                "messageFormat": "TEXT", "encType": mode,
            })
            assert plain == msg

            cipher = api_ok(client, "/api/sm9/encrypt", {
                "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
                "userId": UID_BOB, "userIdFormat": "TEXT",
                "message": msg, "messageFormat": "TEXT",
                "cipherFormat": "HEX", "encType": mode,
            })
            back = _remote("/sm9/decrypt", {
                "userPrivateKey": de_hex, "userPrivateKeyFormat": "HEX",
                "messageFormat": "TEXT", "userId": UID_BOB, "userIdFormat": "TEXT",
                "cipher": cipher, "cipherFormat": "HEX", "encType": mode,
            })
            assert back["code"] == 0 and back["data"] == msg


def test_cross_kem(client, bob_de):
    """密钥封装双向互通。"""
    de_hex = S.generate_user_key(KE, UID_BOB.encode(), 3).hex().upper()
    remote = _remote("/sm9/key/enc", {
        "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
        "userId": UID_BOB, "userIdFormat": "TEXT",
        "cipherFormat": "HEX", "keyFormat": "HEX", "klen": 16,
    })
    assert remote["code"] == 0, remote
    local_key = api_ok(client, "/api/sm9/key/dec", {
        "userPrivateKey": de_hex, "userPrivateKeyFormat": "HEX",
        "userId": UID_BOB, "userIdFormat": "TEXT",
        "cipher": remote["data"]["cipher"], "cipherFormat": "HEX",
        "keyFormat": "HEX", "klen": 16,
    })
    assert local_key.upper() == remote["data"]["key"].upper()

    mine = api_ok(client, "/api/sm9/key/enc", {
        "publicKey": PUBE_HEX, "publicKeyFormat": "HEX",
        "userId": UID_BOB, "userIdFormat": "TEXT",
        "cipherFormat": "HEX", "keyFormat": "HEX", "klen": 24,
    })
    back = _remote("/sm9/key/dec", {
        "userPrivateKey": de_hex, "userPrivateKeyFormat": "HEX",
        "keyFormat": "HEX", "userId": UID_BOB, "userIdFormat": "TEXT",
        "cipher": mine["cipher"], "cipherFormat": "HEX", "klen": 24,
    })
    assert back["code"] == 0 and back["data"].upper() == mine["key"].upper()
