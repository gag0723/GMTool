"""杂凑与 MAC 计算（本地实现）。"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import struct

from gmssl import sm3, func

from .common import ToolError, parse_bytes

HASH_ALGOS = {
    "SM3": ("sm3", 32),
    "SHA224": ("sha224", 28),
    "SHA256": ("sha256", 32),
    "SHA384": ("sha384", 48),
    "SHA512": ("sha512", 64),
    "SHA3_224": ("sha3_224", 28),
    "SHA3_256": ("sha3_256", 32),
    "SHA3_384": ("sha3_384", 48),
    "SHA3_512": ("sha3_512", 64),
    "SHA": ("sha1", 20),
    "MD5": ("md5", 16),
}

ALGO_LABEL = {
    "SM3": "SM3",
    "SHA224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_224": "SHA3-224",
    "SHA3_256": "SHA3-256",
    "SHA3_384": "SHA3-384",
    "SHA3_512": "SHA3-512",
    "SHA": "SHA-1",
    "MD5": "MD5",
}

_M64 = 0xFFFFFFFFFFFFFFFF
_M32 = 0xFFFFFFFF


# --------------------------------------------------------------------------- #
# Keccak-f[1600]（原版 Keccak 填充 0x01，区别于 SHA3 的 0x06）
# --------------------------------------------------------------------------- #
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

# 轮转偏移 rho，按 [x][y] 索引
_KECCAK_RHO = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotl64(v: int, n: int) -> int:
    if n == 0:
        return v & _M64
    return ((v << n) | (v >> (64 - n))) & _M64


def _keccak_f1600(a):
    for rc in _KECCAK_RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(a[x][y], _KECCAK_RHO[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def _keccak(data: bytes, rate: int, out_len: int) -> bytes:
    padded = data + b"\x01" + b"\x00" * ((-len(data) - 1) % rate)
    padded = padded[:-1] + bytes([padded[-1] | 0x80])
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        blk = padded[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        _keccak_f1600(a)
    out = b""
    while len(out) < out_len:
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            out += a[x][y].to_bytes(8, "little")
        if len(out) < out_len:
            _keccak_f1600(a)
    return out[:out_len]


# --------------------------------------------------------------------------- #
# RIPEMD-160（纯 Python，避免依赖 OpenSSL legacy provider）
# --------------------------------------------------------------------------- #
_RMD_ZL = (
    tuple(range(16)),
    (7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8),
    (3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12),
    (1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2),
    (4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13),
)
_RMD_ZR = (
    (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12),
    (6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2),
    (15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13),
    (8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14),
    (12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11),
)
_RMD_SL = (
    (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8),
    (7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12),
    (11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5),
    (11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12),
    (9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6),
)
_RMD_SR = (
    (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6),
    (9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11),
    (9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5),
    (15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8),
    (8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11),
)
_RMD_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RMD_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _ripemd160(data: bytes) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    buf = data + b"\x80" + b"\x00" * ((56 - len(data) - 1) % 64)
    buf += ((len(data) * 8) & _M64).to_bytes(8, "little")
    for off in range(0, len(buf), 64):
        x = struct.unpack("<16I", buf[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j >> 4
            t = (_rotl32((al + _rmd_f(j, bl, cl, dl) + x[_RMD_ZL[rnd][j & 15]] + _RMD_KL[rnd]) & _M32,
                         _RMD_SL[rnd][j & 15]) + el) & _M32
            al, el, dl, cl, bl = el, dl, _rotl32(cl, 10), bl, t
            t = (_rotl32((ar + _rmd_f(79 - j, br, cr, dr) + x[_RMD_ZR[rnd][j & 15]] + _RMD_KR[rnd]) & _M32,
                         _RMD_SR[rnd][j & 15]) + er) & _M32
            ar, er, dr, cr, br = er, dr, _rotl32(cr, 10), br, t
        t = (h[1] + cl + dr) & _M32
        h[1] = (h[2] + dl + er) & _M32
        h[2] = (h[3] + el + ar) & _M32
        h[3] = (h[4] + al + br) & _M32
        h[4] = (h[0] + bl + cr) & _M32
        h[0] = t
    return struct.pack("<5I", *h)


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _M32


# --------------------------------------------------------------------------- #
# Whirlpool（S 盒 + circ(1,1,4,1,8,5,2,9) 生成 C 表，与参考实现等价）
# --------------------------------------------------------------------------- #
_WHIRLPOOL_SBOX = bytes.fromhex(
    "1823c6e887b8014f36a6d2f5796f915260bc9b8ea30c7b351de0d7c22e4bfe57157737e59ff04ada58c9290ab1a06b85bd5d10f4cb3e0567e427418ba77d95d8fbee7c66dd17479eca2dbf07ad5a83336302aa71c81949d9f2e35b889a2632b0e90fd580becd3448ff7a905f20681aaeb454932264f173124008c3ecdba18d3d9700cf2b7682d61bb5af6a5045f330ef3f55a2ea65ba2fc0de1cfd4d9275068ab2e60e1f62d4a896f9c525598472394c5e78388cd1a5e261b3219c1e43c7fc0451996d0dfadf7e243babce118f4eb7eb3c8194f7b9132cd3e76ec40356447fa92abbc153dc0b9d6c3174f646ac8914e1163a690970b6d0edcc4298a4285cf886"
)

_WHIRLPOOL_RC = tuple(
    int.from_bytes(_WHIRLPOOL_SBOX[8 * (r - 1):8 * r], "big") for r in range(1, 11)
)


def _wp_gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
    return r


def _wp_build_c() -> list:
    c0 = []
    for u in range(256):
        s = _WHIRLPOOL_SBOX[u]
        v = 0
        for j, coef in enumerate((1, 1, 4, 1, 8, 5, 2, 9)):
            v |= _wp_gmul(coef, s) << ((7 - j) * 8)
        c0.append(v)
    tables = [c0]
    for i in range(1, 8):
        tables.append([((x >> (8 * i)) | (x << (64 - 8 * i))) & _M64 for x in c0])
    return tables


_WHIRLPOOL_C = _wp_build_c()


def _whirlpool(data: bytes) -> bytes:
    ctab = _WHIRLPOOL_C
    padded = data + b"\x80" + b"\x00" * ((32 - (len(data) + 1)) % 64)
    padded += (len(data) * 8).to_bytes(32, "big")
    h = [0] * 8
    for off in range(0, len(padded), 64):
        blk = padded[off:off + 64]
        block = [int.from_bytes(blk[8 * i:8 * i + 8], "big") for i in range(8)]
        k = h[:]
        state = [block[i] ^ k[i] for i in range(8)]

        def mix(words, add_rc=0):
            out = []
            for i in range(8):
                v = add_rc if i == 0 else 0
                for j in range(8):
                    v ^= ctab[j][(words[(i - j) % 8] >> (56 - 8 * j)) & 0xFF]
                out.append(v)
            return out

        for r in range(1, 11):
            k = mix(k, _WHIRLPOOL_RC[r - 1])
            state = mix(state)
            state = [state[i] ^ k[i] for i in range(8)]
        h = [h[i] ^ state[i] ^ block[i] for i in range(8)]
    return struct.pack(">8Q", *h)


# --------------------------------------------------------------------------- #
# Tiger（192 位，小端 64 位字，大端输出；表为官方生成表）
# --------------------------------------------------------------------------- #
_TIGER_T1 = struct.unpack(">256Q", bytes.fromhex("02aab17cf7e90c5eac424b03e243a8ec72cd5be30dd5fcd36d019b93f6f97f3acd9978ffd21f91937573a1c9708029e2b164326b922a83c346883eee04915870eaace3057103ece6c54169b808a3535c4ce754918ddec47c0aa2f4dfdc0df40c10b76f18a74dbefac6ccb6235ad1ab6a13726121572fe2ff1a488c6f199d921e4bc9f9f4da0007ca26f5e6f6e85241c7859079dbea5947b64f1885c5c99e8c92d78e761ea96f864b8e36428c52b5c17d69cf6827373063c1b607c93d9bb4c56e7d820e760e76b5ea645c9cc6f07fdc42bf38a078243342e05f6b343c9d2e7d04f2c28aeb600b0ec66c0ed85f7254bcac71592281a4db4fe51967fa69ce0fed9ffd5293f8b96545dbc879e9d7f2a7600b860248920193194ea4f9533b2d9cc0b39053836c15957613db6dcf8afc357bf118beea7a7a370f57037117ca50b990666ab30a9774424a35f4e92f02e325249b7739db07061ccae1d8f3b49ceca42a05bd56be3f51382f7345faed5843b0bb281c813d5c11bf1f838af0e4b6d75fa16933ee18a487ad99993c26e8eab1c94410b510102bc0a822f9141eef310ce6123bfc65b90059ddb154e0158640c5e0e607884e079826c3a3cf930d0d9523c535fd35638d754e9a2b004085fccf40469dd5c4b17ad28be23a4ccab2f0fc6a3e6a2e2860971a6b943fcd3dde6ee212e304466222f32ae01765ae5d550bb5478308fea9efa98da0eda22ac351a71686c40da71105586d9c867c84dcffee85fda22853ccfbd0262c5eef76baf294cb8990d201e69464f52afad97594b013afdf133e1406a7d1a32823c9586f95fe5130f61119d92ab34e462c06c0ed7bde33887c71d279746d6e6518393e5ba419385d7133297c1ba6b948a9756431987c197bfdac67de6c23c44b053d02581c49fed002d64ddd474d6338261571aa4546c3e473d062928fce349455f86048161bbacaab94d963912430770e6f686ec8a5e602c6641c87282515337ddd2b2cda6b42034b701bb03d37c181cb096de108438266c71c6f2b3180c7eb51b255df92b82f96c08bbc5c68c8c0a632f3ba5504cc861c3d0556abbfa4e55fb26b8f41848b0ab3baceb4b334a273aa445d32bca696f0a85ad88124f6ec65b528d56c0ce1512e90f4524a4e9dd79d5506d35a258905fac6ce97792019295b3e109b33f8a9478b73a054cc2924f2f934417eb03993357d536d1bc438a81ac21db6ff8b47c4fbf17d6016bf1e0faadd7667e3f57abcff62938beb96a78dad948fc179c98f1f98b72911e50d61e48eae27121a914d62f7ad31859808eceba345ef5ceaebf5ceb25ebc9684cef633e20cb7f76221a32cdf06ab8293e4985a202ca5ee2ca4cf0b8447cc8a8fb19f765244979859a3a8d516b1a12400170bd7ba3ebb5dc726e54bca55b86adb391d7a3afd6c478063519ec608e7669edd0e5715a2d149aa23177d4571848ff194eeb55f3241014c220f5e5ca13a6e2ec28029927b75f5c361ad139fabc3d6e4360d5df1a94ccf402f3e8bd948bea5dfc8a5a0d357bd3ff77ea2d12e251f74f64566fd9e525e81a0822e0c90ce7f687a49c2e8bcbeba973bc5000001bce509745f423777bbe6dab3d6d1661c7eaef06eb5a1781f354daacfd82d11284a2b16affcf1fc4f67fa891d1f73ecc25dcb920adaae610c22c2a1265196e0a810d356b78a5a9a381f2fe7870fd5ad62ede94e5530d225e5e8368d142765977b70c7af463199f889b2de39d74f233f30bf54e1d1439a9675d3d9a63c975470554ff334f9a8166acb744a4f568870c74caab2e4aeadf0d091646f294d1257b82a89684031d1efd95a5a61be0b6b2fbd12e969f2f29a9bd37013feff9fe83f9b0404d6085a064940c1f3166cfe1509542c4dcdf3defbb4c5218385cd5ce3c935b7dc4462a6413417f8a68ed3b63fb80959295b215b40f99cdaef3b8c8572018c0614f8fcb95d1b14accd1a3acdf384d471f200bb732dc1a3110e95e8da16430a7220bf1a82b8b77e090d39df210e5ef4bd9f3cd05e9d9d4ff6da7e57a444da1d60e183d4a5f8b287c38417998e47fe3edc121bb31886c7fe3ccc980ccbefe46fb590189bfd033732fd469a4c57dc7ef700a07cf1ad6559c64468a31d8859762fb0b4d45b61f6155baed09904771868755e4c3d50baa6e9214e7f22d8b4df2addbf532eac95f432ae3909b4bd0109834df537b08e3450fa209da84220728d9e691d9b9efe23f70446d288c4ae8d7f7b4cc524e169785b21d87f0135ca1385cebb400f137b8aa5272e2b66580796be3612264125c2b0de057702bdad1efbb2d4babb8eacf84be991583139641bc67b8bdc2de08036e024603c8156f49f68edf7d236f7dbef51119727c4598ad21e80a08a0896670a5fd7cb4a8f4309eba9cb81af564b0f7036a1c0b99aa778199abd959f1ec83fc8e9528c505077794a81b93acaaf8f056338f007b43f50627a67784a44ab49f5eccc773bc3d6e4b679ee989cc0d4d1cf14108c4406c00b206bc8a082a18854c8d72d8967e366b35c3c432cb923dd61102b37f256ab2779d884271dbe83e1b0ff1525affb7c65d4217e49a96bdbe0e76d48e7d408df828745d9179e22ea6a9add53bd34e36e141c5622200a7f805d1b8cb750eeafe5c7a59f58e837e27f996a4fb1c23cd3867dfb0775f0d0d0e673de6e88891a123aeb9eafb86c2530f1d5d5c145b895bb434a2dee7269e778cb67ecf931fa38f33b0372323bbf9c52d66336fb279c74505f33ac0afb4eaae8a5cd99a2cce187534974801e2d30bb8d2d5711d5876d901f1a412891bc038ed6e2e71d82e5664874036c3a497732b789b67ed96361f5abffed95d8f1ea02a2e72b3bd61464d43da6300f170bdc4820ebc18760ed78a77a"))
_TIGER_T2 = struct.unpack(">256Q", bytes.fromhex("e6a6be5a05a12138b5a122a5b4f87c98563c6089140b69904c46cb2e391f5dd5d932addbc9b7943408ea70e42015aff5d765a6673e478cf1c4fb757eab278d99df11c6862d6e0692ddeb84f10d7f3b166f2ef604a665ea044a8e0f0ff0e0dfb3a5edeef83dbcba51fc4f0a2a0ea4371ee83e1da85cb38429dc8ff882ba1b1ce2cd45505e8353e80d18d19a00d4db071734a0cfeda5f381010be77e518887caf21e341438b3c45136e05797f49089ccf9ffd23f9df2591d14543dda228595c5cd661f81fd99052a338736e641db0f7b7615227725418e5307e25f7f46162eb2fa48a8b2126c13d9feafdc541792e76eea03d912bfc6d1898f31b1aafa1b83f51bf1ac2796e42ab7d940a3a7d7fcd2ebac1056136d0afbbcc57889e1dd9a6d0c85d33525782a7974aaa7e25d09078ac09bbd4138b3eac6edd0920abfbe71eb9e70a2a5d0f54fc2625cc054e36b0b1290a3f6dd59ff62fe932b3537354511a8ac7dca845e9172fadcd484f82b60329d20dc79c62ce1cd672f188b09a2add124642cd0c1e96a19d9e7265a786a9b4ba9500c0e020336634c43f3c17b474aeb66d8226a731ae3ec9baac28226667ae084025867d4567691caeca51d94155c4875adb56d00fd985b813fdf51286efcb774cd065e8834471fa744aff72ca0aee761ae2ebe40e4cdaee8e09ae9970bbb5118f665726e4beb33df1964703b0007291997624631d816f5ef30a7b880b5b51504a6be641793c37ed84b6c7b21ed77f6e97d96776306312ef96b73ae528948e86ff3f453dbd7f286a3f8f816cadce74cfc1063005c19bdfa52c6dd68868f5d64d46ad33a9d512ccf1e186a367e62c2385660aee359e7ea77dcb1d7526c0773749abe6e735ae5f9d09f734b493fc7cc8a558ba8b0b9c1533041ab45321958ba470a59bd852db00b5f46c39391209b2bd336b0e56e604f7d659ef19fb99a8ae2782ccb24ccf52ab6c814c4c74727d9afbe11727b7e950d0c0121b34d756f435670ad471ff5add442615a68494e87e09980b9957a2acfa1df50aee355d898263afd2fd556c8f4924dd80c8fd6cf99ca3d754a173afe477bacaf91bf3ced5371f6d690c12d831a5c285e687094c5d3c90a3708a0a40f7f903717d0658019f9bb13b8fdf27fb1bd6f1b4d5028431c761ba38fff40120d1530c4e2e21f3b8943ce69a7372c8ae5184e11feb5ce66618bdb80bd7366217d29bad68b574d0b81bb613e25e6fe5b071c9c10bc07913fc7beeb7909ac2d97c3e58d353bc5d757eb017892f38f61e8d4effb9c9b1cc21a99727d26f494f7aba3e063a2956b3e039d4a8b9a4aa09c303f6ab7d500090fb49cc0f2a057268ac03dee9d2dedbf42d1330f49c87960a972c6b2720287421b410ac59ec07c00369cef4eac49cb353425f450244eef0129d88acc46e5caf4deb62ffeab63989263f78f7cb9fe5d7a45785bd8f7644e634635427a7315bf2dc90017d0c4aa2125261c3992486c93518e50b4cbfee0a2d7d4c37c75d6202c5ddd8ddbc295d8e35b6c6160b369d302032b19ce42685fdce4413206f3ddb9ddf656108ea4d21db5e148f020b0fce62fcd496f2c1b912358b0ee31b28317b818f5a308a89c1e189ca6d2cf0c6b18576aaadbc8b65deaa91299fae3fb2b794b7f1027e704e4317f443b5beb4b852d325939d0a6d5ae6beefb207ffc309682b281c7d374bae309a194c3b4758cc3f97b13b49f0598a9422ff8293967244b16b01076ff7cf8bf571c663d67ee1f0d6758eee30da1c9b611d97adeb9b7b7afd5887b6c57a26290ae846b984fe194df4cdeacc1a5fd058a5bd1c5483aff63166cc142ba3c378db8526eb2f76f40e10880036f0d6d4e9e0523c9971d311d45ec2824cc7cd691575b8359e62382c9fa9e400dc4889995d1823ecb45721568dafd983b8206082faa7d29082386a8cb269fcd4403b875881b91f5f728bdd1e0e4669f39040201f67a1d7c218cf04ade65623c29d79ce5ce2368449096c00bb1ab9bf1879da503babc23ecb1a458058e9a58df01bb401ecca070e868a85f143d4ff188307df2239e14d565b41a641183ee13337452701602950e3dcf3f285e0959930254b9c809533bf299408930da6da955943f53691387a15edecaa9cb878429142127352be9a076f0371fff4e7afb0239f450274f2228bb073af01d5e868bbfc80571c10e96c1d267088568222e239671a3d48e80b5b055b5d38ae193bb81693ae2d0a18b04b85c48b4ecadd5335ffd743b194916a1ca2577018134be98c4e77987e83c54a4ad28e11014da33e1b9270cc59e226aa21371495f756d1a5f609be853fb60afef77adc786a7f7443dbf0904456173b29a8258bc7a66c232bd5ef306558c673ac8b241f639c6b6c9772a216defe99fda35da11640cc71c7be61593c43694565c5527ea038e6246777839f9abf3ce5a3e2469741e768d0fd312d20144b883ced652c6c20b5a5ba33f85521ae69633c3435a9d97a28ca4088cfdec8824a43c1e96f42037612fa66eeea7466b4cb165f9cf0e5a43aa1c06a0abfb4a7f4dc26ff162796b6cbacc8e54ed9b0fa6b7ffefd2bb253e2e25bc95b0a29d4f86d6a58bdef1388cded74ac576b6f0548030bdbc2b45805d3c81af70e94d92893eff6dda9e3100dbb38dc39fdfcc8847123885528d17b87ef2da0ed240b1b64244cefadcd54bf9a91312200e433c7ee69ffcc84f3a78c748f0cd1f72248576bbec6974053638cfe42ba7b67c0cec4e4cac2f4df3e5ce32edcb33d14326ea4c11a4e9044cc77e58bc5f513293d934fcef5dc9645506e5544450de418f317de40a388cb31a69dde2592db4a83455820a869010a91e84711ae94df7f0b7b1498371d62a2eabc097717922fac097aa8d5c0e"))
_TIGER_T3 = struct.unpack(">256Q", bytes.fromhex("f49fcc2ff1daf39b487fd5c66ff29281e8a30667fcdca83f2c9b4be3d2fcce63da3ff74b93fbbbc22fa165d2fe70ba66a103e279970e93d4becdec77b0e45e71cfb41e723985e497b70aaa025ef75017d42309f03840b8e08efc1ad03589857996c6920be2b2abc566af4163375a91722174abdcca7127fbb33ccea64a72ff41f04a4933083066a58d970acdd7289af58f96e8e031c8c25ef3fec02276875d47ec7bf310056190ddf5adb0aebb0f14919b50f8850fd588924975488358b74de8a3354ff691531c610702bbe481d2c6ee89fb24057deded98ac3075138596e9021d2d3580172772edeb738fc28e6bc30d5854ef8f630443269e5c52325add3bbe90aa53cf325c4623c1d24d51349dd0672051cfeea69ea62413220f0a862e7e4fce39399404e04864d9c42ca47086fcb7685ad2238a03e7cc066484b2ab2ff1dbfe9d5d70efbf79ec5b13b9dd9c48185415f0d475ed1509ad0bebcd060ec79851d58c6791183ab7f8d1187c5052f3eee4c95d1192e54e82ff86eea14cb9ac6ca23485beb153677d5ddd191d781f8c492af60866baa784ebf9518f643ba2d08c748852e956e1087c22a768cb8dc410ae8d38047726bfec8e1aa67738b4cd3b45aaad16691cec0dde19c6d4319380462e07c5a5876d0ba6193816b9fa1fa58fd840188ab1173ca74f18abda2f98c99c021f3e0580ab134ae8165f3b05b773645abb2501a2be5575f2f61b2f74004e7e8ba91cd7580371e8d9537f6ed89562764e30b15926ff596f003d9f65293da8c5d6b96ecef04dd690f84c4782275fff33af88e41433083f820801fd0dfe409a1af9b54325a3342cdb396b8ae77e62b301b252c36f9e9f6655615a85455a2d92d32c09f2c7dea94947748563cfb4c133a39eba83b040cc6ebc54623b9454c8fdb326b056f56a9e87ffd78c2dc2940d99f42bc698f7df096b096e2d19a6e01e3ad852bf42a99ccbdbd4b40ba59998af45e9c559366295e807d931866b48181bfaa1f7731fec57e2157a0a1d4667446af6201ad5e615ebcacfb0f075b8f31f4f6829077822713ed6ce22d11e3057c1a72ec3c93bcb46acc37c3f1f2fdbb893fd02aaf50e331fd92e600b9fcfa498f96148ea3ad6a8d8426e8b6a83eaa089b274b7735cdc87f6b3731e524a11118808e5cbc967499906e4c7b19bd394afed7f7e9b24a20c6509eadeeb3644a76c1ef1d3e8ef0edeb9c97d43e9798fb4a2f2d784740c28a37b8496476197566f7a5be3e6b65f069df96330ed78be6f10eee60de77a076a152b4bee4aa08b9bd06a56a63ec7b8894e02121359ba34fef44cbf99f8283703fc398071350caf30c8d0a77a89f017687af1c1a9eb9e4235698c7976282dee81995d1737a5dd1f7abd4f53433c09a9fa80fa8b0c53df7ca1d93fd9dcbc886ccb77c040917ca91b47207dd00142f9d1dcdf8476fc1d4f387b5823f8e7c5f3316503032a2244e7e373395c87a5d750f5a74b082b4cc43698992edf917becb858f63c3270b8fc5bf86dda10ae72bb29b5dd76576ac94e7700362b1ad112dac61efb8f691bc30ec5faa427ff246311cc3271433142368e30e5320671380e31e02ca396958d5c960aad76f1f8d6f430c16da536c8ffd13f1be7e1d27578ae66004ddbe105833f01067be646bb34b5ad3bfe586d095f34c9a12b97f0247ab64525d60ca8dcdbc6f3017477d14a2e14d4decad24dbdb5e6d9be0a1eeb2a7e70f7794301abdef42d8a270540fd01078ec0a34c22c1e5de511af4c163877ebb3a52bd9a330a77697857aa7d6435004e831603ae4c32e7a21020ad78e3129d41a70c6ab420f228e06c18ea1141e6d2b28cbd984f6b2826b75f6c446e9d83ba47568c4d418d7fd80badbfe6183d8e0e206d7f5f166044e258a43911cbca3e723a1746b21dc0bcc7caa854f5d7cdd37cac32883d261d9c7690c26423ba942c17e55524478042b8e0be477656a2389f4d289b5e67ab2da044862b9c8fbbfd31b47cc8049d141365822c1b362b91c7934eb14655fb13dfd81ecbba0714e2a97b6143459d5cde5f1453a8fbf1d5f0ac8997ea04d81c5e5b00622181a8d4fdb3f3e9bcd341572a12081411258643cce58a9144c5fea4c6e0a40d33d06565cf620f54a48d489f219ca1c43e5eac6d63c821a9728b3a72770dafd7934e7b20df87efe35503b61a3e86e5cae321fbc819d504129a50b3ac60bfa6cd5e68ea7e9fb6c3b01c90199483b1c73de93cd5c295376caed52edf2ab9ad132e60f512c0a07884bc3d86a3e36210c935269d9b163951ce0c7d6e2ad0cdb5fa59e86297d87f5733298ef221898db0e755000029d1a5aa7e8bc08ae1b5061b45c2c31c2b6c92703a94cc596baf25ef420a1d73db2254045604b6a0f9d9c4179aeffdafa2ae3d3c60f7c8075bb49496c49cc5c7141d1cd4e378bd1638218e5534b2f11568f850246aedfabcfa9502bc29796ce5f2da23051baae128b0dc93537c3a493da0ee4b29aeb5df6b2c416895d7fcabbd25122d7f3770810b58105dc4b1e10fdd37f7882a90524dcab5518a3f5c3c9e85878451255b4029828119bd34e274a05b6f5d3ceccbb610021542e13eca0ff979d12f59e2ac6037da27e4f9cc505e92975a0df1847dd66de190d3e623fe5032d6b87b5680489a36b7ce8235216e80272a7a24f64b4a93efed8b8c6916f737ddbff44cce15554b95db5d4b99bd2592d3fda169812fc0fb1a4a9a90660bb6730c196946a4b9b281e289aa7f49da6864669a0f83b1a05f27b3ff7d9644f48bcc6b615c8db675b3674f20b9bcebbe956f312382756559825ae488713e45cf05bf619f9954c21157eabac46040a8eae9454c6fe9f2c0c1cd419cf6496412691cd3dc3bef265b0f706d0e60f5c3578a9e"))
_TIGER_T4 = struct.unpack(">256Q", bytes.fromhex("5b0e608526323c551a46c1a9fa1b59f5a9e245a17c4c8ffa65ca5159db2955d705db0a76ce35afc281eac77ea9113d45528ef88ab6ac0a0da09ea253597be3ff430ddfb3ac48cd56c4b3a67af45ce46f4ececfd8fbe2d05e3ef56f10b39935f00b22d6829cd619c617fd460a74df20696cf8cc8e8510ed40d6c824bf3a6ecaa761243d581a817049048bacb6bbc163a2d9a38ac27d44cc327fddff5baaf410abad6d495aa804824be1a6a74f2d8c9f94d4f7851235dee8e3fd4b7f886540d893247c20042aa4bfda096ea1c517d1327cd56966b4361a6685277da5c31221057d94d59893a43acff764f0c51ccdc022813d33bcc4ff6189dbe005cb184ce66af1ff5ccd1d1db99beab0b854a7fe42980f7bd46a6a718d4b9fd10fa8cc22a5fd8cd31484952be4bd31c7fa975fcb2438474886ed1e5846c40728cddb791eb70b04c2b00be2f573417f5c9590452180f8777a6bddfff370eb00ce509e38d6d9d6a4ebeb0f00647fa7021dcc06cf76606f06e4d9f28ba286ff0ad85a305dc918c262475b1d8732225f542d4fb51668ccb5fea679b9d9d72bba2053841c0d912d43a53b7eaa48bf12a4e8781e0e47f22f1ddfeff20ce60ab5097320d261d19dffb74216a12b03062a2e391960eb2239650495251c16fed50eb8b89ac0c330f826016eed152665953e767102d63194a63695705074f08394b1c98770ba598c90b25ce1794a15810b9742f60d5925e9fcaf8c6c3067716cd868744e910ab077e8d7731b6a61bbdb5ac42f6193513efbf0851567f494724b9e83e9d5e887e1985c09648d34b1d3c675370cfddc35e433bc0d255dd0aab84234131be008042a50b48b7eaf9997c4ee44a3ab35829a7b49201799d0263b8307b7c54441752f95f4fd6a6ca6927217402c08c6e52a8ab754a795d9eea442f7552f72943d2c31334e197812084fa98d7ceaee629155c3862f665db309bd0610175d53b1f346fe6cb840413f273fe03792df0cfa59cfe700372eb85e8fa7be29e7adbce118e544ee5cde8431dd8a781b1b41f1873ea5c94c78a0d2f0e739412e2877b60728a1265ef3afc9a62cbcc2770c6a2506c53ab66dd5dce1ce12e65499d04a675b377d8f523481bfd2160f6f64fcec15f38974efbe618b5b13c8acdc82b714273e1ddd40bfe003199d1737e99257e7e061f8fa52626904775aaa8bbbf63a463d56f9f0013f1543a26e64a8307e9f879ec898cc4c27a4150177cc1b432f2cca1d3348de1d1f8f9f6fa013606602a047a7ddd6d237ab64cc1cb2c79b938e7225fcd1d3ec4e03708e0ff476feb2fbda3d03c12dae0bced2ee43889a22cb8923ebfb4f4369360d013cf7396d855e3602d2d4e022073805bad01f784c33e17a133852f546df4874058ac7b638ba92b29c678aa14a0ce89fc76cfaadcd5f9d4e0908339e34f1afe9291f5923b96e3480f60f4a265feebf3a2ab29b841ce21938a88f91b4ad57dfeff845c6d3c32f006b0bf62caaf262f479ef6f75ee7811a55ad41c8916a9f229d29084fed45342f1c27b16b000e62b1f76749823c0744b76eca3c27453608c98f463b91691bd14bcc93cf1ade66a8885213e6d4583978e177df0274d4711b49b73b5503f295110168168c3f96b6b0e3d963b63cab0ae8dfc4b5655a1db14f789f1356e14de5c683e68af4e51dac1c9a84f9d8d4b0fd93691e03f52a0f9d15ed86e46e1878e803c711a0e99d071505a0865b20c4e931056fbfc1fe4f0682eea8d5de3105edf9b71abfdb12379187a2eb99de1bee77b9c21ecc0ea33cf452359a4d7521805c7a13896f5eb56ae7c72aa638f3db18f75dc9f39358dabe9808eb7defa91c00b72ac6b5541fd62492d926dc6dee8f92e4d5b353f57abc4beea7e735769d6da5690ce0a234aa642391484f6f9508028f80d9db8e319a27ab3f21531ad9c1151341a4d773c22a57bef580545c7561a07968633f913da9e249dbe36da652d9b78a64c684c27a97f3bc334ef76621220e66b17f4967743899acd7d0bf3ee5bcae0ed6782409f753600c879fc06d09a39b5926db66f83aeb0317ac58801e6ca4a86381f2166ff3462d19f302572207c24ddfd3bfb4af6b6d3e2ece2eb9c994dbec7ea08de49ace597b09a8bc4b38c4766cf0797ba131b9373c57c2a75b1822cce61931e589d7555b909ba1c0c127fafdd937d11d229da3badc66d92e4a2c1d57154c2ecbc58c5134d82f6fe241c3ae3515b62274fe907c82e01cb8126f8ed091913e37fcb3249d8f9c80046c980cf9bede388fb631881539a116cf19e5103f3f76bd5245715b7e6f5ae47f7a8dbd7c6ded47e9ccf44e55c410228bb1ab647d4255edb4e995d11882bb8aafc30f5098bbb29d3212a8fb5ea14e90296b3677b942157dd025afb58e7c0a390acb589d3674c83bd4a019e2da4df4bf3b93bfcc41e328cab482903f38c96ba582c52cad1bdbd7fd85db2bbb442c16082ae83b95fe86ba5da9ab0b22e04673771a93f845358c9493152d8be2a488697b4541e95a2dc2dd38e6966c02c11ac923c852b2388b1990df2a87b7c8008fa1b4f37be1f70d0c84d54e5035490adec7ece57d4002b3c27d9063a3a7eaea3848030a2bfc602326ded2003c083a7287d69a94086c57a5fcb30f57a8ab56844e479ebe779a373b40f05dcbce9d71a786e88570ee2879cbacdbde8f6a0976ad1bcc164a32fab21e25e9666d78b901063aae5e5c33c9818b34448698d90e36487ae3e1e8abbafbdf931893bdcb46345a0dc5fbbd5198628fe269b9465ca1e5d01603f9c51ec4de44006a15049b7bf6c70e5f776cbb1411218f2ef552bedcb0c0708705a36a3e74d14754f986044cd56d9430ea8280ec12591d7535f5065c83223f1720aef96c3a0396f7363a51f"))


def _tiger_round(a: int, b: int, c: int, x: int, mul: int):
    c = (c ^ x) & _M64
    a = (a - (_TIGER_T1[c & 0xFF] ^ _TIGER_T2[(c >> 16) & 0xFF]
              ^ _TIGER_T3[(c >> 32) & 0xFF] ^ _TIGER_T4[(c >> 48) & 0xFF])) & _M64
    b = ((b + (_TIGER_T4[(c >> 8) & 0xFF] ^ _TIGER_T3[(c >> 24) & 0xFF]
               ^ _TIGER_T2[(c >> 40) & 0xFF] ^ _TIGER_T1[(c >> 56) & 0xFF])) * mul) & _M64
    return a, b, c


def _tiger_pass(a: int, b: int, c: int, mul: int, x):
    a, b, c = _tiger_round(a, b, c, x[0], mul)
    b, c, a = _tiger_round(b, c, a, x[1], mul)
    c, a, b = _tiger_round(c, a, b, x[2], mul)
    a, b, c = _tiger_round(a, b, c, x[3], mul)
    b, c, a = _tiger_round(b, c, a, x[4], mul)
    c, a, b = _tiger_round(c, a, b, x[5], mul)
    a, b, c = _tiger_round(a, b, c, x[6], mul)
    b, c, a = _tiger_round(b, c, a, x[7], mul)
    return a, b, c


def _tiger_compress(block: bytes, res):
    a, b, c = res
    x = list(struct.unpack("<8Q", block))
    aa, bb, cc = a, b, c
    for i in range(3):
        if i:
            x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)) & _M64
            x[1] ^= x[0]
            x[2] = (x[2] + x[1]) & _M64
            x[3] = (x[3] - (x[2] ^ (((~x[1] & _M64) << 19) & _M64))) & _M64
            x[4] ^= x[3]
            x[5] = (x[5] + x[4]) & _M64
            x[6] = (x[6] - (x[5] ^ ((~x[4] & _M64) >> 23))) & _M64
            x[7] ^= x[6]
            x[0] = (x[0] + x[7]) & _M64
            x[1] = (x[1] - (x[0] ^ (((~x[7] & _M64) << 19) & _M64))) & _M64
            x[2] ^= x[1]
            x[3] = (x[3] + x[2]) & _M64
            x[4] = (x[4] - (x[3] ^ ((~x[2] & _M64) >> 23))) & _M64
            x[5] ^= x[4]
            x[6] = (x[6] + x[5]) & _M64
            x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)) & _M64
        a, b, c = _tiger_pass(a, b, c, (5, 7, 9)[i], x)
        a, b, c = c, a, b
    a ^= aa
    b = (b - bb) & _M64
    c = (c + cc) & _M64
    res[0], res[1], res[2] = a, b, c


def _tiger(data: bytes) -> bytes:
    res = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187]
    off = 0
    while len(data) - off >= 64:
        _tiger_compress(data[off:off + 64], res)
        off += 64
    tail = data[off:] + b"\x01" + b"\x00" * ((56 - len(data) - 1) % 64)
    tail += ((len(data) * 8) & _M64).to_bytes(8, "little")
    for off in range(0, len(tail), 64):
        _tiger_compress(tail[off:off + 64], res)
    return struct.pack("<3Q", *res)


# --------------------------------------------------------------------------- #
# GOST R 34.11-94（256 位，BouncyCastle 默认 D-A S 盒，ECB 加密 + 三步压缩）
# --------------------------------------------------------------------------- #
_GOST_SBOX = tuple(int(ch, 16) for ch in "A4568137DCE092BF5F402DB91763CEA87FCE94103B526A8D4A7C0F28E165DB93764B9C2A180EFD357624D9F0A15B8EC3DE41705A3C8F629B13A95B4F867ED02C")

_GOST_C2 = bytes.fromhex(
    "00FF00FF00FF00FFFF00FF00FF00FF00"
    "00FFFF00FF0000FFFF000000FFFF00FF"
)


def _gost_main_step(n1: int, key: int) -> int:
    cm = (key + n1) & _M32
    om = 0
    for i in range(8):
        om |= _GOST_SBOX[i * 16 + ((cm >> (4 * i)) & 0xF)] << (4 * i)
    return ((om << 11) | (om >> 21)) & _M32


def _gost_ecb(key: bytes, block: bytes) -> bytes:
    keys = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]
    n1 = int.from_bytes(block[:4], "little")
    n2 = int.from_bytes(block[4:], "little")
    for _ in range(3):
        for j in range(8):
            n1, n2 = n2 ^ _gost_main_step(n1, keys[j]), n1
    for j in range(7, 0, -1):
        n1, n2 = n2 ^ _gost_main_step(n1, keys[j]), n1
    n2 = n2 ^ _gost_main_step(n1, keys[0])
    return n1.to_bytes(4, "little") + n2.to_bytes(4, "little")


def _gost_p(inb: bytes) -> bytes:
    out = bytearray(32)
    for k in range(8):
        out[4 * k] = inb[k]
        out[4 * k + 1] = inb[8 + k]
        out[4 * k + 2] = inb[16 + k]
        out[4 * k + 3] = inb[24 + k]
    return bytes(out)


def _gost_a(inb: bytes) -> bytes:
    x = bytes(inb[j] ^ inb[j + 8] for j in range(8))
    return bytes(inb[8:32]) + x


def _gost_psi(inb: bytes) -> bytes:
    w = [(inb[2 * i + 1] << 8) | inb[2 * i] for i in range(16)]
    w = w[1:] + [w[0] ^ w[1] ^ w[2] ^ w[3] ^ w[12] ^ w[15]]
    out = bytearray(32)
    for i in range(16):
        out[2 * i] = w[i] & 0xFF
        out[2 * i + 1] = w[i] >> 8
    return bytes(out)


def _gost3411_94(data: bytes) -> bytes:
    h = bytearray(32)
    total = bytearray(32)
    ckeys = [b"\x00" * 32, b"\x00" * 32, _GOST_C2, b"\x00" * 32]

    def compress(m: bytes):
        u, v = h[:], m[:]
        s = bytearray(32)
        w = bytes(u[j] ^ v[j] for j in range(32))
        s[0:8] = _gost_ecb(_gost_p(w), bytes(h[0:8]))
        for i in range(1, 4):
            u = _gost_a(u)
            u = bytes(u[j] ^ ckeys[i][j] for j in range(32))
            v = _gost_a(_gost_a(v))
            w = bytes(u[j] ^ v[j] for j in range(32))
            s[8 * i:8 * i + 8] = _gost_ecb(_gost_p(w), bytes(h[8 * i:8 * i + 8]))
        for _ in range(12):
            s = _gost_psi(bytes(s))
        s = bytearray(s[j] ^ m[j] for j in range(32))
        s = _gost_psi(bytes(s))
        s = bytearray(s[j] ^ h[j] for j in range(32))
        for _ in range(61):
            s = _gost_psi(bytes(s))
        h[:] = s

    padded = data + b"\x00" * (-len(data) % 32)
    for off in range(0, len(padded), 32):
        blk = padded[off:off + 32]
        carry = 0
        for i in range(32):
            t = total[i] + blk[i] + carry
            total[i] = t & 0xFF
            carry = t >> 8
        compress(blk)
    compress(((len(data) * 8) & ((1 << 256) - 1)).to_bytes(32, "little"))
    compress(bytes(total))
    return bytes(h)


# --------------------------------------------------------------------------- #
# 扩展算法注册（与原站 BouncyCastle 目录对齐）
# --------------------------------------------------------------------------- #
EXTRA_HASH_ALGOS = {
    "RIPEMD_160": (20, _ripemd160),
    "BLAKE2B_512": (64, lambda d: hashlib.blake2b(d, digest_size=64).digest()),
    "BLAKE2S_256": (32, lambda d: hashlib.blake2s(d, digest_size=32).digest()),
    "WHIRLPOOL": (64, _whirlpool),
    "SHAKE128": (16, lambda d: hashlib.shake_128(d).digest(16)),
    "SHAKE256": (32, lambda d: hashlib.shake_256(d).digest(32)),
    "GOST3411": (32, _gost3411_94),
    "KECCAK_224": (28, lambda d: _keccak(d, 144, 28)),
    "KECCAK_256": (32, lambda d: _keccak(d, 136, 32)),
    "KECCAK_384": (48, lambda d: _keccak(d, 104, 48)),
    "KECCAK_512": (64, lambda d: _keccak(d, 72, 64)),
    "TIGER": (24, _tiger),
}

for _k in EXTRA_HASH_ALGOS:
    ALGO_LABEL[_k] = _k


def _hash_once(algo: str, data: bytes) -> bytes:
    if algo in EXTRA_HASH_ALGOS:
        return EXTRA_HASH_ALGOS[algo][1](data)
    if algo not in HASH_ALGOS:
        raise ToolError(f"不支持的杂凑算法：{algo}")
    name = HASH_ALGOS[algo][0]
    if name == "sm3":
        return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))
    return hashlib.new(name, data).digest()


def digest(algo: str, data: bytes, salt: bytes = b"", site: str = "PRE", times: int = 1) -> bytes:
    if times is None or times == "":
        times = 1
    try:
        times = int(times)
    except (TypeError, ValueError):
        raise ToolError("迭代次数必须为整数")
    if times < 1:
        raise ToolError("迭代次数必须大于 0")
    if times > 10000:
        raise ToolError("迭代次数不能超过 10000")
    buf = (salt + data) if (site or "PRE").upper() in ("PRE", "FRONT", "前置") else (data + salt)
    out = _hash_once(algo, buf)
    for _ in range(times - 1):
        out = _hash_once(algo, out)
    return out


def digest_all(data: bytes, salt: bytes = b"", site: str = "PRE", times: int = 1) -> list[dict]:
    rows = []
    for algo in list(HASH_ALGOS) + list(EXTRA_HASH_ALGOS):
        try:
            value = digest(algo, data, salt, site, times).hex()
        except Exception:  # pragma: no cover - 防御
            continue
        rows.append({"algo": ALGO_LABEL[algo], "value": value, "bits": len(value) * 4})
    return rows


def hmac_digest(algo: str, data: bytes, key: bytes) -> bytes:
    if algo not in HASH_ALGOS:
        raise ToolError(f"不支持的杂凑算法：{algo}")
    if key is None or len(key) == 0:
        raise ToolError("请输入 HMAC 密钥")
    name = HASH_ALGOS[algo][0]
    if name == "sm3":
        # HMAC-SM3（RFC 2104 结构）
        block = 64
        if len(key) > block:
            key = _hash_once(algo, key)
        key = key.ljust(block, b"\x00")
        ipad = bytes(b ^ 0x36 for b in key)
        opad = bytes(b ^ 0x5C for b in key)
        return _hash_once(algo, opad + _hash_once(algo, ipad + data))
    return _hmac.new(key, data, name).digest()


def to_format(data: bytes, fmt: str = "HEX") -> str:
    import base64

    fmt = (fmt or "HEX").upper()
    if fmt in ("BASE64", "B64"):
        return base64.b64encode(data).decode()
    if fmt == "TEXT":
        return data.decode("utf-8", "replace")
    return data.hex()


__all__ = ["digest", "digest_all", "hmac_digest", "parse_bytes", "HASH_ALGOS",
           "EXTRA_HASH_ALGOS", "ALGO_LABEL"]
