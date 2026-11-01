/* SM9 算法 —— 标识密码（GB/T 38635 / GM/T 0044）
 * 参数展示 / 密钥生成 / 签名验签 / 加密解密 / 密钥封装 */
(function () {
  'use strict';
  const el = CB.el;

  const FMT_TEXT = [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']];
  const FMT_BIN = [['HEX', '十六进制'], ['BASE64', 'Base64']];

  /* 曲线参数（与后端 app/core/sm9.py 的 CURVE_INFO 一致） */
  const CURVE_ROWS = [
    ['曲线方程', 'y^2=x^3+b, 256位NB椭圆曲线'],
    ['嵌入度 t', '60000000 0058F98A'],
    ['素数 q', 'B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D'],
    ['阶 n', 'B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25'],
    ['G1生成元 xp1', '93DE051D 62BF718F F5ED0704 487D01D6 E1E40869 09DC3280 E8C4E481 7C66DDDD'],
    ['G1生成元 yp1', '21FE8DDA 4F21E607 63106512 5C395BBC 1C1C00CB FA602435 0C464CD7 0A3EA616'],
    ['G2生成元 xp2', '85AEF3D0 78640C98 597B6027 B441A01F F1DD2C19 0F5E93C4 54806C11 D8806141 '
      + '37227552 92130B08 D2AAB97F D34EC120 EE265948 D19C17AB F9B7213B AF82D65B'],
    ['G2生成元 yp2', '17509B09 2E845C12 66BA0D26 2CBEE6ED 0736A96F A347C8BD 856DC76B 84EBEB96 '
      + 'A7CF28D5 19BE3DA6 5F317015 3D278FF2 47EFBA98 A71A0811 6215BBA5 C999A7C7']
  ];

  /* 固定示例密钥（GB/T 38635 附录 A 的标准密钥对，保证示例可复现） */
  const DEMO = {
    /* 签名主私钥 ks */
    signMasterPri: '000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4',
    /* 签名主公钥 Ppubs = ks*P2 */
    signMasterPub: '049F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408'
      + '29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32'
      + '69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25'
      + '41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D',
    /* Alice 的签名私钥 ds */
    aliceSignKey: '04A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820'
      + '78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3',
    /* 加密主私钥 ke */
    encMasterPri: '0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22',
    /* 加密主公钥 Ppube = ke*P1 */
    encMasterPub: '04787ED7B8A51F3AB84E0A66003F32DA5C720B17ECA7137D39ABC66E3C80A892'
      + 'FF769DE61791E5ADC4B9FF85A31354900B202871279A8C49DC3F220F644C57A7B1',
    /* Bob 的加密私钥 de */
    bobEncKey: '0494736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683'
      + '115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158'
      + '7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F'
      + '27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1',
    /* 用固定随机数生成的示例密文 / 签名，可复现 */
    streamCipher: '2891A01520549D3D5C2CCF2FFC6641C41395C25E8A48BE18F1B8FC110546F3E2'
      + '68E275801636BE6D690C30EE841840263BCBE1D335FE9971F9658E383E5215F0'
      + 'B18154F488955476821F872655EF1F21D488DC19C661C7966265758141BB5843'
      + '3DCFC8126CDB75C1C6779B3E155A91',
    kemCipher: '04725EF9F4438D1E961511F9C6CA007E3A39FB57DF3DD8CBFAD85571299B1274'
      + '6868F624CD940B5D91CFA0A347715DA76DC104726DC1D5301902B733702026A6B5',
    signature: '9DAB10B4C3FF32A529A39DBE2593CF5B7143824C496B441B7CB5E9BC20581DCD'
      + '0461C4667E08F6E52261FE4CF7B8981E0E5D0527F1F834378117B970F7949DC5'
      + '3A7AF87FDE378AF0DE17B41D48EC5D1EDA838C672F6F074CEC6A3DB74C86BC1EAE',
    signatureDer: '306604209DAB10B4C3FF32A529A39DBE2593CF5B7143824C496B441B7CB5E9BC20581DCD'
      + '0342000461C4667E08F6E52261FE4CF7B8981E0E5D0527F1F834378117B970F7949DC53A7AF87FDE378AF0DE'
      + '17B41D48EC5D1EDA838C672F6F074CEC6A3DB74C86BC1EAE'
  };

  const TABS = [['enc', '加密解密'], ['kem', '密钥封装'], ['key', '密钥生成'], ['sign', '签名验签'], ['curve', '曲线参数']];
  const showOn = (...tabs) => (v) => tabs.indexOf(v.tab) >= 0;

  CB.register({
    key: 'sm9',
    cat: 'asym',
    title: 'SM9 算法',
    desc: '标识密码算法：曲线参数、主密钥与用户私钥、签名验签、加密解密、密钥封装',
    help: [
      {
        title: '输入格式',
        items: [
          '文本输入按 UTF-8 处理；十六进制输入必须为合法 HEX 字符串；Base64 输入必须为合法 Base64 编码。',
          '公钥支持带 04 前缀或不带前缀的非压缩编码形式（G1 点 65/64 字节，G2 点 129/128 字节）。',
          '用户标识 ID 的类型（字符串 / 十六进制 / Base64）必须与生成用户私钥时一致。'
        ]
      },
      {
        title: '使用提示',
        items: [
          '验签时签名值需要为 h||s 格式（32 字节 h + 65 字节 s）；若当前数据为 DER 编码，请先点击“转 h||s 格式”。',
          '解密时密文需要为裸密文格式：C1（64 字节）|| C3（32 字节）|| C2；若为 DER 编码请先转换。',
          '签名与加密分属两套主密钥：签名主密钥对应 G2 上的主公钥，加密主密钥对应 G1 上的主公钥，请勿混用。',
          '请留意用户标识等业务参数是否与生成阶段保持一致。'
        ]
      },
      {
        title: '算法说明',
        items: [
          '曲线为 256 位 BN 曲线 y^2=x^3+5，嵌入度 12，扩域塔 Fp2=Fp[u]/(u^2+2)、Fp4=Fp2[v]/(v^2-u)、Fp12=Fp4[w]/(w^3-v)。',
          '配对采用 R-ate（Miller 环长 6t+2），签名/验签、加解密、密钥封装均按 GB/T 38635 与 GM/T 0044 实现。',
          '加密模式：流模式按 C2 = M ⊕ KDF 计算；分组模式使用 SM4-ECB（PKCS#7 填充），两者完整性校验值均为 SM3(C2 || K2)。',
          '所有计算均在本地完成，密钥与数据不会上传。'
        ]
      }
    ],
    state: {
      tab: 'enc',
      encPublicKey: '', encPublicKeyFormat: 'HEX',
      encUserPrivateKey: '', encUserPrivateKeyFormat: 'HEX',
      encType: 'STREAM',
      userIdEnc: 'Bob', userIdEncFormat: 'TEXT',
      encMessage: '', encMessageFormat: 'TEXT',
      cipher: '', cipherFormat: 'HEX',
      klen: 16, kemKey: '', kemKeyFormat: 'HEX', kemCipher: '', kemCipherFormat: 'HEX',
      masterPublicKey: '', masterPublicKeyFormat: 'HEX',
      masterPrivateKey: '', masterPrivateKeyFormat: 'HEX',
      userKeyType: '1', userIdKey: 'Alice', userIdKeyFormat: 'TEXT',
      userPrivateKey: '', userPrivateKeyFormat: 'HEX',
      signPublicKey: '', signPublicKeyFormat: 'HEX',
      signUserPrivateKey: '', signUserPrivateKeyFormat: 'HEX',
      userIdSign: 'Alice', userIdSignFormat: 'TEXT',
      signMessage: '', signMessageFormat: 'TEXT',
      signature: '', signatureFormat: 'HEX'
    },
    fields: [
      { name: 'tab', label: '功能分组', type: 'radio', options: TABS, span: 2 },

      /* ---- 加密解密 / 密钥封装 ---- */
      {
        name: 'encPublicKey', label: '加密主公钥', type: 'key', formatField: 'encPublicKeyFormat',
        formats: FMT_BIN, placeholder: '请输入加密主公钥', span: 2, show: showOn('enc', 'kem')
      },
      {
        name: 'encUserPrivateKey', label: '用户加密私钥', type: 'key', formatField: 'encUserPrivateKeyFormat',
        formats: FMT_BIN, placeholder: '请输入用户加密私钥（解密 / 解封装用）', span: 2, show: showOn('enc', 'kem')
      },
      {
        name: 'encType', label: '加密模式', type: 'radio',
        options: [['BLOCK', '分组密码加密'], ['STREAM', '流密码加密']],
        show: showOn('enc')
      },
      {
        name: 'userIdEnc', label: '用户标识ID', type: 'key', formatField: 'userIdEncFormat',
        formats: FMT_TEXT, placeholder: '例如 Bob', show: showOn('enc', 'kem')
      },
      {
        name: 'encMessage', label: '消息', type: 'textarea', formatField: 'encMessageFormat',
        formats: FMT_TEXT, rows: 4, placeholder: '请输入加密原消息', show: showOn('enc')
      },
      {
        name: 'cipher', label: '密文', type: 'textarea', formatField: 'cipherFormat',
        formats: FMT_BIN, rows: 4, placeholder: 'C1 || C3 || C2 裸密文', show: showOn('enc')
      },
      {
        name: 'klen', label: '密钥长度', type: 'number', min: 8, max: 100, step: 1,
        tip: '单位：字节，范围 8~100', show: showOn('kem')
      },
      {
        name: 'kemCipher', label: '密钥封装密文', type: 'textarea', formatField: 'kemCipherFormat',
        formats: FMT_BIN, rows: 3, placeholder: '请输入密钥封装密文（G1 点）', show: showOn('kem')
      },
      {
        name: 'kemKey', label: '密钥原文', type: 'key', formatField: 'kemKeyFormat',
        formats: FMT_BIN, placeholder: '封装产生的密钥 / 解封装结果', span: 2, show: showOn('kem')
      },

      /* ---- 密钥生成 ---- */
      {
        name: 'masterPublicKey', label: '主公钥', type: 'key', formatField: 'masterPublicKeyFormat',
        formats: FMT_BIN, placeholder: '签名主公钥（129 字节 G2）或加密主公钥（65 字节 G1）',
        span: 2, show: showOn('key')
      },
      {
        name: 'masterPrivateKey', label: '主私钥', type: 'key', formatField: 'masterPrivateKeyFormat',
        formats: FMT_BIN, placeholder: '请输入主私钥（32 字节十六进制整数）', span: 2, show: showOn('key')
      },
      {
        name: 'userKeyType', label: '用户私钥类型', type: 'radio',
        options: [['1', '签名私钥'], ['2', '密钥交换中的加密私钥'], ['3', '解密与解封中的加密私钥']],
        span: 2, show: showOn('key')
      },
      {
        name: 'userIdKey', label: '用户标识ID', type: 'key', formatField: 'userIdKeyFormat',
        formats: FMT_TEXT, placeholder: '例如 Alice', show: showOn('key')
      },
      {
        name: 'userPrivateKey', label: '用户私钥', type: 'textarea', formatField: 'userPrivateKeyFormat',
        formats: FMT_BIN, rows: 3, placeholder: '生成结果（签名私钥为 G1 点，加密私钥为 G2 点）',
        span: 2, show: showOn('key')
      },

      /* ---- 签名验签 ---- */
      {
        name: 'signPublicKey', label: '签名主公钥', type: 'key', formatField: 'signPublicKeyFormat',
        formats: FMT_BIN, placeholder: '请输入签名主公钥（G2 点 129 字节）', span: 2, show: showOn('sign')
      },
      {
        name: 'signUserPrivateKey', label: '用户签名私钥', type: 'key', formatField: 'signUserPrivateKeyFormat',
        formats: FMT_BIN, placeholder: '请输入用户签名私钥（G1 点）', span: 2, show: showOn('sign')
      },
      {
        name: 'userIdSign', label: '用户标识ID', type: 'key', formatField: 'userIdSignFormat',
        formats: FMT_TEXT, placeholder: '例如 Alice', show: showOn('sign')
      },
      {
        name: 'signMessage', label: '消息', type: 'textarea', formatField: 'signMessageFormat',
        formats: FMT_TEXT, rows: 3, placeholder: '请输入签名原消息', span: 2, show: showOn('sign')
      },
      {
        name: 'signature', label: '签名值', type: 'textarea', formatField: 'signatureFormat',
        formats: FMT_BIN, rows: 4, span: 2,
        hint: '签名值包含 h、s 两部分，前 32 字节为 h，后 65 字节为 s（04 前缀）',
        placeholder: '请输入裸签名值 h||s 或 DER 编码', show: showOn('sign')
      }
    ],
    actions: [
      {
        name: 'encrypt', label: '加密', primary: true, run: async (ctx) => {
          const data = await CB.api('/api/sm9/encrypt', {
            publicKey: ctx.val('encPublicKey'), publicKeyFormat: ctx.val('encPublicKeyFormat'),
            userId: ctx.val('userIdEnc'), userIdFormat: ctx.val('userIdEncFormat'),
            message: ctx.val('encMessage'), messageFormat: ctx.val('encMessageFormat'),
            cipherFormat: ctx.val('cipherFormat'), encType: ctx.val('encType')
          });
          ctx.set('cipher', data);
          ctx.setResult('cipherOut', data);
          CB.toast('SM9 加密成功', 'success');
        }
      },
      {
        name: 'decrypt', label: '解密', run: async (ctx) => {
          const data = await CB.api('/api/sm9/decrypt', {
            userPrivateKey: ctx.val('encUserPrivateKey'), userPrivateKeyFormat: ctx.val('encUserPrivateKeyFormat'),
            userId: ctx.val('userIdEnc'), userIdFormat: ctx.val('userIdEncFormat'),
            cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
            messageFormat: ctx.val('encMessageFormat'), encType: ctx.val('encType')
          });
          ctx.set('encMessage', data);
          ctx.setResult('plainOut', data);
          CB.toast('SM9 解密成功', 'success');
        }
      },
      {
        name: 'keyEncaps', label: '封装', run: async (ctx) => {
          const data = await CB.api('/api/sm9/key/enc', {
            publicKey: ctx.val('encPublicKey'), publicKeyFormat: ctx.val('encPublicKeyFormat'),
            userId: ctx.val('userIdEnc'), userIdFormat: ctx.val('userIdEncFormat'),
            cipherFormat: ctx.val('kemCipherFormat'), keyFormat: ctx.val('kemKeyFormat'),
            klen: ctx.val('klen')
          });
          ctx.set('kemCipher', data.cipher);
          ctx.set('kemKey', data.key);
          ctx.setResult('kemCipherOut', data.cipher);
          ctx.setResult('kemKeyOut', data.key);
          CB.toast('SM9 密钥封装成功', 'success');
        }
      },
      {
        name: 'keyDecaps', label: '解封装', run: async (ctx) => {
          const data = await CB.api('/api/sm9/key/dec', {
            userPrivateKey: ctx.val('encUserPrivateKey'), userPrivateKeyFormat: ctx.val('encUserPrivateKeyFormat'),
            userId: ctx.val('userIdEnc'), userIdFormat: ctx.val('userIdEncFormat'),
            cipher: ctx.val('kemCipher'), cipherFormat: ctx.val('kemCipherFormat'),
            keyFormat: ctx.val('kemKeyFormat'), klen: ctx.val('klen')
          });
          ctx.set('kemKey', data);
          ctx.setResult('kemKeyOut', data);
          CB.toast('SM9 解封装成功', 'success');
        }
      },
      {
        name: 'genSignMaster', label: '生成签名主密钥对', run: async (ctx) => {
          const data = await CB.api('/api/sm9/generate/master/keypair', {
            type: 'SIGN', publicKeyFormat: ctx.val('masterPublicKeyFormat'),
            privateKeyFormat: ctx.val('masterPrivateKeyFormat')
          });
          ctx.set('masterPublicKey', data.pubKey);
          ctx.set('masterPrivateKey', data.priKey);
          ctx.setResult('masterPubOut', data.pubKey);
          ctx.setResult('masterPriOut', data.priKey);
          CB.toast('签名主密钥对生成成功', 'success');
        }
      },
      {
        name: 'genEncMaster', label: '生成加密主密钥对', run: async (ctx) => {
          const data = await CB.api('/api/sm9/generate/master/keypair', {
            type: 'ENC', publicKeyFormat: ctx.val('masterPublicKeyFormat'),
            privateKeyFormat: ctx.val('masterPrivateKeyFormat')
          });
          ctx.set('masterPublicKey', data.pubKey);
          ctx.set('masterPrivateKey', data.priKey);
          ctx.setResult('masterPubOut', data.pubKey);
          ctx.setResult('masterPriOut', data.priKey);
          CB.toast('加密主密钥对生成成功', 'success');
        }
      },
      {
        name: 'genUserKey', label: '生成用户私钥', run: async (ctx) => {
          const data = await CB.api('/api/sm9/generate/user/Key', {
            privateKeyFormat: ctx.val('masterPrivateKeyFormat'), privateKey: ctx.val('masterPrivateKey'),
            userId: ctx.val('userIdKey'), userIdFormat: ctx.val('userIdKeyFormat'),
            userPrivateKeyFormat: ctx.val('userPrivateKeyFormat'), userKeyType: ctx.val('userKeyType')
          });
          ctx.set('userPrivateKey', data);
          ctx.setResult('userPriOut', data);
          CB.toast('用户私钥生成成功', 'success');
        }
      },
      {
        name: 'sign', label: '签名', run: async (ctx) => {
          const data = await CB.api('/api/sm9/sign', {
            publicKey: ctx.val('signPublicKey'), publicKeyFormat: ctx.val('signPublicKeyFormat'),
            userPrivateKey: ctx.val('signUserPrivateKey'), userPrivateKeyFormat: ctx.val('signUserPrivateKeyFormat'),
            userId: ctx.val('userIdSign'), userIdFormat: ctx.val('userIdSignFormat'),
            message: ctx.val('signMessage'), messageFormat: ctx.val('signMessageFormat'),
            signatureFormat: ctx.val('signatureFormat')
          });
          ctx.set('signature', data);
          ctx.setResult('signatureOut', data);
          CB.toast('SM9 签名成功', 'success');
        }
      },
      {
        name: 'verify', label: '验签', run: async (ctx) => {
          try {
            const data = await CB.api('/api/sm9/verify', {
              publicKey: ctx.val('signPublicKey'), publicKeyFormat: ctx.val('signPublicKeyFormat'),
              userId: ctx.val('userIdSign'), userIdFormat: ctx.val('userIdSignFormat'),
              message: ctx.val('signMessage'), messageFormat: ctx.val('signMessageFormat'),
              signature: ctx.val('signature'), signatureFormat: ctx.val('signatureFormat')
            });
            ctx.setResult('verifyOut', '验证通过');
            CB.toast(data || '验证通过', 'success');
          } catch (err) {
            ctx.setResult('verifyOut', '验证不通过');
            CB.toast((err && err.message) || '验证不通过', 'error');
          }
        }
      },
      {
        name: 'toDer', label: '转 DER 编码', run: async (ctx) => {
          const data = await CB.api('/api/sm9/signature/convert', {
            signature: ctx.val('signature'), signatureFormat: ctx.val('signatureFormat'), targetFormat: 'DER'
          });
          ctx.set('signature', data);
          ctx.setResult('signatureOut', data);
          CB.toast('已转换为 DER 编码', 'success');
        }
      },
      {
        name: 'toRaw', label: '转 h||s 格式', run: async (ctx) => {
          const data = await CB.api('/api/sm9/signature/convert', {
            signature: ctx.val('signature'), signatureFormat: ctx.val('signatureFormat'), targetFormat: 'RAW'
          });
          ctx.set('signature', data);
          ctx.setResult('signatureOut', data);
          CB.toast('已转换为 h||s 格式', 'success');
        }
      },
      {
        name: 'loadParams', label: '读取曲线参数', run: async (ctx) => {
          const data = await CB.api('/api/sm9/params', {});
          const rows = (data.curve || []).map((r) => [r.name, r.value]);
          ctx.setResult('curveTable', rows);
          CB.toast('曲线参数已刷新', 'success');
        }
      }
    ],
    results: [
      { name: 'cipherOut', label: '加密结果（密文）', type: 'textarea', rows: 4 },
      { name: 'plainOut', label: '解密结果（明文）', type: 'textarea', rows: 3 },
      { name: 'kemCipherOut', label: '封装密文', type: 'textarea', rows: 3 },
      { name: 'kemKeyOut', label: '封装 / 解封密钥', type: 'textarea', rows: 2 },
      { name: 'masterPubOut', label: '主公钥', type: 'textarea', rows: 3 },
      { name: 'masterPriOut', label: '主私钥', type: 'textarea', rows: 2 },
      { name: 'userPriOut', label: '用户私钥', type: 'textarea', rows: 3 },
      { name: 'signatureOut', label: '签名值', type: 'textarea', rows: 4 },
      { name: 'verifyOut', label: '验签结果', type: 'text' },
      {
        name: 'curveTable', type: 'custom',
        render: (box, ctx) => {
          const wrap = el('div', { 'data-result': 'curveTable' });
          box.appendChild(wrap);
          const paint = (rows) => {
            wrap.innerHTML = '';
            const data = rows || CURVE_ROWS;
            const table = el('table', { class: 'grid' });
            table.appendChild(el('thead', {}, [
              el('tr', {}, [el('th', {}, ['参数']), el('th', {}, ['取值'])])
            ]));
            const tbody = el('tbody', {});
            data.forEach((r) => {
              tbody.appendChild(el('tr', {}, [
                el('td', {}, [r[0]]),
                el('td', { class: 'mono' }, [r[1]])
              ]));
            });
            table.appendChild(tbody);
            wrap.appendChild(table);
          };
          paint(CURVE_ROWS);
          ctx.onResult = (name, value) => { if (name === 'curveTable') paint(value); };
        }
      }
    ],
    samples: {
      encrypt: {
        tab: 'enc', encPublicKey: DEMO.encMasterPub, encType: 'STREAM',
        userIdEnc: 'Bob', encMessage: 'SM9 加密示例'
      },
      decrypt: {
        tab: 'enc', encUserPrivateKey: DEMO.bobEncKey, encType: 'STREAM',
        userIdEnc: 'Bob', cipher: DEMO.streamCipher
      },
      keyEncaps: {
        tab: 'kem', encPublicKey: DEMO.encMasterPub, userIdEnc: 'Bob', klen: 16
      },
      keyDecaps: {
        tab: 'kem', encUserPrivateKey: DEMO.bobEncKey, userIdEnc: 'Bob',
        kemCipher: DEMO.kemCipher, klen: 16
      },
      genSignMaster: { tab: 'key', masterPrivateKey: DEMO.signMasterPri },
      genEncMaster: { tab: 'key', masterPrivateKey: DEMO.encMasterPri },
      genUserKey: {
        tab: 'key', masterPrivateKey: DEMO.signMasterPri, userIdKey: 'Alice', userKeyType: '1'
      },
      sign: {
        tab: 'sign', signPublicKey: DEMO.signMasterPub, signUserPrivateKey: DEMO.aliceSignKey,
        userIdSign: 'Alice', signMessage: 'Chinese IBS standard'
      },
      verify: {
        tab: 'sign', signPublicKey: DEMO.signMasterPub, userIdSign: 'Alice',
        signMessage: 'Chinese IBS standard', signature: DEMO.signature
      },
      toDer: { tab: 'sign', signature: DEMO.signature },
      toRaw: { tab: 'sign', signature: DEMO.signatureDer },
      loadParams: { tab: 'curve' }
    }
  });
})();
