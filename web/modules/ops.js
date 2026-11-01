/* 能力验证必备：PRF / KDF / TLCP 密钥生成 / SM2 加密 k / 签名攻击 / 点运算 / PBKDF2 / 工作模式检测 */
(function () {
  'use strict';
  const el = CB.el;

  const FORMATS_IN = [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']];
  const FORMATS_BYTES = [['HEX', '十六进制'], ['BASE64', 'Base64']];
  const HASH_PRF = [['SM3', 'SM3'], ['SHA256', 'SHA-256'], ['SHA384', 'SHA-384'], ['SHA512', 'SHA-512'], ['SHA', 'SHA-1']];

  /* ============================ 1. PRF ============================ */
  CB.register({
    key: 'prf',
    cat: 'ability',
    title: '伪随机函数 PRF',
    desc: '按 GB/T 32918 / GM/T 0042 的 HMAC 迭代结构扩展密钥，输出长度 = 轮数 × 摘要长度',
    help: [
      { title: '适用场景', items: ['PRF 常用于 TLCP / TLS 一类协议中的主密钥和密钥块扩展。', '本页与 TLCP 页共用同一套 PRF 运算，可先用固定输入验证结果，再推导主密钥。'] },
      { title: '参数说明', items: ['构造方式支持 HMAC 迭代 PRF（默认，GB/T 32918 / GM/T 0042 的 P_hash 结构）与直接 SM3 迭代 PRF 两种。', 'Key 与 Seed 支持字符串、HEX、Base64 三种格式。', 'Label 为常量字符串，默认（后置）参与运算时放在 Seed 之后，与协议接口输出一致。', '选择「前置」则按 GM/T 0024 的 master secret / key expansion 写法把 Label 放在 Seed 之前。'] },
      { title: '长度建议', items: ['Key、Seed 最多 500 个字符，Label 最多 200 个字符。', '迭代轮数 1~10，每轮输出一个摘要长度（SM3 为 32 字节）。'] }
    ],
    state: {
      type: 'SM3', key: '', keyFormat: 'HEX', seed: '', seedFormat: 'TEXT',
      lable: '', labelSite: 'POST', prfMode: 'HMAC', rounds: 4, resultFormat: 'HEX'
    },
    fields: [
      { name: 'type', label: '摘要算法', type: 'radio', options: HASH_PRF, span: 2 },
      { name: 'prfMode', label: '构造方式', type: 'radio', options: [['HMAC', 'HMAC 迭代 PRF'], ['ITER', 'SM3 迭代 PRF']], span: 2 },
      { name: 'key', label: 'Key', type: 'key', formatField: 'keyFormat', formats: FORMATS_IN, placeholder: '请输入 Key' },
      { name: 'seed', label: 'Seed', type: 'textarea', formatField: 'seedFormat', formats: FORMATS_IN, rows: 3, placeholder: '请输入 Seed' },
      { name: 'lable', label: 'Label（字符串）', type: 'input', placeholder: '请输入 Label' },
      { name: 'rounds', label: '迭代轮数', type: 'number', min: 1, max: 10 },
      { name: 'labelSite', label: 'Label 位置', type: 'radio', options: [['POST', '后置（原站默认）'], ['PRE', '前置（GM/T 0024）']], span: 2 },
      { name: 'resultFormat', label: '结果格式', type: 'radio', options: FORMATS_BYTES }
    ],
    actions: [
      {
        name: 'run', label: '执行 PRF', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/prf', {
            type: ctx.val('type'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            seed: ctx.val('seed'), seedFormat: ctx.val('seedFormat'),
            lable: ctx.val('lable'), labelSite: ctx.val('labelSite'), prfMode: ctx.val('prfMode'),
            rounds: ctx.val('rounds'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data);
          CB.toast('PRF 计算成功', 'success');
        }
      }
    ],
    results: [{ name: 'result', label: 'PRF 结果', type: 'textarea', rows: 6 }],
    samples: {
      run: {
        type: 'SM3', key: '6b6579', seed: 'abc', prfMode: 'HMAC',
        lable: '', labelSite: 'POST', rounds: 2
      }
    }
  });

  /* ============================ 2. KDF ============================ */
  CB.register({
    key: 'kdf',
    cat: 'ability',
    title: '密钥派生函数 KDF',
    desc: 'SM3-KDF（GB/T 32918.4）/ SHA-256 迭代 KDF / HKDF-SHA256 / X9.63-KDF',
    help: [
      { title: '标准依据', items: ['GB/T 32918.4 的 KDF：Ha_i = SM3(Z || CT_i)，CT 为 32 位大端计数器，从 1 开始。', 'HKDF-SHA256 按 RFC 5869 执行 extract + expand，Salt 与 SharedInfo 均为可选项。', 'X9.63-KDF 使用 SHA-256：Hash(Z || CT_i || SharedInfo)。'] },
      { title: '输入说明', items: ['Z 为参与派生的共享比特串（一般为 SM2 密钥交换得到的 x2||y2），支持 HEX 与 Base64。', '输出长度按字节填写，最大 4096 字节。', 'SharedInfo 为空时，SM3-KDF 与 SHA-256 迭代 KDF 的输出与原站接口一致。'] },
      { title: '结果说明', items: ['派生结果为十六进制或 Base64，可直接复制到对称算法页作为密钥或 IV 使用。'] }
    ],
    state: {
      type: 'SM3', message: '', messageFormat: 'HEX', sharedInfo: '', sharedInfoFormat: 'HEX',
      salt: '', saltFormat: 'HEX', length: 32, resultFormat: 'HEX'
    },
    fields: [
      { name: 'type', label: '派生算法', type: 'radio', options: [['SM3', 'SM3-KDF'], ['SHA256', 'SHA-256 KDF'], ['HKDF', 'HKDF-SHA256'], ['X963', 'X9.63-KDF']], span: 2 },
      { name: 'message', label: '比特串 Z', type: 'textarea', formatField: 'messageFormat', formats: FORMATS_BYTES, rows: 4, placeholder: '请输入待派生的共享比特串 Z' },
      { name: 'length', label: '输出长度（字节）', type: 'number', min: 1, max: 4096 },
      { name: 'sharedInfo', label: 'SharedInfo（可选）', type: 'textarea', formatField: 'sharedInfoFormat', formats: FORMATS_BYTES, rows: 2, placeholder: '可选，参与派生的共享信息' },
      { name: 'salt', label: 'Salt（HKDF 可选）', type: 'textarea', formatField: 'saltFormat', formats: FORMATS_BYTES, rows: 2, placeholder: '可选，仅 HKDF 使用；为空时按全零盐值处理' },
      { name: 'resultFormat', label: '结果格式', type: 'radio', options: FORMATS_BYTES }
    ],
    actions: [
      {
        name: 'run', label: '执行 KDF', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/kdf', {
            type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            sharedInfo: ctx.val('sharedInfo'), sharedInfoFormat: ctx.val('sharedInfoFormat'),
            salt: ctx.val('salt'), saltFormat: ctx.val('saltFormat'),
            length: ctx.val('length'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data);
          CB.toast('KDF 计算成功', 'success');
        }
      }
    ],
    results: [{ name: 'result', label: '派生结果 t', type: 'textarea', rows: 6 }],
    samples: {
      run: { type: 'SM3', message: '0102030405060708', sharedInfo: '', length: 32 }
    }
  });

  /* ============================ 3. TLCP ============================ */
  const TLCP_MASTER_SAMPLE = '2e60036cab78c77e9557d5f13c1446c0f8c972049f65f22d2d5b99f10d6bf1c3462d7fa3ab0dd5bf344aa57dd50eb28f';

  CB.register({
    key: 'tlcp',
    cat: 'ability',
    title: 'TLCP / TLS 密钥生成',
    desc: 'pre_master_secret + 随机数 → 主密钥 → 密钥块（写密钥 / IV / MAC Secret）',
    help: [
      { title: '计算流程', items: ['master_secret = PRF(pre_master_secret, "master secret", ClientRandom || ServerRandom)，取前 48 字节。', 'key_block = PRF(master_secret, "key expansion", ServerRandom || ClientRandom)，按套件切分。', '随机数、预主密钥、主密钥均为十六进制输入。'] },
      { title: '默认常量', items: ['常量字符串 1 默认 master secret，常量字符串 2 默认 key expansion，可直接按 TLCP 1.1 流程计算。', 'PRF 摘要可选 SM3（TLCP 默认）或 SHA-256。'] },
      { title: '结果说明', items: ['分组套件：MAC Secret 32 字节 + 写密钥 16 字节 + IV 16 字节，两组共 128 字节密钥块。', 'GCM（AEAD）套件：无 MAC Secret，写密钥 16 字节 + IV 4 字节，两组共 40 字节密钥块。'] }
    ],
    state: {
      type: 'SM3', clientRandom: '', serverRandom: '', preMasterKey: '',
      cipherSuiteType: '1', str1: 'master secret', str2: 'key expansion', masterKey: ''
    },
    fields: [
      { name: 'type', label: '摘要算法', type: 'radio', options: [['SM3', 'SM3'], ['SHA256', 'SHA-256']], span: 2 },
      { name: 'clientRandom', label: '客户端随机数（十六进制）', type: 'input', placeholder: '请输入 ClientHello.random' },
      { name: 'serverRandom', label: '服务端随机数（十六进制）', type: 'input', placeholder: '请输入 ServerHello.random' },
      { name: 'preMasterKey', label: '预主密钥（十六进制）', type: 'input', placeholder: '请输入 pre_master_secret' },
      { name: 'cipherSuiteType', label: '密码套件类型', type: 'radio', options: [['1', '分组算法'], ['2', 'GCM（AEAD）']] },
      { name: 'str1', label: '常量字符串 1', type: 'input', placeholder: 'master secret' },
      { name: 'str2', label: '常量字符串 2', type: 'input', placeholder: 'key expansion' },
      { name: 'masterKey', label: '主密钥（十六进制）', type: 'input', placeholder: '点击“计算主密钥”后可自动回填' }
    ],
    actions: [
      {
        name: 'master', label: '计算主密钥', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/tlcp/master', {
            type: ctx.val('type'), clientRandom: ctx.val('clientRandom'), serverRandom: ctx.val('serverRandom'),
            preMasterKey: ctx.val('preMasterKey'), str1: ctx.val('str1')
          });
          ctx.set('masterKey', data);
          ctx.setResult('master', data);
          ctx.refresh();
          CB.toast('主密钥计算成功', 'success');
        }
      },
      {
        name: 'keys', label: '计算会话密钥',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/tlcp/keys', {
            type: ctx.val('type'), masterKey: ctx.val('masterKey'),
            clientRandom: ctx.val('clientRandom'), serverRandom: ctx.val('serverRandom'),
            str2: ctx.val('str2'), cipherSuiteType: ctx.val('cipherSuiteType')
          });
          ctx.setResult('master', data.masterKey || '');
          const lines = [
            'master_secret           = ' + (data.masterKey || ''),
            'client_write_mac_secret = ' + (data.clientWriteMacSecret || '（AEAD 套件无 MAC Secret）'),
            'server_write_mac_secret = ' + (data.serverWriteMacSecret || '（AEAD 套件无 MAC Secret）'),
            'client_write_key        = ' + (data.clientWritekey || ''),
            'server_write_key        = ' + (data.serverWritekey || ''),
            'client_write_iv         = ' + (data.clientWriteIv || ''),
            'server_write_iv         = ' + (data.serverWriteIv || ''),
            '',
            '密钥块长度 = ' + data.length + ' 字节（套件：' + data.suite + '）',
            'key_block  = ' + (data.keyBlock || '')
          ];
          ctx.setResult('keyblock', lines.join('\n'));
          CB.toast('会话密钥计算成功', 'success');
        }
      }
    ],
    results: [
      { name: 'master', label: 'master_secret', type: 'textarea', rows: 2 },
      { name: 'keyblock', label: '密钥块明细', type: 'textarea', rows: 10 }
    ],
    samples: {
      master: {
        type: 'SM3', clientRandom: '00'.repeat(32), serverRandom: '11'.repeat(32),
        preMasterKey: '22'.repeat(32), str1: 'master secret'
      },
      keys: {
        type: 'SM3', masterKey: TLCP_MASTER_SAMPLE, clientRandom: '00'.repeat(32),
        serverRandom: '11'.repeat(32), str2: 'key expansion', cipherSuiteType: '1'
      }
    }
  });

  /* ============================ 4. SM2 加密 k ============================ */
  const SM2_PUB = '0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13';
  const SM2_CT_C1 = 'fb9bbd2a90f301b7379fde2a8b47de3915b60df226c126fd9d4e8550412ce8f85530d349c076575bea6eb5df2e4b111a3df7e22dd19d8f47e56982f10b2d9ac5';
  const SM2_CT = '04' + SM2_CT_C1 + '93be4dc94c01332b77f8376b3b27bccecedf57c6132e918345b3aca80af6b738a253fcb68c0de9d955358315357c687a';
  const SM2_CT2 = '04' + SM2_CT_C1 + '68b96d6d96430c83e3b42a844077c570c198dccfb6a7762f1923aa94222ea0afb953f3b58d499af902669b49632b7b3de29b5219b6';

  CB.register({
    key: 'sm2k',
    cat: 'ability',
    title: 'SM2 加密 k 碰撞分析',
    desc: '按 C1 碰撞随机数 k、恢复明文、检测两组密文是否复用同一 k',
    help: [
      { title: '功能说明', items: ['本页用于分析 SM2 加密中随机数 k 取值过小或可复用的风险：可从 C1 部分逐点累加碰撞出 k，也可进一步恢复明文。', '检测 k 复用则是比较两组密文的 C1 是否相同：相同即说明两次加密用了同一个 k。'] },
      { title: '输入要求', items: ['C1 支持 65 字节（04||X||Y）与 64 字节（X||Y）两种写法，与原站接口兼容。', '只碰撞 k 时输入 C1 即可；恢复明文需要完整密文（C1C3C2）与加密公钥。', '碰撞上限默认 65536，越大越慢；原站接口只支持 k ≤ 100。'] },
      { title: '结果说明', items: ['恢复明文时会用 C3 做完整性校验，校验通过才输出明文。', '未碰撞到时请增大上限，或确认 C1 与曲线是否匹配。'] }
    ],
    state: {
      cipher: '', cipherFormat: 'HEX', cipher2: '', cipher2Format: 'HEX',
      publicKey: '', publicKeyFormat: 'HEX', maxK: 65536, resultFormat: 'TEXT'
    },
    fields: [
      { name: 'cipher', label: '密文或 C1 部分', type: 'textarea', formatField: 'cipherFormat', formats: FORMATS_BYTES, rows: 3, placeholder: '请输入完整密文，或仅输入 C1 部分' },
      { name: 'cipher2', label: '第二组密文（检测 k 复用用）', type: 'textarea', formatField: 'cipher2Format', formats: FORMATS_BYTES, rows: 3, placeholder: '可选，用于比较两组密文的 C1 是否相同' },
      { name: 'publicKey', label: '公钥', type: 'key', formatField: 'publicKeyFormat', formats: FORMATS_BYTES, placeholder: '请输入用于加密的公钥（04 开头）' },
      { name: 'maxK', label: '碰撞上限', type: 'number', min: 1, max: 1048576 },
      { name: 'resultFormat', label: '明文输出格式', type: 'radio', options: FORMATS_IN }
    ],
    actions: [
      {
        name: 'k', label: '碰撞随机数 k', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/sm2k/collision', {
            cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
            publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
            maxK: ctx.val('maxK')
          });
          ctx.setResult('result', 'k = ' + parseInt(data.k, 16) + '\n0x' + data.k);
          ctx.setResult('detail', data.detail || '');
          CB.toast('碰撞计算成功', 'success');
        }
      },
      {
        name: 'recover', label: '尝试恢复明文',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/sm2k/recover', {
            cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
            publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat'),
            maxK: ctx.val('maxK'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data.result || '（未恢复出明文）');
          ctx.setResult('detail', data.detail || '');
          CB.toast('明文恢复完成', 'success');
        }
      },
      {
        name: 'reuse', label: '检测 k 复用',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/sm2k/reuse', {
            cipher: ctx.val('cipher'), cipherFormat: ctx.val('cipherFormat'),
            cipher2: ctx.val('cipher2'), cipher2Format: ctx.val('cipher2Format'),
            publicKey: ctx.val('publicKey'), publicKeyFormat: ctx.val('publicKeyFormat')
          });
          ctx.setResult('result', data.reuse ? '检测结果：两组密文复用同一随机数 k' : '检测结果：未发现随机数 k 复用');
          ctx.setResult('detail', data.detail || '');
          CB.toast('k 复用检测完成', 'success');
        }
      }
    ],
    results: [
      { name: 'result', label: '碰撞 / 恢复结果', type: 'textarea', rows: 4 },
      { name: 'detail', label: '分析明细', type: 'textarea', rows: 6 }
    ],
    samples: {
      k: { cipher: SM2_CT_C1, cipher2: '', publicKey: SM2_PUB, maxK: 2000 },
      recover: { cipher: SM2_CT, publicKey: SM2_PUB, maxK: 2000 },
      reuse: { cipher: SM2_CT, cipher2: SM2_CT2, publicKey: SM2_PUB }
    }
  });

  /* ============================ 5. 签名攻击 unravelSm2 ============================ */
  const SIG1 = '8d7181485e545b57967faf05a6850cd89ac133bdbb1fbe3d3fd060cd39049971648900834c2b86194ef4f71a35b82c2882471d1677c9383492ff6724c7c2cc16';
  const SIG2 = '9e8292596f656c68a790c016b7961de9abd244cecc30cf4e50e171de4a15aa8259131576686c29b42c2d142d74ed3a3649814ad4fcedc84e831b86694e6893fc';
  const E1 = '11'.repeat(32);
  const E2 = '22'.repeat(32);
  const D_SAMPLE = '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8';
  const K_SAMPLE = '1f2e3d4c5b6a79880f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a6978';
  const EESS1 = SIG1 + E1;
  const EESS2 = SIG2 + E2;
  const DER1 = '30450221008d7181485e545b57967faf05a6850cd89ac133bdbb1fbe3d3fd060cd390499710220648900834c2b86194ef4f71a35b82c2882471d1677c9383492ff6724c7c2cc16';

  function sigResult(ctx, data, mainKey) {
    const val = data[mainKey] || '';
    ctx.setResult('key', val);
    const rest = Object.assign({}, data);
    delete rest[mainKey];
    ctx.setResult('extra', JSON.stringify(rest, null, 2));
    CB.toast('计算成功', 'success');
  }

  CB.register({
    key: 'unravelSm2',
    cat: 'ability',
    title: 'SM2 签名攻击推导',
    desc: 'k 复用 / 弱随机数反推私钥 d，支持 rs→d、eess→d、rsd→k、rsd1→d2 与 DER 互转',
    help: [
      { title: '数据格式', items: ['所有输入均为十六进制字符串。', '签名值按 R||S 共 64 字节输入；EESS 按 R||S||E 共 96 字节输入（与原站一致）。'] },
      { title: '数学原理', items: ['SM2 签名：r = (e + x1) mod n，s = ((1+d)^-1 · (k - r·d)) mod n。', '两组签名复用同一 k 时：(s1-s2)·(1+d) = (r2-r1)·d，故 d = (s1-s2)/(r2-r1-s1+s2) mod n。', '已知 r、s、k 时：d = (k-s)/(r+s) mod n；已知 r、s、d 时：k = s·(1+d) + r·d mod n。'] },
      { title: '交叉验证', items: ['推导结果会同时给出由 d 计算的公钥，可用「验签」按钮结合公钥确认。', '页面计算成功不代表私钥一定正确，最终仍需结合公钥推导结果进行交叉验证。'] }
    ],
    state: { macOne: '', macTwo: '', signOne: '', signTwo: '', key: '', random: '', publicKey: '' },
    fields: [
      { name: 'macOne', label: 'e 值（第一组）', type: 'input', placeholder: '请输入第一组 e 值（十六进制）' },
      { name: 'macTwo', label: 'e 值（第二组）', type: 'input', placeholder: '请输入第二组 e 值（十六进制）' },
      { name: 'signOne', label: '签名值 R||S / EESS（第一组）', type: 'textarea', rows: 2, placeholder: '请输入第一组签名值（R||S 或 R||S||E）' },
      { name: 'signTwo', label: '签名值 R||S / EESS（第二组）', type: 'textarea', rows: 2, placeholder: '请输入第二组签名值（R||S 或 R||S||E）' },
      { name: 'key', label: '私钥 d', type: 'input', placeholder: '请输入私钥 d（十六进制）' },
      { name: 'random', label: '随机数 k', type: 'input', placeholder: '请输入随机数 k（十六进制）' },
      { name: 'publicKey', label: '公钥（验签用）', type: 'input', placeholder: '04 开头的未压缩公钥' }
    ],
    actions: [
      {
        name: 'rrss', label: 'rrss → d', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/rrss', {
            signOne: ctx.val('signOne'), signTwo: ctx.val('signTwo'),
            macOne: ctx.val('macOne'), macTwo: ctx.val('macTwo')
          });
          ctx.set('key', data.d); ctx.set('random', data.k);
          ctx.refresh();
          sigResult(ctx, data, 'd');
        }
      },
      {
        name: 'eess', label: 'eess → d',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/eess', {
            signOne: ctx.val('signOne'), signTwo: ctx.val('signTwo'),
            macOne: ctx.val('macOne'), macTwo: ctx.val('macTwo')
          });
          ctx.set('key', data.d); ctx.set('random', data.k);
          ctx.refresh();
          sigResult(ctx, data, 'd');
        }
      },
      {
        name: 'rsk', label: 'rsk → d',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/rsk', {
            signOne: ctx.val('signOne'), random: ctx.val('random')
          });
          ctx.set('key', data.d);
          ctx.refresh();
          sigResult(ctx, data, 'd');
        }
      },
      {
        name: 'rsd', label: 'rsd → k',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/rsd', {
            signOne: ctx.val('signOne'), key: ctx.val('key')
          });
          ctx.set('random', data.k);
          ctx.refresh();
          sigResult(ctx, data, 'k');
        }
      },
      {
        name: 'rsd1', label: 'rsd1 → d2',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/rsd1', {
            signOne: ctx.val('signOne'), key: ctx.val('key'), signTwo: ctx.val('signTwo')
          });
          ctx.set('key', data.d2 || data.d);
          ctx.refresh();
          sigResult(ctx, data, 'd2');
        }
      },
      {
        name: 'rs2der', label: 'R||S → DER',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/rs2der', { signOne: ctx.val('signOne'), resultFormat: 'HEX' });
          ctx.setResult('key', data);
          ctx.setResult('extra', '已转为 ASN.1 DER：SEQUENCE { INTEGER r, INTEGER s }');
          CB.toast('DER 转换成功', 'success');
        }
      },
      {
        name: 'der2rs', label: 'DER → R||S',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/der2rs', { signOne: ctx.val('signOne') });
          ctx.setResult('key', data.rs);
          ctx.setResult('extra', JSON.stringify({ r: data.r, s: data.s }, null, 2));
          CB.toast('R||S 转换成功', 'success');
        }
      },
      {
        name: 'eess2der', label: 'EESS → DER',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/eess2der', { signOne: ctx.val('signOne'), resultFormat: 'HEX' });
          ctx.setResult('key', data);
          ctx.setResult('extra', 'EESS 中的 R||S 已转为 DER，e 值不进入 DER 编码');
          CB.toast('DER 转换成功', 'success');
        }
      },
      {
        name: 'der2eess', label: 'DER → EESS',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/der2eess', { signOne: ctx.val('signOne'), macOne: ctx.val('macOne'), resultFormat: 'HEX' });
          ctx.setResult('key', data);
          ctx.setResult('extra', '已按 R||S||E 布局输出，e 值取自「e 值（第一组）」');
          CB.toast('EESS 转换成功', 'success');
        }
      },
      {
        name: 'verify', label: '验签',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/unravel/verify', {
            signOne: ctx.val('signOne'), macOne: ctx.val('macOne'), publicKey: ctx.val('publicKey')
          });
          ctx.setResult('key', data.detail);
          ctx.setResult('extra', JSON.stringify({ valid: data.valid }, null, 2));
          CB.toast(data.valid ? '签名验证通过' : '签名验证未通过', data.valid ? 'success' : 'warn');
        }
      }
    ],
    results: [
      { name: 'key', label: '推导结果', type: 'textarea', rows: 3 },
      { name: 'extra', label: '附加信息', type: 'textarea', rows: 6 }
    ],
    samples: {
      rrss: { signOne: SIG1, signTwo: SIG2, macOne: E1, macTwo: E2 },
      eess: { signOne: EESS1, signTwo: EESS2, macOne: E1, macTwo: E2 },
      rsk: { signOne: SIG1, random: K_SAMPLE },
      rsd: { signOne: SIG1, key: D_SAMPLE },
      rsd1: { signOne: SIG1, key: D_SAMPLE, signTwo: SIG2 },
      rs2der: { signOne: SIG1 },
      der2rs: { signOne: DER1 },
      eess2der: { signOne: EESS1 },
      der2eess: { signOne: DER1, macOne: E1 },
      verify: { signOne: SIG1, macOne: E1, publicKey: SM2_PUB }
    }
  });

  /* ============================ 6. 椭圆曲线点运算 ============================ */
  const CURVE_OPTIONS = [
    ['sm2p256v1', 'sm2p256v1（SM2）'], ['prime256v1', 'prime256v1（P-256）'],
    ['secp256k1', 'secp256k1'], ['prime192v1', 'prime192v1（P-192）'],
    ['secp384r1', 'secp384r1（P-384）'], ['secp521r1', 'secp521r1（P-521）'],
    ['sm9g1', 'sm9g1（SM9 G1）'], ['sm9g2', 'sm9g2（SM9 G2）']
  ];
  const SM2_G = '0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0';
  const SM2_2G = '0456cefd60d7c87c000d58ef57fa73ba4d9c0dfa08c08a7331495c2e1da3f2bd5231b7e7e6cc8189f668535ce0f8eaf1bd6de84c182f6c8e716f780d3a970a23c3';
  const SM2_G_COMP = '0232c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7';

  CB.register({
    key: 'multiply',
    cat: 'ability',
    title: '椭圆曲线点运算',
    desc: '点加、点减、数乘 kP、求逆、Y 坐标恢复（SM2 与 NIST / SM9 G1、G2 曲线）',
    help: [
      { title: '运算说明', items: ['椭圆曲线点运算是 ECC 的基础能力：点加 P+Q、点减 P-Q、数乘 kP、求逆 -P。', '「解压点」由压缩点（02/03||X）恢复 Y 坐标；「压缩点」把 04||X||Y 压成 02/03||X。'] },
      { title: '输入要求', items: ['点坐标支持 04 开头的未压缩格式（04||X||Y）、压缩格式（02/03||X）以及裸 X||Y。', '点乘时第二个输入框填写标量 k（十六进制，如 02 表示 2）。', 'SM9 G2 坐标按标准写作 (x1, x0)：前 32 字节为 u 系数、后 32 字节为实部，共 128 字节。'] },
      { title: '使用提示', items: ['若结果异常，请优先检查曲线名称是否匹配，以及输入点是否属于所选曲线。', '结果为 00 表示无穷远点 O。'] }
    ],
    state: {
      curveName: 'sm2p256v1', pointOne: '', pointOneFormat: 'HEX',
      pointTwo: '', pointTwoFormat: 'HEX', resultFormat: 'HEX', compressed: false
    },
    fields: [
      { name: 'curveName', label: '曲线名称', type: 'select', options: CURVE_OPTIONS, span: 2 },
      { name: 'pointOne', label: '点 G / 自定义点', type: 'textarea', formatField: 'pointOneFormat', formats: FORMATS_BYTES, rows: 3, placeholder: '请输入第一个点（04||X||Y 或 02/03||X）' },
      { name: 'pointTwo', label: '运算点 / 标量', type: 'textarea', formatField: 'pointTwoFormat', formats: FORMATS_BYTES, rows: 3, placeholder: '点加、点减时输入点坐标；点乘时输入标量 k' },
      { name: 'resultFormat', label: '结果格式', type: 'radio', options: FORMATS_BYTES },
      { name: 'compressed', label: '输出压缩点', type: 'checkbox', text: '压缩输出（02/03||X）' }
    ],
    actions: [
      {
        name: 'add', label: '点加 +', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/point', {
            type: 'add', curveName: ctx.val('curveName'),
            pointOne: ctx.val('pointOne'), pointOneFormat: ctx.val('pointOneFormat'),
            pointTwo: ctx.val('pointTwo'), pointTwoFormat: ctx.val('pointTwoFormat'),
            resultFormat: ctx.val('resultFormat'), compressed: ctx.val('compressed')
          });
          ctx.setResult('result', data);
          CB.toast('点运算成功', 'success');
        }
      },
      {
        name: 'sub', label: '点减 -',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/point', {
            type: 'sub', curveName: ctx.val('curveName'),
            pointOne: ctx.val('pointOne'), pointOneFormat: ctx.val('pointOneFormat'),
            pointTwo: ctx.val('pointTwo'), pointTwoFormat: ctx.val('pointTwoFormat'),
            resultFormat: ctx.val('resultFormat'), compressed: ctx.val('compressed')
          });
          ctx.setResult('result', data);
          CB.toast('点运算成功', 'success');
        }
      },
      {
        name: 'mul', label: '点乘 *',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/point', {
            type: 'mul', curveName: ctx.val('curveName'),
            pointOne: ctx.val('pointOne'), pointOneFormat: ctx.val('pointOneFormat'),
            pointTwo: ctx.val('pointTwo'), pointTwoFormat: ctx.val('pointTwoFormat'),
            resultFormat: ctx.val('resultFormat'), compressed: ctx.val('compressed')
          });
          ctx.setResult('result', data);
          CB.toast('点运算成功', 'success');
        }
      },
      {
        name: 'neg', label: '求逆 -P',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/point', {
            type: 'neg', curveName: ctx.val('curveName'),
            pointOne: ctx.val('pointOne'), pointOneFormat: ctx.val('pointOneFormat'),
            resultFormat: ctx.val('resultFormat'), compressed: ctx.val('compressed')
          });
          ctx.setResult('result', data);
          CB.toast('求逆完成', 'success');
        }
      },
      {
        name: 'decompress', label: '解压点（恢复 Y）',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/point', {
            type: 'decompress', curveName: ctx.val('curveName'),
            pointOne: ctx.val('pointOne'), pointOneFormat: ctx.val('pointOneFormat'),
            resultFormat: ctx.val('resultFormat'), compressed: false
          });
          ctx.setResult('result', data);
          CB.toast('Y 坐标恢复成功', 'success');
        }
      },
      {
        name: 'compress', label: '压缩点',
        run: async (ctx) => {
          const data = await CB.api('/api/ops/point', {
            type: 'compress', curveName: ctx.val('curveName'),
            pointOne: ctx.val('pointOne'), pointOneFormat: ctx.val('pointOneFormat'),
            resultFormat: ctx.val('resultFormat'), compressed: true
          });
          ctx.setResult('result', data);
          CB.toast('压缩完成', 'success');
        }
      }
    ],
    results: [{ name: 'result', label: '运算结果', type: 'textarea', rows: 4 }],
    samples: {
      add: { curveName: 'sm2p256v1', pointOne: SM2_G, pointTwo: SM2_G, compressed: false },
      sub: { curveName: 'sm2p256v1', pointOne: SM2_G, pointTwo: SM2_G, compressed: false },
      mul: { curveName: 'sm2p256v1', pointOne: SM2_G, pointTwo: '02', compressed: false },
      neg: { curveName: 'sm2p256v1', pointOne: SM2_2G, compressed: false },
      decompress: { curveName: 'sm2p256v1', pointOne: SM2_G_COMP },
      compress: { curveName: 'sm2p256v1', pointOne: SM2_G }
    }
  });

  /* ============================ 7. PBKDF2 ============================ */
  CB.register({
    key: 'pbkdf2',
    cat: 'ability',
    title: 'PBKDF 密钥派生',
    desc: 'PBKDF2 口令密钥派生，PRF 可选 HMAC-SM3 / SHA-1 / SHA-256 / SHA-384 / SHA-512',
    help: [
      { title: '算法简介', items: ['PBKDF2 按 RFC 8018 对口令与盐值执行多轮 HMAC 迭代，将较弱的口令材料扩展为可用的派生密钥。', 'T_i = U_1 xor U_2 xor … xor U_c，其中 U_1 = PRF(P, S||INT(i))。'] },
      { title: '参数建议', items: ['口令与盐值都支持字符串、HEX、Base64；盐值建议保持随机且唯一。', '迭代次数可根据性能要求逐步上调，原站默认 1024 次、32 字节。'] },
      { title: '标准向量', items: ['口令 password、盐值 salt、1 次迭代、20 字节、HMAC-SHA1 的结果为 0c60c80f961f0e71f3a9b524af6012062fe037a6（RFC 6070）。'] }
    ],
    state: {
      type: 'SM3', password: '', passwordFormat: 'TEXT', salt: '', saltFormat: 'TEXT',
      times: 1024, length: 32, resultFormat: 'HEX'
    },
    fields: [
      { name: 'type', label: '摘要算法', type: 'radio', options: [['SM3', 'HMAC-SM3'], ['SHA', 'HMAC-SHA1'], ['SHA256', 'HMAC-SHA256'], ['SHA384', 'HMAC-SHA384'], ['SHA512', 'HMAC-SHA512']], span: 2 },
      { name: 'password', label: '口令 Password', type: 'key', formatField: 'passwordFormat', formats: FORMATS_IN, placeholder: '请输入 Password' },
      { name: 'salt', label: '盐值 Salt', type: 'key', formatField: 'saltFormat', formats: FORMATS_IN, placeholder: '请输入 Salt' },
      { name: 'times', label: '迭代次数', type: 'number', min: 1, max: 100000 },
      { name: 'length', label: '密钥长度（字节）', type: 'number', min: 1, max: 500 },
      { name: 'resultFormat', label: '结果格式', type: 'radio', options: FORMATS_BYTES }
    ],
    actions: [
      {
        name: 'run', label: '派生密钥', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/pbkdf2', {
            type: ctx.val('type'), password: ctx.val('password'), passwordFormat: ctx.val('passwordFormat'),
            salt: ctx.val('salt'), saltFormat: ctx.val('saltFormat'),
            times: ctx.val('times'), length: ctx.val('length'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data);
          CB.toast('派生密钥成功', 'success');
        }
      }
    ],
    results: [{ name: 'result', label: '派生密钥', type: 'textarea', rows: 4 }],
    samples: {
      run: { type: 'SM3', password: 'password', salt: 'salt', times: 2, length: 32 }
    }
  });

  /* ============================ 8. 工作模式检测 ============================ */
  CB.register({
    key: 'cipher/mode/detector',
    cat: 'ability',
    title: '工作模式检测',
    desc: '比较两组密文的重复分组、差异分布，推断 ECB / CBC / CFB / OFB / CTR / BC',
    help: [
      { title: '功能说明', items: ['通过比较两组密文的重复块、差异分布等特征，辅助推测分组加密工作模式。', '检测为统计推断，结果仅供参考，实际判断还需结合上下文和算法信息。'] },
      { title: '支持模式', items: ['支持分析 ECB、CBC、CFB、OFB、CTR、BC 等常见模式。', 'ECB 的典型特征是出现重复分组；流式模式（CFB/OFB/CTR）通常不要求分组对齐。'] },
      { title: '注意事项', items: ['两组密文长度应保持一致，且建议至少达到一个分组长度（16 字节）。', '若两组密文完全相同，只能判断为确定性加密，需要更换 IV 再测。'] }
    ],
    state: { ciphertext1: '', ciphertext1Format: 'HEX', ciphertext2: '', ciphertext2Format: 'HEX' },
    fields: [
      { name: 'ciphertext1', label: '密文 1', type: 'textarea', formatField: 'ciphertext1Format', formats: FORMATS_BYTES, rows: 4, placeholder: '请输入第一组密文数据' },
      { name: 'ciphertext2', label: '密文 2', type: 'textarea', formatField: 'ciphertext2Format', formats: FORMATS_BYTES, rows: 4, placeholder: '请输入第二组密文数据' }
    ],
    actions: [
      {
        name: 'detect', label: '开始检测', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/ops/mode/detect', {
            ciphertext1: ctx.val('ciphertext1'), ciphertext1Format: ctx.val('ciphertext1Format'),
            ciphertext2: ctx.val('ciphertext2'), ciphertext2Format: ctx.val('ciphertext2Format')
          });
          if (ctx._detectDraw) ctx._detectDraw(data);
          CB.toast('检测完成', 'success');
        }
      }
    ],
    results: [{
      name: 'mode', type: 'custom',
      render: (box, ctx) => {
        box.setAttribute('data-result', 'mode');
        const listWrap = el('div', { class: 'result-section' });
        const pre = el('pre', { class: 'json-view', 'data-result': 'detail' });
        box.appendChild(el('div', { class: 'result-head' }, [el('span', {}, ['可能的工作模式'])]));
        box.appendChild(listWrap);
        box.appendChild(el('div', { class: 'result-head mt12' }, [el('span', {}, ['详细分析报告'])]));
        box.appendChild(pre);
        ctx._detectDraw = (data) => {
          listWrap.innerHTML = '';
          (data.guesses || []).forEach((g) => {
            const item = el('div', { class: 'detect-item' });
            const head = el('div', { class: 'detect-mode' }, [g.mode + '　' + (g.label || '')]);
            if (g.confidence !== undefined) {
              head.appendChild(el('span', { class: 'field-tip' }, [' 置信度 ' + Math.round((g.confidence || 0) * 100) + '%']));
            }
            item.appendChild(head);
            item.appendChild(el('div', { class: 'field-tip' }, [g.reasoning || '']));
            listWrap.appendChild(item);
          });
          pre.textContent = data.detailedAnalysis || '';
        };
        ctx._detectDraw({ guesses: [], detailedAnalysis: '点击“开始检测”后展示分析报告。' });
      }
    }],
    samples: {
      detect: {
        ciphertext1: '11223344556677889900aabbccddeeff'.repeat(4),
        ciphertext2: '11223344556677889900aabbccddeeff'.repeat(3) + 'ffeeddccbbaa99887766554433221100'
      }
    }
  });
})();
