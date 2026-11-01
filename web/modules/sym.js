/* 对称密码：分组密码 / ZUC 序列密码 / GCM 模式（全部本地计算） */
(function () {
  'use strict';

  const FORMATS_IN = [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']];
  const FORMATS_BYTES = [['HEX', '十六进制'], ['BASE64', 'Base64']];

  const ALGO_OPTIONS = [
    ['SM4', 'SM4'], ['AES128', 'AES-128'], ['AES192', 'AES-192'], ['AES256', 'AES-256'],
    ['DES', 'DES'], ['DESEDE16', '3DES-2KEY'], ['DESEDE24', '3DES-3KEY']
  ];
  const AEAD_OPTIONS = [['SM4', 'SM4'], ['AES128', 'AES-128'], ['AES192', 'AES-192'], ['AES256', 'AES-256']];
  const MODE_OPTIONS = [
    ['ECB', 'ECB'], ['CBC', 'CBC'], ['CTR', 'CTR'], ['OFB', 'OFB'], ['CFB', 'CFB'], ['XTS', 'XTS']
  ];
  const PADDING_OPTIONS = [
    ['PKCS7', 'PKCS7'], ['ISO_10126', 'ISO10126'], ['ISO7816_4', 'ISO7816-4'],
    ['ANSIX923', 'ANSI X9.23'], ['ZERO', 'ZERO'], ['NOPADDING', 'NO PADDING'],
    ['M2', 'GB/T17964 C.3 (M2)'], ['M3', 'GB/T17964 C.4 (M3)']
  ];

  const KEY_LEN = { SM4: 16, AES128: 16, AES192: 24, AES256: 32, DES: 8, DESEDE16: 16, DESEDE24: 24 };
  const BLOCK_LEN = { SM4: 16, AES128: 16, AES192: 16, AES256: 16, DES: 8, DESEDE16: 8, DESEDE24: 8 };

  function keyLen(state) {
    return KEY_LEN[state.type] || 16;
  }

  function blockLen(state) {
    return BLOCK_LEN[state.type] || 16;
  }

  /* ---------------- 分组密码 ---------------- */
  CB.register({
    key: 'group',
    cat: 'sym',
    title: '分组密码',
    desc: 'SM4 / AES / DES / 3DES 的 ECB、CBC、CTR、OFB、CFB、XTS 加解密，支持多种填充方式',
    help: [
      {
        title: '数据格式要求',
        items: [
          '文本输入按 UTF-8 处理。',
          '十六进制输入应为合法 HEX 字符串。',
          'Base64 输入应为合法 Base64 编码。',
          'NO PADDING 模式下，数据长度必须满足分组大小要求。'
        ]
      },
      {
        title: '密钥与 IV 规范',
        items: [
          '密钥长度必须与所选算法匹配：SM4/AES-128 16 字节、AES-192 24 字节、AES-256 32 字节、DES 8 字节、3DES-2KEY 16 字节、3DES-3KEY 24 字节。',
          'IV 长度必须与分组大小匹配：SM4 与 AES 为 16 字节，DES 与 3DES 为 8 字节。'
        ]
      },
      {
        title: '填充方式说明',
        items: [
          'PKCS7：补 n 个值为 n 的字节（GB/T 17964-2021 附录 C.2 填充方式一）。',
          'ISO10126：补随机字节，最后一个字节为填充长度。',
          'ISO7816-4 / GB/T17964 C.3 (M2)：先补 0x80，再补 0x00。',
          'ANSI X9.23 / GB/T17964 C.4 (M3)：先补 0x00，最后一个字节为填充长度。',
          'ZERO：补 0x00 至分组整数倍（总是至少补一个分组，无法与明文尾部 0x00 区分）。'
        ]
      },
      {
        title: 'XTS 模式说明',
        items: [
          'XTS 模式需要双倍长度密钥（如 SM4 为 32 字节），并使用 Tweak 替代 IV。',
          'Tweak 固定为 16 字节，且 XTS 不使用填充；末分组不足时采用密文挪用（CTS）。',
          '标准模式可选 GB/T 17964-2021 与 IEEE 1619，两者 tweak 递推的比特约定不同。'
        ]
      }
    ],
    state: {
      type: 'SM4', mode: 'CBC', padding: 'PKCS7', gcmStandard: 'GB',
      message: '', messageFormat: 'TEXT', cipherData: '', cipherFormat: 'HEX',
      key: '', keyFormat: 'HEX', iv: '', ivFormat: 'HEX', tweak: '', tweakFormat: 'HEX'
    },
    defaults: {
      type: 'SM4', mode: 'CBC', padding: 'PKCS7', gcmStandard: 'GB',
      messageFormat: 'TEXT', cipherFormat: 'HEX', keyFormat: 'HEX', ivFormat: 'HEX', tweakFormat: 'HEX'
    },
    fields: [
      { name: 'type', label: '算法选择', type: 'radio', options: ALGO_OPTIONS, span: 2 },
      { name: 'mode', label: '加密模式', type: 'radio', options: MODE_OPTIONS, span: 2 },
      {
        name: 'padding', label: '填充方式', type: 'radio', options: PADDING_OPTIONS, span: 2,
        show: (v) => v.mode !== 'XTS'
      },
      {
        name: 'gcmStandard', label: '标准模式', type: 'radio', span: 2,
        options: [['GB', 'GB/T 17964-2021'], ['IEEE', 'IEEE 1619']],
        show: (v) => v.mode === 'XTS'
      },
      {
        name: 'message', label: '输入文本', type: 'textarea', formatField: 'messageFormat',
        formats: FORMATS_IN, rows: 4, placeholder: '请输入待处理的数据'
      },
      {
        name: 'cipherData', label: '密文文本', type: 'textarea', formatField: 'cipherFormat',
        formats: FORMATS_BYTES, rows: 4, placeholder: '请输入密文数据'
      },
      {
        name: 'key', label: '密钥', type: 'key', formatField: 'keyFormat', formats: FORMATS_BYTES,
        random: (v) => (v.mode === 'XTS' ? 2 * keyLen(v) : keyLen(v)),
        placeholder: '请输入对应算法长度的密钥'
      },
      {
        name: 'iv', label: 'IV', type: 'key', formatField: 'ivFormat', formats: FORMATS_BYTES,
        random: (v) => blockLen(v),
        show: (v) => v.mode !== 'ECB' && v.mode !== 'XTS',
        placeholder: 'IV 长度与分组长度一致'
      },
      {
        name: 'tweak', label: 'Tweak', type: 'key', formatField: 'tweakFormat', formats: FORMATS_BYTES,
        random: 16, show: (v) => v.mode === 'XTS', placeholder: '请输入 16 字节的 Tweak'
      }
    ],
    actions: [
      {
        name: 'encrypt', label: '加密', primary: true,
        run: async (ctx) => {
          const mode = ctx.val('mode');
          let data;
          if (mode === 'XTS') {
            data = await CB.api('/api/sym/xts/encrypt', {
              type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
              cipherFormat: ctx.val('cipherFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
              tweak: ctx.val('tweak'), tweakFormat: ctx.val('tweakFormat'),
              isGB: ctx.val('gcmStandard') !== 'IEEE'
            });
          } else {
            data = await CB.api('/api/sym/encrypt', {
              type: ctx.val('type'), mode: mode, padding: ctx.val('padding'),
              message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
              cipherFormat: ctx.val('cipherFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
              iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat')
            });
          }
          ctx.set('cipherData', data);
          ctx.setResult('cipher', data);
          ctx.refresh();
          CB.toast('加密成功', 'success');
        }
      },
      {
        name: 'decrypt', label: '解密',
        run: async (ctx) => {
          const mode = ctx.val('mode');
          let data;
          if (mode === 'XTS') {
            data = await CB.api('/api/sym/xts/decrypt', {
              type: ctx.val('type'), cipher: ctx.val('cipherData'), cipherFormat: ctx.val('cipherFormat'),
              messageFormat: ctx.val('messageFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
              tweak: ctx.val('tweak'), tweakFormat: ctx.val('tweakFormat'),
              isGB: ctx.val('gcmStandard') !== 'IEEE'
            });
          } else {
            data = await CB.api('/api/sym/decrypt', {
              type: ctx.val('type'), mode: mode, padding: ctx.val('padding'),
              cipher: ctx.val('cipherData'), cipherFormat: ctx.val('cipherFormat'),
              messageFormat: ctx.val('messageFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
              iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat')
            });
          }
          ctx.setResult('plain', data);
          CB.toast('解密成功', 'success');
        }
      }
    ],
    results: [
      { name: 'cipher', label: '密文文本', type: 'textarea', rows: 5 },
      { name: 'plain', label: '解密明文', type: 'textarea', rows: 5 }
    ],
    samples: {
      encrypt: {
        type: 'SM4', mode: 'CBC', padding: 'PKCS7', message: 'abc',
        key: '0123456789abcdeffedcba9876543210', iv: '000102030405060708090a0b0c0d0e0f'
      },
      decrypt: {
        type: 'SM4', mode: 'CBC', padding: 'PKCS7',
        cipherData: '4301693c448c7da7cff13f84690f7dea',
        key: '0123456789abcdeffedcba9876543210', iv: '000102030405060708090a0b0c0d0e0f'
      }
    }
  });

  /* ---------------- ZUC 序列密码 ---------------- */
  CB.register({
    key: 'seq',
    cat: 'sym',
    title: 'ZUC序列算法',
    desc: 'ZUC-128 / ZUC-256 序列密码加解密与完整性 MAC 计算',
    help: [
      {
        title: '数据格式要求',
        items: ['字符串输入按 UTF-8 处理。', '十六进制输入应为合法 HEX 字符串。', 'Base64 输入应为合法 Base64 编码。']
      },
      {
        title: '密钥与 IV 规范',
        items: [
          'ZUC-128 需要 16 字节密钥与 16 字节 IV（GM/T 0001）。',
          'ZUC-256 需要 32 字节密钥与 25 字节 IV（ZUC-256 草案，IV 后 8 字节为 6 比特）。'
        ]
      },
      {
        title: 'MAC 说明',
        items: [
          'ZUC-128 使用 128-EIA3 结构，固定输出 4 字节 MAC。',
          'ZUC-256 支持 4、8、16 字节 MAC 长度切换（256-NIA6）。',
          'MAC 计算与加密是两套独立流程，请勿混用输出。'
        ]
      }
    ],
    state: {
      type: 'ZUC128', message: '', messageFormat: 'TEXT', result: '', resultFormat: 'HEX',
      key: '', keyFormat: 'HEX', iv: '', ivFormat: 'HEX', macLength: 4
    },
    defaults: {
      type: 'ZUC128', messageFormat: 'TEXT', resultFormat: 'HEX',
      keyFormat: 'HEX', ivFormat: 'HEX', macLength: 4
    },
    fields: [
      { name: 'type', label: '算法选择', type: 'radio', span: 2, options: [['ZUC128', 'ZUC-128'], ['ZUC256', 'ZUC-256']] },
      {
        name: 'message', label: '消息', type: 'textarea', formatField: 'messageFormat',
        formats: FORMATS_IN, rows: 4, placeholder: '请输入待处理的消息'
      },
      {
        name: 'result', label: '密文 / MAC', type: 'textarea', formatField: 'resultFormat',
        formats: FORMATS_BYTES, rows: 4, placeholder: '请输入待解密的密文，或在此查看 MAC 结果'
      },
      {
        name: 'macLength', label: 'MAC 长度', type: 'radio', options: [[16, '16字节'], [8, '8字节'], [4, '4字节']],
        show: (v) => v.type === 'ZUC256'
      },
      {
        name: 'key', label: '密钥', type: 'key', formatField: 'keyFormat', formats: FORMATS_BYTES,
        random: (v) => (v.type === 'ZUC256' ? 32 : 16), placeholder: '请输入对应格式与长度的密钥'
      },
      {
        name: 'iv', label: 'IV', type: 'key', formatField: 'ivFormat', formats: FORMATS_BYTES,
        random: (v) => (v.type === 'ZUC256' ? 25 : 16), placeholder: '请输入对应格式与长度的 IV'
      }
    ],
    actions: [
      {
        name: 'encrypt', label: '加密', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/sym/zuc/encrypt', {
            type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            resultFormat: ctx.val('resultFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat')
          });
          ctx.set('result', data);
          ctx.setResult('output', data);
          ctx.refresh();
          CB.toast('加密成功', 'success');
        }
      },
      {
        name: 'decrypt', label: '解密',
        run: async (ctx) => {
          const data = await CB.api('/api/sym/zuc/decrypt', {
            type: ctx.val('type'), result: ctx.val('result'), resultFormat: ctx.val('resultFormat'),
            messageFormat: ctx.val('messageFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat')
          });
          ctx.setResult('output', data);
          CB.toast('解密成功', 'success');
        }
      },
      {
        name: 'mac', label: '计算 MAC',
        run: async (ctx) => {
          const data = await CB.api('/api/sym/zuc/mac', {
            type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            resultFormat: ctx.val('resultFormat'), macLength: ctx.val('macLength'),
            key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat')
          });
          ctx.set('result', data);
          ctx.setResult('output', data);
          ctx.refresh();
          CB.toast('MAC 计算成功', 'success');
        }
      }
    ],
    results: [{ name: 'output', label: '运算结果', type: 'textarea', rows: 5 }],
    samples: {
      encrypt: {
        type: 'ZUC128', message: 'abc',
        key: '0123456789abcdeffedcba9876543210', iv: '000102030405060708090a0b0c0d0e0f'
      },
      decrypt: {
        type: 'ZUC128', result: 'f5ca4c',
        key: '0123456789abcdeffedcba9876543210', iv: '000102030405060708090a0b0c0d0e0f'
      },
      mac: {
        type: 'ZUC256', message: 'abc', macLength: 16,
        key: '0123456789abcdeffedcba9876543210fedcba98765432100123456789abcdef',
        iv: '000102030405060708090a0b0c0d0e0f101112131415161718'
      }
    }
  });

  /* ---------------- GCM 模式 ---------------- */
  CB.register({
    key: 'gcm',
    cat: 'sym',
    title: 'GCM 模式',
    desc: 'SM4 / AES 的 GCM 认证加密，支持 AAD 与 4 / 8 / 16 字节标签',
    help: [
      {
        title: '数据格式要求',
        items: ['字符串输入按 UTF-8 处理。', '十六进制输入应为合法 HEX 字符串。', 'Base64 输入应为合法 Base64 编码。']
      },
      {
        title: '密钥与 IV 规范',
        items: [
          '密钥长度必须与所选算法匹配（SM4 / AES-128 16 字节、AES-192 24 字节、AES-256 32 字节）。',
          '与原站一致推荐使用 16 字节 IV（此时 J0 由 GHASH 派生）；同时兼容 12 字节标准 IV（96 位快速路径）。'
        ]
      },
      {
        title: '认证说明',
        items: [
          '解密时必须使用与加密阶段完全一致的 AAD、IV 与 Tag。',
          'Tag 支持 4、8、16 字节长度，默认推荐 16 字节。',
          '认证标签校验不通过时会直接报错，不返回任何明文。'
        ]
      }
    ],
    state: {
      type: 'SM4', message: '', messageFormat: 'TEXT', result: '', resultFormat: 'HEX',
      aad: '', aadFormat: 'TEXT', tag: '', tagFormat: 'HEX', tagLength: 16,
      key: '', keyFormat: 'HEX', iv: '', ivFormat: 'HEX'
    },
    defaults: {
      type: 'SM4', messageFormat: 'TEXT', resultFormat: 'HEX', aadFormat: 'TEXT',
      tagFormat: 'HEX', tagLength: 16, keyFormat: 'HEX', ivFormat: 'HEX'
    },
    fields: [
      { name: 'type', label: '算法选择', type: 'radio', options: AEAD_OPTIONS, span: 2 },
      {
        name: 'message', label: '消息', type: 'textarea', formatField: 'messageFormat',
        formats: FORMATS_IN, rows: 4, placeholder: '请输入待加密或解密后的消息'
      },
      {
        name: 'result', label: '密文', type: 'textarea', formatField: 'resultFormat',
        formats: FORMATS_BYTES, rows: 4, placeholder: '请输入待解密或加密后的密文'
      },
      {
        name: 'aad', label: '附加认证数据（AAD）', type: 'key', formatField: 'aadFormat',
        formats: FORMATS_IN, placeholder: '请输入对应格式的附加认证数据'
      },
      {
        name: 'tag', label: '认证标签（Tag）', type: 'key', formatField: 'tagFormat',
        formats: FORMATS_BYTES, placeholder: '请输入认证标签'
      },
      {
        name: 'tagLength', label: 'Tag 长度', type: 'radio',
        options: [[16, '16 字节'], [8, '8 字节'], [4, '4 字节']]
      },
      {
        name: 'key', label: '密钥', type: 'key', formatField: 'keyFormat', formats: FORMATS_BYTES,
        random: (v) => (KEY_LEN[v.type] || 16), placeholder: '请输入对应算法长度的密钥'
      },
      {
        name: 'iv', label: 'IV', type: 'key', formatField: 'ivFormat', formats: FORMATS_BYTES,
        random: 16, placeholder: '推荐 16 字节 IV'
      }
    ],
    actions: [
      {
        name: 'encrypt', label: '加密', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/sym/gcm/encrypt', {
            type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            resultFormat: ctx.val('resultFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat'),
            aad: ctx.val('aad'), aadFormat: ctx.val('aadFormat'),
            tagLength: ctx.val('tagLength'), tagFormat: ctx.val('tagFormat')
          });
          ctx.set('result', data.cipher);
          ctx.set('tag', data.tag);
          ctx.setResult('cipher', data.cipher);
          ctx.setResult('tagout', data.tag);
          ctx.refresh();
          CB.toast('加密成功', 'success');
        }
      },
      {
        name: 'decrypt', label: '解密',
        run: async (ctx) => {
          const data = await CB.api('/api/sym/gcm/decrypt', {
            type: ctx.val('type'), result: ctx.val('result'), resultFormat: ctx.val('resultFormat'),
            messageFormat: ctx.val('messageFormat'), key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            iv: ctx.val('iv'), ivFormat: ctx.val('ivFormat'),
            aad: ctx.val('aad'), aadFormat: ctx.val('aadFormat'),
            tag: ctx.val('tag'), tagFormat: ctx.val('tagFormat'),
            tagLength: ctx.val('tagLength')
          });
          ctx.setResult('plain', data);
          CB.toast('解密成功', 'success');
        }
      }
    ],
    results: [
      { name: 'cipher', label: '密文', type: 'textarea', rows: 4 },
      { name: 'tagout', label: '认证标签', type: 'textarea', rows: 2 },
      { name: 'plain', label: '解密明文', type: 'textarea', rows: 4 }
    ],
    samples: {
      encrypt: {
        type: 'SM4', message: 'abc',
        key: '0123456789abcdeffedcba9876543210', iv: '000102030405060708090a0b0c0d0e0f',
        aad: '', tagLength: 16
      },
      decrypt: {
        type: 'SM4', result: 'cb66ab', tag: '738be013adb5f09f040ebee6f9dcb8ed',
        key: '0123456789abcdeffedcba9876543210', iv: '000102030405060708090a0b0c0d0e0f',
        aad: '', tagLength: 16
      }
    }
  });
})();
