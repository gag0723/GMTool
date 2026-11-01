/* 哈希算法 / MAC 算法 / 哈希猜测 */
(function () {
  'use strict';
  const el = CB.el;

  const HASH_OPTIONS = [
    ['SM3', 'SM3'], ['SHA224', 'SHA-224'], ['SHA256', 'SHA-256'], ['SHA384', 'SHA-384'],
    ['SHA512', 'SHA-512'], ['SHA3_224', 'SHA3-224'], ['SHA3_256', 'SHA3-256'],
    ['SHA3_384', 'SHA3-384'], ['SHA3_512', 'SHA3-512'], ['SHA', 'SHA-1'], ['MD5', 'MD5']
  ];
  const FORMATS_IN = [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']];
  const FORMATS_BYTES = [['HEX', '十六进制'], ['BASE64', 'Base64']];

  CB.register({
    key: 'hash',
    cat: 'hash',
    title: '哈希算法',
    desc: '计算 SM3 / SHA / MD5 摘要与 HMAC，可设置盐值与迭代次数',
    help: [
      { title: '数据格式要求', items: ['文本输入按 UTF-8 处理。', '十六进制输入应为合法 HEX 字符串。', 'Base64 输入应为合法 Base64 编码。'] },
      { title: '密钥说明', items: ['普通哈希不需要密钥，只有 HMAC 模式会使用密钥。'] },
      { title: '盐值说明', items: ['盐值为可选项，可放在消息前或后，用于增强抗碰撞能力。', '迭代次数大于 1 时，会对上一次摘要结果继续迭代计算。'] }
    ],
    state: {
      type: 'SM3', messageFormat: 'TEXT', resultFormat: 'HEX',
      message: '', slot: '', slotFormat: 'HEX', slotSite: 'PRE', times: 1,
      key: '', keyFormat: 'HEX'
    },
    fields: [
      { name: 'type', label: '算法选择', type: 'radio', options: HASH_OPTIONS, span: 2 },
      { name: 'message', label: '输入消息', type: 'textarea', formatField: 'messageFormat', formats: FORMATS_IN, rows: 5, placeholder: '请输入需要 HASH/HMAC 的明文' },
      { name: 'resultFormat', label: '结果格式', type: 'radio', options: FORMATS_BYTES },
      { name: 'slot', label: '盐值（可选）', type: 'textarea', formatField: 'slotFormat', formats: FORMATS_BYTES, rows: 2, placeholder: '可选，作为盐值参与计算' },
      { name: 'slotSite', label: '盐值位置', type: 'radio', options: [['PRE', '前置'], ['POST', '后置']] },
      { name: 'times', label: '迭代次数', type: 'number', min: 1, max: 10000 },
      { name: 'key', label: 'HMAC 密钥', type: 'key', formatField: 'keyFormat', formats: FORMATS_BYTES, placeholder: '计算 HMAC 时必填' }
    ],
    actions: [
      {
        name: 'digest', label: '计算哈希', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/hash/digest', {
            type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            slot: ctx.val('slot'), slotFormat: ctx.val('slotFormat'), slotSite: ctx.val('slotSite'),
            times: ctx.val('times'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data);
          CB.toast('哈希计算成功', 'success');
        }
      },
      {
        name: 'hmac', label: '计算 HMAC',
        run: async (ctx) => {
          const data = await CB.api('/api/hash/hmac', {
            type: ctx.val('type'), message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            key: ctx.val('key'), keyFormat: ctx.val('keyFormat'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data);
          CB.toast('HMAC 计算成功', 'success');
        }
      }
    ],
    results: [
      { name: 'result', label: '哈希 / MAC 结果', type: 'textarea', rows: 6 }
    ],
    samples: {
      digest: { type: 'SM3', message: 'abc', messageFormat: 'TEXT', resultFormat: 'HEX', slot: '', slotFormat: 'HEX', slotSite: 'PRE', times: 1 },
      hmac: { type: 'SM3', message: 'abc', messageFormat: 'TEXT', resultFormat: 'HEX', key: '6b6579', keyFormat: 'HEX' }
    }
  });
})();

/* ---------------- MAC 算法 ---------------- */
(function () {
  'use strict';
  const el = CB.el;

  const MAC_ALGOS = [
    ['SM4', 'SM4'], ['AES128', 'AES-128'], ['AES192', 'AES-192'], ['AES256', 'AES-256'],
    ['DES', 'DES'], ['DESEDE16', '3DES-2KEY'], ['DESEDE24', '3DES-3KEY']
  ];
  const MAC_MODES = [
    ['CBCMAC', 'CBC-MAC'], ['CMAC', 'CMAC'], ['EMAC', 'EMAC'], ['ANSIRETAILMAC', 'ANSI-retail-MAC'],
    ['MacDES', 'MacDES'], ['LMAC', 'LMAC'], ['CBCR', 'CBCR'], ['TrCBC', 'TrCBC']
  ];
  const MAC_PADDINGS = [['PKCS7', 'PKCS7'], ['M2', '填充方式二（M2）'], ['M3', '填充方式三（M3）'], ['NOPADDING', 'NO PADDING']];
  const TWO_KEY_MODES = ['EMAC', 'MacDES', 'ANSIRETAILMAC'];
  const MAC_BLOCK = { SM4: 16, AES128: 16, AES192: 16, AES256: 16, DES: 8, DESEDE16: 8, DESEDE24: 8 };
  const MAC_KEYLEN = { SM4: 16, AES128: 16, AES192: 24, AES256: 32, DES: 8, DESEDE16: 16, DESEDE24: 24 };
  const MAC_LABEL = {
    CBCMAC: 'CBC-MAC', CMAC: 'CMAC', EMAC: 'EMAC', ANSIRETAILMAC: 'ANSI-retail-MAC',
    MacDES: 'MacDES', LMAC: 'LMAC', CBCR: 'CBCR', TrCBC: 'TrCBC'
  };
  const PAD_LABEL = {
    PKCS7: 'PKCS7', M2: '填充方式二（0x80 补位）', M3: '填充方式三（前置长度块）', NOPADDING: 'NO PADDING',
    M4: '填充方式四（标准固定）'
  };

  function algoLabel(v) {
    const hit = MAC_ALGOS.filter((a) => a[0] === v)[0];
    return hit ? hit[1] : v;
  }

  function byteLength(text, fmt) {
    const s = text || '';
    if (!s) return 0;
    const f = (fmt || 'TEXT').toUpperCase();
    if (f === 'HEX') return Math.floor(s.replace(/[\s:]/g, '').length / 2);
    if (f === 'BASE64') {
      try {
        const clean = s.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
        return Math.floor((clean.length * 3) / 4);
      } catch (e) { return 0; }
    }
    return new TextEncoder().encode(s).length;
  }

  CB.register({
    key: 'mac',
    cat: 'hash',
    title: 'MAC 算法',
    desc: '分组密码消息鉴别码：CBC-MAC / CMAC / EMAC / ANSI-retail-MAC / MacDES / LMAC / CBCR / TrCBC',
    help: [
      { title: '数据格式要求', items: ['字符串输入按 UTF-8 处理。', '十六进制输入应为合法 HEX 字符串。', 'Base64 输入应为合法 Base64 编码。'] },
      { title: '密钥规范', items: ['密钥长度必须与所选分组算法匹配：SM4/AES-128 16 字节，AES-192 24 字节，AES-256 32 字节，DES 8 字节，3DES-2KEY 16 字节，3DES-3KEY 24 字节。', 'EMAC、MacDES、ANSI-retail-MAC 模式需要额外提供第二把密钥。', 'LMAC 未提供第二把密钥时，按 GB/T 15852.1-2020 密钥诱导 1 由密钥一派生出链密钥与末块密钥。'] },
      { title: '填充说明', items: ['填充方式二（M2）为默认值，按 ISO/IEC 9797-1 方法 2 补 0x80 再补 0x00，消息整分组时同样补一整块。', 'PKCS7 补 n 个值为 n 的字节，填充方式三前置一个消息比特长度分组。', 'NO PADDING 要求消息长度为分组长度的整数倍。', 'CMAC、CBCR 固定使用标准中的填充方式四（未对齐才补 0x80），与填充选项无关。'] },
      { title: '模式说明', items: ['八种模式均按 GB/T 15852.1-2020（等同采用 ISO/IEC 9797-1 模型）实现，结果取左侧 tlen 字节；TrCBC 在消息非整分组时取右侧 tlen 字节。', 'ANSI-retail-MAC 与 MacDES 的标准定义针对 DES 系列，选择 AES/SM4 时按同一结构泛化计算。'] }
    ],
    state: {
      cipherType: 'SM4', mode: 'CBCMAC',
      message: '', messageFormat: 'TEXT',
      resultFormat: 'HEX', tlen: 8, paddingType: 'M2',
      key: '', keyFormat: 'HEX', spareKey: '', sparekeyFormat: 'HEX'
    },
    fields: [
      {
        name: 'cipherType', label: '算法选择', type: 'radio', options: MAC_ALGOS, span: 2,
        onChange: (v, ctx) => {
          const bs = MAC_BLOCK[v] || 16;
          if (Number(ctx.val('tlen')) > bs) ctx.set('tlen', bs);
        }
      },
      { name: 'mode', label: 'MAC 模式', type: 'radio', options: MAC_MODES, span: 2 },
      {
        name: 'message', label: '消息', type: 'textarea', formatField: 'messageFormat',
        formats: [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 4,
        placeholder: '请输入待计算 MAC 的消息'
      },
      { name: 'resultFormat', label: 'MAC 结果格式', type: 'radio', options: [['HEX', '十六进制'], ['BASE64', 'Base64']] },
      {
        name: 'paddingType', label: '填充模式', type: 'radio', options: MAC_PADDINGS, span: 2,
        show: (v) => v.mode !== 'CMAC' && v.mode !== 'CBCR'
      },
      {
        name: 'tlen', label: 'MAC 长度', type: 'radio',
        options: [['8', '8字节'], ['12', '12字节'], ['16', '16字节']],
        show: (v) => (MAC_BLOCK[v.cipherType] || 16) === 16
      },
      {
        name: 'key', label: '密钥一', type: 'key', formatField: 'keyFormat',
        formats: [['HEX', '十六进制'], ['BASE64', 'Base64']],
        random: (state) => MAC_KEYLEN[state.cipherType] || 16,
        placeholder: '请输入与算法匹配的密钥'
      },
      {
        name: 'spareKey', label: '密钥二', type: 'key', formatField: 'sparekeyFormat',
        formats: [['HEX', '十六进制'], ['BASE64', 'Base64']],
        random: (state) => MAC_KEYLEN[state.cipherType] || 16,
        placeholder: '请输入第二把密钥（EMAC / MacDES / ANSI-retail-MAC）',
        show: (v) => TWO_KEY_MODES.indexOf(v.mode) >= 0
      }
    ],
    actions: [
      {
        name: 'calc', label: '计算 MAC', primary: true,
        run: async (ctx) => {
          if (!ctx.val('message')) {
            CB.toast('请输入需要计算 MAC 的消息', 'error');
            return;
          }
          const data = await CB.api('/api/mac/calc', {
            cipherType: ctx.val('cipherType'), mode: ctx.val('mode'),
            message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
            key: ctx.val('key'), keyFormat: ctx.val('keyFormat'),
            spareKey: ctx.val('spareKey'), sparekeyFormat: ctx.val('sparekeyFormat'),
            paddingType: ctx.val('paddingType'), tlen: ctx.val('tlen'),
            resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data);
          const mode = ctx.val('mode');
          const pad = (mode === 'CMAC' || mode === 'CBCR') ? PAD_LABEL.M4 : (PAD_LABEL[ctx.val('paddingType')] || ctx.val('paddingType'));
          ctx.setResult('detail', [
            '算法：' + algoLabel(ctx.val('cipherType')) + '（分组 ' + (MAC_BLOCK[ctx.val('cipherType')] || 16) + ' 字节）',
            '模式：' + (MAC_LABEL[mode] || mode),
            '填充：' + pad,
            'MAC 长度：' + ctx.val('tlen') + ' 字节',
            '消息长度：' + byteLength(ctx.val('message'), ctx.val('messageFormat')) + ' 字节',
            '结果长度：' + (data || '').length + ' 字符'
          ].join('；'));
          CB.toast('MAC 计算成功', 'success');
        }
      }
    ],
    results: [
      { name: 'result', label: 'MAC 结果', type: 'textarea', rows: 3 },
      { name: 'detail', label: '计算参数', type: 'text' }
    ],
    samples: {
      /* 采样值只填 data-field 字段：格式下拉框（messageFormat/keyFormat 等）保持默认值 */
      calc: {
        cipherType: 'SM4', mode: 'CMAC', message: 'abc',
        key: '0123456789abcdeffedcba9876543210', tlen: 16, resultFormat: 'HEX'
      }
    }
  });

  /* ---------------- 杂凑算法猜测 ---------------- */
  (function () {
    const HASH_ORDER = ['SM3', 'SHA', 'MD5', 'SHA224', 'SHA256', 'SHA384', 'SHA512', 'SHA3_224', 'SHA3_256', 'SHA3_384', 'SHA3_512'];
    const TYPE_OF = {
      'SM3': 'SM3', 'SHA-1': 'SHA', 'MD5': 'MD5', 'SHA-224': 'SHA224', 'SHA-256': 'SHA256',
      'SHA-384': 'SHA384', 'SHA-512': 'SHA512', 'SHA3-224': 'SHA3_224', 'SHA3-256': 'SHA3_256',
      'SHA3-384': 'SHA3_384', 'SHA3-512': 'SHA3_512'
    };

    function digestToHex(raw, fmt) {
      const text = (raw || '').replace(/[\s:]/g, '');
      if (!text) return '';
      if ((fmt || 'HEX').toUpperCase() === 'BASE64') {
        try {
          let b64 = text.replace(/-/g, '+').replace(/_/g, '/');
          while (b64.length % 4) b64 += '=';
          const bin = atob(b64);
          let out = '';
          for (let i = 0; i < bin.length; i += 1) out += bin.charCodeAt(i).toString(16).padStart(2, '0');
          return out;
        } catch (e) {
          return text.toLowerCase();
        }
      }
      return text.toLowerCase();
    }

    CB.register({
      key: 'hash/all',
      cat: 'hash',
      title: '杂凑算法猜测',
      desc: '一次计算 11 种杂凑算法，并根据原始摘要高亮匹配项',
      help: [
        { title: '数据格式要求', items: ['字符串输入按 UTF-8 处理。', '十六进制输入应为合法 HEX 字符串。', 'Base64 输入应为合法 Base64 编码。'] },
        { title: '长度要求', items: ['消息长度不能超过 5000 个字节。'] },
        { title: '结果说明', items: ['如果提供原始摘要，结果会将匹配项自动排序到前面并高亮显示。', '原始摘要支持十六进制与 Base64 两种格式。'] }
      ],
      state: { message: '', messageFormat: 'TEXT', hash: '', hashFormat: 'HEX' },
      fields: [
        {
          name: 'message', label: '输入消息', type: 'textarea', formatField: 'messageFormat',
          formats: [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 4,
          placeholder: '请输入待猜测的消息',
          tip: '左侧为待计算消息格式，右侧原始摘要格式单独控制。'
        },
        {
          name: 'hash', label: '原始摘要', type: 'textarea', formatField: 'hashFormat',
          formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 4,
          placeholder: '可选输入原始摘要，用于高亮匹配结果',
          tip: '输入摘要后会在结果表格中自动标记匹配算法。'
        }
      ],
      actions: [
        {
          name: 'hashAll', label: '计算杂凑', primary: true,
          run: async (ctx) => {
            if (!ctx.val('message')) {
              CB.toast('请输入需要计算杂凑的消息', 'error');
              return;
            }
            const origin = digestToHex(ctx.val('hash'), ctx.val('hashFormat'));
            const data = await CB.api('/api/hash/digest/all', {
              message: ctx.val('message'), messageFormat: ctx.val('messageFormat'),
              originDigest: origin, hashFormat: 'HEX'
            });
            const rows = (data.rows || []).map((r) => {
              const type = TYPE_OF[r.algo] || r.algo;
              return { type: type, hash: (r.value || '').toUpperCase(), match: origin ? (r.value || '').toLowerCase() === origin : false };
            });
            rows.sort((a, b) => {
              if (a.match !== b.match) return a.match ? -1 : 1;
              return HASH_ORDER.indexOf(a.type) - HASH_ORDER.indexOf(b.type);
            });
            rows.forEach((r, i) => { r.no = i + 1; });
            ctx.setResult('table', rows);
            const hits = rows.filter((r) => r.match).length;
            ctx.setResult('hint', origin
              ? ('消息 ' + data.length + ' 字节，共 ' + rows.length + ' 种算法，匹配 ' + hits + ' 个' + (hits ? '' : '（原始摘要与任何算法结果都不一致）'))
              : ('消息 ' + data.length + ' 字节，共 ' + rows.length + ' 种算法'));
            CB.toast('杂凑计算成功', 'success');
          }
        }
      ],
      results: [
        { name: 'hint', label: '统计', type: 'text' },
        {
          name: 'table', type: 'custom',
          render: (box, ctx) => {
            const wrap = el('div', { 'data-result': 'table' });
            box.appendChild(wrap);
            const paint = (rows) => {
              wrap.innerHTML = '';
              if (!rows || !rows.length) {
                wrap.appendChild(el('div', { class: 'muted' }, ['尚未计算，请点击“计算杂凑”']));
                return;
              }
              const withCompare = !!ctx.val('hash');
              const table = el('table', { class: 'grid' });
              const head = el('tr', {}, [el('th', {}, ['序号']), el('th', {}, ['杂凑算法']), el('th', {}, ['杂凑值'])]);
              if (withCompare) head.appendChild(el('th', {}, ['比对结果']));
              table.appendChild(el('thead', {}, [head]));
              const tbody = el('tbody', {});
              rows.forEach((r) => {
                const tr = el('tr', r.match ? { style: 'background:#e8ffea' } : {});
                tr.appendChild(el('td', {}, [String(r.no)]));
                tr.appendChild(el('td', {}, [r.type]));
                tr.appendChild(el('td', { class: 'mono' }, [r.hash]));
                if (withCompare) tr.appendChild(el('td', {}, [CB.badge(!!r.match, '匹配', '不匹配')]));
                tbody.appendChild(tr);
              });
              table.appendChild(tbody);
              wrap.appendChild(table);
            };
            paint([]);
            ctx.onResult = (name, value) => { if (name === 'table') paint(value); };
          }
        }
      ],
      samples: {
        hashAll: { message: 'abc', hash: '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0' }
      }
    });
  })();
})();
