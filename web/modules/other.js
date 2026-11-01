/* 其他常用工具：编码转换、密文长度分析、大数运算、取模、逻辑运算、字节逆序 */
(function () {
  'use strict';
  const el = CB.el;

  /* ---------------- 编码转换工具 ---------------- */
  CB.register({
    key: 'encode',
    cat: 'top',
    title: '编码转换工具',
    desc: '字符串 / 十六进制 / Base64 / 二进制互转，字符集转换、ASN.1 解析、URL 解码',
    help: [
      { title: '使用说明', items: ['所有转换均在本地完成，不会上传任何数据。', '十六进制输入中的空格与换行会被自动忽略。'] }
    ],
    render: function (root, ctx) {
      const tabs = [
        ['convert', '编码转换'], ['charset', '字符集转换'], ['asn1', 'ASN.1 解析'], ['url', 'URL 解码'], ['identify', '算法识别']
      ];
      let active = 'convert';
      const bar = el('div', { class: 'tabs' });
      const body = el('div', {});
      root.appendChild(bar);
      root.appendChild(body);

      function paint() {
        bar.innerHTML = '';
        tabs.forEach(([k, t]) => {
          const b = el('button', { class: 'tab' + (active === k ? ' active' : ''), 'data-tab': k }, [t]);
          b.addEventListener('click', () => { active = k; paint(); });
          bar.appendChild(b);
        });
        body.innerHTML = '';
        if (active === 'convert') renderConvert(body);
        if (active === 'charset') renderCharset(body);
        if (active === 'asn1') renderAsn1(body);
        if (active === 'url') renderUrl(body);
        if (active === 'identify') renderIdentify(body);
      }

      function panel() {
        const card = el('div', { class: 'card' });
        body.appendChild(card);
        return card;
      }

      function renderConvert(host) {
        const card = panel.call(null);
        host.appendChild(card);
        const state = { data: '', from: 'TEXT', to: 'HEX', out: '' };
        card.appendChild(el('div', { class: 'field-label' }, ['输入数据']));
        const fmtRow = el('div', { class: 'input-bar' });
        const fromSel = el('select', { class: 'fmt-select', 'data-field': 'convert-from' });
        [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64'], ['BIN', '二进制']].forEach(([v, l]) => fromSel.appendChild(el('option', { value: v, selected: v === 'TEXT' }, [l])));
        fromSel.addEventListener('change', () => { state.from = fromSel.value; });
        fmtRow.appendChild(fromSel);
        fmtRow.appendChild(el('button', { class: 'btn btn-mini', 'data-action': 'convert-clean', onclick: () => { ta.value = ta.value.replace(/\s+/g, ''); state.data = ta.value; CB.toast('空格和换行已清理', 'success'); } }, ['清理空格换行']));
        card.appendChild(fmtRow);
        const ta = el('textarea', { class: 'textarea', rows: 6, 'data-field': 'convert-input', placeholder: '请输入需要转换的数据' });
        ta.addEventListener('input', () => { state.data = ta.value; });
        card.appendChild(ta);

        const res = el('div', { class: 'result-block mt12' });
        res.appendChild(el('div', { class: 'result-head' }, [el('span', {}, ['运算结果'])]));
        const outTa = el('textarea', { class: 'textarea result-text', rows: 6, readonly: true, 'data-result': 'convert-out' });
        res.appendChild(outTa);
        card.appendChild(res);

        const row = el('div', { class: 'actions-bar' });
        const toSel = el('select', { class: 'fmt-select', 'data-field': 'convert-to' });
        [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64'], ['BIN', '二进制']].forEach(([v, l]) => toSel.appendChild(el('option', { value: v, selected: v === 'HEX' }, [l])));
        toSel.addEventListener('change', () => { state.to = toSel.value; });
        row.appendChild(toSel);
        const btn = el('button', { class: 'btn btn-primary', 'data-action': 'convert' }, ['转换']);
        btn.addEventListener('click', async () => {
          try {
            const r = await CB.api('/api/encoding/convert', { data: state.data, fromFormat: state.from, toFormat: state.to });
            outTa.value = r.result;
            lenEl.textContent = '长度：' + r.length + ' 字节 / ' + r.bits + ' 位';
            CB.toast('转换成功', 'success');
          } catch (e) { CB.toast(e.message, 'error'); }
        });
        row.appendChild(btn);
        row.appendChild(el('button', { class: 'btn btn-ghost', 'data-action': 'convert-copy', onclick: () => CB.copyText(outTa.value) }, ['复制']));
        row.appendChild(el('button', { class: 'btn btn-ghost', onclick: () => { ta.value = ''; outTa.value = ''; state.data = ''; lenEl.textContent = ''; } }, ['清除']));
        card.appendChild(row);
        const lenEl = el('div', { class: 'field-tip', 'data-result': 'convert-length' });
        card.appendChild(lenEl);
      }

      function renderCharset(host) {
        const card = panel();
        host.appendChild(card);
        const state = { data: '', sourceCharset: 'UTF-8', targetCharset: 'GBK' };
        card.appendChild(el('div', { class: 'field-label' }, ['输入数据']));
        const srcSel = el('select', { class: 'fmt-select', 'data-field': 'charset-source' });
        srcSel.addEventListener('change', () => { state.sourceCharset = srcSel.value; });
        card.appendChild(srcSel);
        const ta = el('textarea', { class: 'textarea', rows: 5, 'data-field': 'charset-input' });
        ta.addEventListener('input', () => { state.data = ta.value; });
        card.appendChild(ta);
        card.appendChild(el('div', { class: 'field-label mt12' }, ['目标编码']));
        const dstSel = el('select', { class: 'fmt-select', 'data-field': 'charset-target' });
        dstSel.addEventListener('change', () => { state.targetCharset = dstSel.value; });
        card.appendChild(dstSel);
        const out = el('textarea', { class: 'textarea result-text', rows: 5, readonly: true, 'data-result': 'charset-out' });
        card.appendChild(out);
        const row = el('div', { class: 'actions-bar' });
        const btn = el('button', { class: 'btn btn-primary', 'data-action': 'charset-convert' }, ['转换']);
        const hexEl = el('div', { class: 'field-tip', 'data-result': 'charset-hex' });
        btn.addEventListener('click', async () => {
          try {
            const r = await CB.api('/api/encoding/charset', state);
            const obj = typeof r === 'string' ? { result: r, hex: '', length: 0 } : r;
            out.value = obj.result;
            hexEl.textContent = obj.hex ? ('字节序列（HEX，无损）：' + obj.hex.toUpperCase() + '　' + obj.length + ' 字节') : '';
            CB.toast('转换成功', 'success');
          } catch (e) { CB.toast(e.message, 'error'); }
        });
        card.appendChild(hexEl);
        row.appendChild(btn);
        row.appendChild(el('button', { class: 'btn btn-ghost', onclick: () => { ta.value = ''; out.value = ''; state.data = ''; } }, ['清除']));
        card.appendChild(row);
        CB.api('/api/encoding/charsets').then((list) => {
          const fill = (sel, current) => {
            sel.innerHTML = '';
            list.forEach((c) => sel.appendChild(el('option', { value: c, selected: c === current }, [c])));
          };
          fill(srcSel, 'UTF-8');
          fill(dstSel, 'GBK');
        }).catch(() => {});
      }

      function renderAsn1(host) {
        const card = panel();
        host.appendChild(card);
        const state = { data: '', dataFormat: 'HEX' };
        card.appendChild(el('div', { class: 'field-label' }, ['请输入 ASN.1 格式数据']));
        const fmt = el('select', { class: 'fmt-select', 'data-field': 'asn1-format' });
        [['HEX', '十六进制'], ['BASE64', 'Base64'], ['TEXT', '字符串']].forEach(([v, l]) => fmt.appendChild(el('option', { value: v, selected: v === 'HEX' }, [l])));
        fmt.addEventListener('change', () => { state.dataFormat = fmt.value; });
        card.appendChild(fmt);
        const ta = el('textarea', { class: 'textarea', rows: 8, 'data-field': 'asn1-input', placeholder: '请输入证书或 ASN.1 数据的 DER 十六进制内容' });
        ta.addEventListener('input', () => { state.data = ta.value; });
        card.appendChild(ta);
        const row = el('div', { class: 'actions-bar' });
        const btn = el('button', { class: 'btn btn-primary', 'data-action': 'asn1-parse' }, ['解析']);
        row.appendChild(btn);
        row.appendChild(el('button', { class: 'btn btn-ghost', onclick: () => { ta.value = ''; tree.innerHTML = ''; } }, ['清除']));
        card.appendChild(row);
        const tree = el('div', { class: 'tree mt12', 'data-result': 'asn1-tree' });
        card.appendChild(tree);
        btn.addEventListener('click', async () => {
          try {
            const data = await CB.api('/api/encoding/asn1/parse', state);
            tree.innerHTML = '';
            tree.appendChild(buildNode(data));
            CB.toast('ASN.1 解析成功', 'success');
          } catch (e) { CB.toast('ASN.1 解析失败：' + e.message, 'error'); }
        });
        function buildNode(node) {
          const item = el('div', { class: 'tree-node' });
          const head = el('div', { class: 'tree-row' });
          head.appendChild(el('span', { class: 'tree-type' }, [node.type]));
          if (node.value) head.appendChild(el('span', { class: 'tree-value' }, [': ' + node.value]));
          head.appendChild(el('span', { class: 'muted' }, ['  [长度: ' + node.contentLength + ']']));
          item.appendChild(head);
          if (node.children && node.children.length) {
            const ul = el('div', { class: 'tree-children' });
            node.children.forEach((c) => ul.appendChild(buildNode(c)));
            item.appendChild(ul);
          }
          return item;
        }
      }

      function renderUrl(host) {
        const card = panel();
        host.appendChild(card);
        const state = { data: '' };
        card.appendChild(el('div', { class: 'field-label' }, ['URL 编码内容']));
        const ta = el('textarea', { class: 'textarea', rows: 4, 'data-field': 'url-input', placeholder: '请输入需要解码的 URL 编码内容' });
        ta.addEventListener('input', () => { state.data = ta.value; });
        card.appendChild(ta);
        const out = el('textarea', { class: 'textarea result-text', rows: 4, readonly: true, 'data-result': 'url-out' });
        card.appendChild(out);
        const row = el('div', { class: 'actions-bar' });
        const btn = el('button', { class: 'btn btn-primary', 'data-action': 'url-decode' }, ['解码']);
        btn.addEventListener('click', async () => {
          try { out.value = await CB.api('/api/encoding/url', state); CB.toast('解码成功', 'success'); }
          catch (e) { CB.toast(e.message, 'error'); }
        });
        row.appendChild(btn);
        card.appendChild(row);
      }

      function renderIdentify(host) {
        const card = panel();
        host.appendChild(card);
        const state = { data: '', dataFormat: 'HEX' };
        card.appendChild(el('div', { class: 'field-label' }, ['待分析数据']));
        const fmt = el('select', { class: 'fmt-select', 'data-field': 'identify-format' });
        [['HEX', '十六进制'], ['BASE64', 'Base64'], ['TEXT', '字符串']].forEach(([v, l]) => fmt.appendChild(el('option', { value: v, selected: v === 'HEX' }, [l])));
        fmt.addEventListener('change', () => { state.dataFormat = fmt.value; });
        card.appendChild(fmt);
        const ta = el('textarea', { class: 'textarea', rows: 5, 'data-field': 'identify-input' });
        ta.addEventListener('input', () => { state.data = ta.value; });
        card.appendChild(ta);
        const out = el('div', { class: 'mt12', 'data-result': 'identify-out' });
        card.appendChild(out);
        const row = el('div', { class: 'actions-bar' });
        const btn = el('button', { class: 'btn btn-primary', 'data-action': 'identify' }, ['识别']);
        btn.addEventListener('click', async () => {
          try {
            const r = await CB.api('/api/encoding/identify', state);
            out.innerHTML = '';
            out.appendChild(el('div', { class: 'field-tip' }, ['数据长度：' + r.length + ' 字节 / ' + r.bits + ' 位']));
            const rows = [];
            r.hash.forEach((x) => rows.push(['杂凑算法', x.algo, x.value * 8 + ' 位']));
            r.symmetric.forEach((x) => rows.push(['对称算法', x.algo, x.value + ' 字节']));
            r.asymmetric.forEach((x) => rows.push(['非对称算法', x.algo, x.value + ' 字节']));
            if (!rows.length) out.appendChild(el('div', { class: 'muted' }, ['未识别到匹配的算法长度']));
            else out.appendChild(CB.table([{ key: '0', label: '类别' }, { key: '1', label: '可能的算法' }, { key: '2', label: '长度' }], rows.map((r) => ({ 0: r[0], 1: r[1], 2: r[2] }))));
            CB.toast('分析完成', 'success');
          } catch (e) { CB.toast(e.message, 'error'); }
        });
        row.appendChild(btn);
        card.appendChild(row);
      }

      paint();
    }
  });
})();


/* =====================================================================
 * 以下为追加模块：密文长度分析、大数运算、取模运算、逻辑运算、字节逆序
 * 字段名与原站 chunk（CipherLengthView / BigNumberView / ModView /
 * XORView / ByteReverseView）保持一致：s1/s1Format/s2/s2Format/p1/p1Format/resultFormat
 * ===================================================================== */

/* ---------------- 密文长度分析 ---------------- */
(function () {
  'use strict';
  const el = CB.el;

  const GROUP_LABEL = { HASH: '哈希算法', SYMMETRIC: '对称算法', ASYMMETRIC: '非对称算法' };

  function algoTable(rows) {
    if (!rows || !rows.length) {
      return el('div', { class: 'muted' }, ['暂无匹配结果']);
    }
    return CB.table([
      { key: 'name', label: '算法' },
      { key: 'length', label: '密文/分组长度' },
      { key: 'strength', label: '安全强度（位）' },
      { key: 'note', label: '说明' }
    ], rows.map((r) => Object.assign({}, r, { strength: String(r.strength) })));
  }

  function section(title, rows) {
    const box = el('div', { class: 'mt12' });
    box.appendChild(el('div', { class: 'result-head' }, [el('span', {}, [title + '（' + rows.length + '）'])]));
    box.appendChild(algoTable(rows));
    return box;
  }

  CB.register({
    key: 'length',
    cat: 'other',
    title: '密文长度分析',
    desc: '按输入长度推测可能的哈希 / 对称 / 非对称算法，并给出各算法的分组长度与安全强度',
    help: [
      { title: '分析说明', items: ['该工具通过输入长度和格式特征推测可能的算法类型，结果适合作为缩小排查范围的辅助信息。'] },
      { title: '使用建议', items: ['如果输入中包含空格、换行或前缀分隔，建议先清理后再分析。', '下方强度表会随分组切换更新，便于对照不同算法长度与安全级别。'] }
    ],
    state: { message: '', messageFormat: 'HEX', tableType: 'HASH' },
    fields: [
      {
        name: 'message', label: '输入数据', type: 'textarea', formatField: 'messageFormat',
        formats: [['TEXT', '字符串'], ['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 5,
        placeholder: '请输入待分析的数据（密文 / 摘要 / 签名）'
      },
      {
        name: 'tableType', label: '强度表分组', type: 'radio',
        options: [['HASH', '哈希算法'], ['SYMMETRIC', '对称算法'], ['ASYMMETRIC', '非对称算法']]
      }
    ],
    actions: [
      {
        name: 'analyze', label: '开始分析', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/other/length/analyze', {
            message: ctx.val('message'), messageFormat: ctx.val('messageFormat')
          });
          ctx.setResult('summary', [
            data.summary,
            data.hints.join('；')
          ].filter(Boolean).join('\n'));
          ctx.setResult('report', { kind: 'analyze', data });
          CB.toast('分析完成', 'success');
        }
      },
      {
        name: 'table', label: '查看分组强度表',
        run: async (ctx) => {
          const data = await CB.api('/api/other/length/table', { type: ctx.val('tableType') });
          ctx.setResult('summary', data.title + '：共 ' + data.total + ' 种算法，长度单位见表格。');
          ctx.setResult('report', { kind: 'table', data });
          CB.toast('查询完成', 'success');
        }
      }
    ],
    results: [
      { name: 'summary', label: '分析结论', type: 'textarea', rows: 4 },
      {
        name: 'report', label: '各算法分组与安全强度', type: 'custom',
        render: (box, ctx) => {
          box.setAttribute('data-result', 'report');
          const paint = (payload) => {
            box.innerHTML = '';
            if (!payload) {
              box.appendChild(el('div', { class: 'muted' }, ['请先点击“开始分析”或“查看分组强度表”']));
              return;
            }
            if (payload.kind === 'analyze') {
              const d = payload.data;
              box.appendChild(el('div', { class: 'field-tip' }, [
                '数据长度：' + d.bits + ' 位 / ' + d.bytes + ' 字节'
              ]));
              box.appendChild(section('哈希算法', d.hash));
              box.appendChild(section('对称算法', d.symmetric));
              box.appendChild(section('非对称算法', d.asymmetric));
              if (d.hints && d.hints.length) {
                const hint = el('div', { class: 'field-tip mt12' });
                d.hints.forEach((h) => hint.appendChild(el('div', {}, ['· ' + h])));
                box.appendChild(hint);
              }
            } else {
              const d = payload.data;
              box.appendChild(el('div', { class: 'field-tip' }, [d.title + '（共 ' + d.total + ' 种）']));
              box.appendChild(algoTable(d.rows));
            }
          };
          ctx.onResult = (name, value) => { if (name === 'report') paint(value); };
          paint(ctx.result('report'));
        }
      }
    ],
    samples: {
      analyze: { message: '0123456789abcdeffedcba9876543210', tableType: 'HASH' },
      table: { message: '', tableType: 'SYMMETRIC' }
    }
  });

  /* ---------------- 大数运算 ---------------- */
  (function () {
    const OPS = [
      ['add', 'A + B'], ['sub', 'A - B'], ['mul', 'A * B'], ['div', 'A / B'],
      ['mod', 'A % B'], ['pow', 'A ^ B'], ['cmp', '比较 A、B'],
      ['shl', 'A << B'], ['shr', 'A >> B'],
      ['and', 'A AND B'], ['or', 'A OR B'], ['xor', 'A XOR B']
    ];
    const sample = {
      s1: '0102030405060708',
      s2: '0102', resultFormat: 'HEX'
    };
    const actions = OPS.map(([op, label], idx) => ({
      name: op, label: label, primary: idx === 0,
      run: async (ctx) => {
        const data = await CB.api('/api/other/big/number', {
          type: op, s1: ctx.val('s1'), s1Format: ctx.val('s1Format'),
          s2: ctx.val('s2'), s2Format: ctx.val('s2Format'), resultFormat: ctx.val('resultFormat')
        });
        ctx.setResult('result', data.result);
        ctx.setResult('meta', op === 'cmp'
          ? ('比较结果：' + data.result + '（-1 表示 A < B）')
          : ('共 ' + data.bytes + ' 字节 / ' + data.bits + ' 位，十进制：' + data.decimal + (data.note ? '；' + data.note : '')));
        CB.toast('计算成功', 'success');
      }
    }));
    const samples = {};
    OPS.forEach(([op]) => { samples[op] = Object.assign({}, sample); });

    CB.register({
      key: 'big/number',
      cat: 'other',
      title: '大数运算',
      desc: 'HEX / Base64 大整数的加减乘除、取余、幂、比较、位移与位运算，结果可指定输出格式',
      help: [
        { title: '格式要求', items: ['输入支持 HEX 与 Base64，按大端无符号整数解释。', 'HEX 输出为大写，与原站保持一致。'] },
        { title: '运算说明', items: ['A - B 结果为负时按补码（最小编码宽度）表示，例如 01 - 03 = FE。', '幂与位移会做规模限制，避免超大结果拖垮浏览器。'] }
      ],
      state: { s1: '', s1Format: 'HEX', s2: '', s2Format: 'HEX', resultFormat: 'HEX' },
      fields: [
        {
          name: 's1', label: '数据 A', type: 'textarea', formatField: 's1Format',
          formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 3, placeholder: '请输入数据 A'
        },
        {
          name: 's2', label: '数据 B', type: 'textarea', formatField: 's2Format',
          formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 3, placeholder: '请输入数据 B'
        },
        { name: 'resultFormat', label: '结果输出格式', type: 'radio', options: [['HEX', '十六进制'], ['BASE64', 'Base64'], ['DEC', '十进制']] }
      ],
      actions: actions,
      results: [
        { name: 'result', label: '运算结果', type: 'textarea', rows: 4 },
        { name: 'meta', label: '结果说明', type: 'text' }
      ],
      samples: samples
    });
  })();

  /* ---------------- 取模运算 ---------------- */
  (function () {
    const OPS = [['add', 'A + B mod p'], ['sub', 'A - B mod p'], ['mul', 'A * B mod p'], ['pow', 'A ^ B mod p']];
    const sample = {
      s1: '0A0B0C', s2: '010203',
      p1: 'FFFEFD', resultFormat: 'HEX'
    };
    const actions = OPS.map(([op, label], idx) => ({
      name: op, label: label, primary: idx === 0,
      run: async (ctx) => {
        const data = await CB.api('/api/other/mod/number', {
          type: op, s1: ctx.val('s1'), s1Format: ctx.val('s1Format'),
          s2: ctx.val('s2'), s2Format: ctx.val('s2Format'),
          p1: ctx.val('p1'), p1Format: ctx.val('p1Format'), resultFormat: ctx.val('resultFormat')
        });
        ctx.setResult('result', data.result);
        ctx.setResult('meta', '共 ' + data.bytes + ' 字节 / ' + data.bits + ' 位，十进制：' + data.decimal + '，模数 P（十进制）：' + data.modulus);
        CB.toast('计算成功', 'success');
      }
    }));
    const samples = {};
    OPS.forEach(([op]) => { samples[op] = Object.assign({}, sample); });

    CB.register({
      key: 'mod/number',
      cat: 'other',
      title: '取模运算',
      desc: '大整数模运算：A+B、A-B、A*B 取模以及大数模幂 A^B mod P',
      help: [
        { title: '参数说明', items: ['模数 P 对应接口字段 p1 / p1Format，与原站协议保持一致。'] },
        { title: '格式要求', items: ['输入支持 HEX 与 Base64，HEX 输出统一大写。'] }
      ],
      state: { s1: '', s1Format: 'HEX', s2: '', s2Format: 'HEX', p1: '', p1Format: 'HEX', resultFormat: 'HEX' },
      fields: [
        { name: 's1', label: '数据 A', type: 'textarea', formatField: 's1Format', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 3, placeholder: '请输入数据 A' },
        { name: 's2', label: '数据 B', type: 'textarea', formatField: 's2Format', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 3, placeholder: '请输入数据 B' },
        { name: 'p1', label: '模数 P', type: 'textarea', formatField: 'p1Format', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 2, placeholder: '请输入模数 P' },
        { name: 'resultFormat', label: '结果输出格式', type: 'radio', options: [['HEX', '十六进制'], ['BASE64', 'Base64'], ['DEC', '十进制']] }
      ],
      actions: actions,
      results: [
        { name: 'result', label: '运算结果', type: 'textarea', rows: 4 },
        { name: 'meta', label: '结果说明', type: 'text' }
      ],
      samples: samples
    });
  })();

  /* ---------------- 逻辑运算 ---------------- */
  (function () {
    const OPS = [['AND', '逻辑与'], ['OR', '逻辑或'], ['XOR', '逻辑异或'], ['NOT', '逻辑非']];
    const sample = { s1: 'F0F0F0F0', s2: '0FF00FF0', resultFormat: 'HEX' };
    const actions = OPS.map(([op, label], idx) => ({
      name: op.toLowerCase(), label: label, primary: idx === 0,
      run: async (ctx) => {
        const data = await CB.api('/api/other/xor', {
          type: op, s1: ctx.val('s1'), s1Format: ctx.val('s1Format'),
          s2: ctx.val('s2'), s2Format: ctx.val('s2Format'), resultFormat: ctx.val('resultFormat')
        });
        ctx.setResult('result', data.result);
        ctx.setResult('meta', '共 ' + data.bytes + ' 字节 / ' + data.bits + ' 位' + (data.note ? '；' + data.note : ''));
        CB.toast('计算成功', 'success');
      }
    }));
    const samples = {};
    OPS.forEach(([op]) => { samples[op.toLowerCase()] = Object.assign({}, sample); });

    CB.register({
      key: 'xor',
      cat: 'other',
      title: '逻辑运算',
      desc: '按字节执行 AND / OR / XOR / NOT，支持 HEX 与 Base64 输入输出',
      help: [
        { title: '运算说明', items: ['AND、OR、XOR 需要同时输入数据 A 和数据 B；NOT 仅处理数据 A。', '长度不一致时按较长一方处理，较短一方左侧补 0（与原站一致）。'] },
        { title: '格式建议', items: ['建议先清理空白字符，避免人工分段导致格式校验失败。'] }
      ],
      state: { s1: '', s1Format: 'HEX', s2: '', s2Format: 'HEX', resultFormat: 'HEX' },
      fields: [
        { name: 's1', label: '数据 A', type: 'textarea', formatField: 's1Format', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 3, placeholder: '请输入数据 A' },
        { name: 's2', label: '数据 B', type: 'textarea', formatField: 's2Format', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 3, placeholder: '请输入数据 B（NOT 运算可留空）' },
        { name: 'resultFormat', label: '结果输出格式', type: 'radio', options: [['HEX', '十六进制'], ['BASE64', 'Base64']] }
      ],
      actions: actions,
      results: [
        { name: 'result', label: '运算结果', type: 'textarea', rows: 4 },
        { name: 'meta', label: '结果说明', type: 'text' }
      ],
      samples: samples
    });
  })();

  /* ---------------- 字节逆序 ---------------- */
  CB.register({
    key: 'byte/reverse',
    cat: 'other',
    title: '字节逆序',
    desc: '整段字节逆序，或按 2 / 4 / 8 / 16 字节分组做组内字节序翻转（大小端互换）',
    help: [
      { title: '格式说明', items: ['支持 HEX 与 Base64 输入输出，HEX 输出为大写。'] },
      { title: '使用建议', items: ['按分组翻转要求数据长度为分组大小的整数倍。', '如果数据中含有空格、换行或人工分段，建议先清理再运算。'] }
    ],
    state: { s1: '', s1Format: 'HEX', mode: 'all', resultFormat: 'HEX' },
    fields: [
      { name: 's1', label: '输入数据', type: 'textarea', formatField: 's1Format', formats: [['HEX', '十六进制'], ['BASE64', 'Base64']], rows: 4, placeholder: '请输入待逆序的数据' },
      {
        name: 'mode', label: '逆序方式', type: 'radio',
        options: [['all', '整段逆序'], ['2', '2 字节分组'], ['4', '4 字节分组'], ['8', '8 字节分组'], ['16', '16 字节分组']]
      },
      { name: 'resultFormat', label: '结果输出格式', type: 'radio', options: [['HEX', '十六进制'], ['BASE64', 'Base64']] }
    ],
    actions: [
      {
        name: 'reverse', label: '执行逆序', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/other/byte/reverse', {
            s1: ctx.val('s1'), s1Format: ctx.val('s1Format'),
            mode: ctx.val('mode'), resultFormat: ctx.val('resultFormat')
          });
          ctx.setResult('result', data.result);
          ctx.setResult('meta', data.label + '：共 ' + data.bytes + ' 字节，' + data.groups + ' 组');
          CB.toast('计算成功', 'success');
        }
      }
    ],
    results: [
      { name: 'result', label: '运算结果', type: 'textarea', rows: 4 },
      { name: 'meta', label: '结果说明', type: 'text' }
    ],
    samples: {
      reverse: { s1: '0102030405060708', mode: 'all', resultFormat: 'HEX' }
    }
  });
})();
