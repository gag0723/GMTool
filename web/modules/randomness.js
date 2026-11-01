/* 随机数检测（NIST SP 800-22 常用子集）与随机数生成 */
(function () {
  'use strict';
  const el = CB.el;

  /* 固定示例：SHA-256 计数器模式生成的 256 字节（2048 比特）序列，已确认全部检测项通过 */
  const SAMPLE_DATA = 'a6685f3b62d57bfc4935263140bae87fcd48088975c238c1c8455fa2c716659dd6b5915c46057bcb005f46f6433df656'
    + '09dd3a7a57af75ac1a5a4a7c299ebffb673aeeb08cfbb00b91e5e3c60b5ba31896d55b522b1be2dccb0645a59bae877585'
    + 'f2ef987b76f4c3fc081acef84e0a730f5df8a2488a5bb7ddae4f7dee721ed8492ab00bbe71db09cc80c473346ab2119a857'
    + '3638cf8c433e3d91a1a450522fc6669b8482999dfdcef11e5e9a07caffabe2509d25d14904f74ef47054de3af1b62325dfc'
    + '1fc675255519674da6e2c4aad5f51cc6c3217ed3c6fbf6cabe0d86b03d5f0fd838606f1f7c5b2a7cf3cfaa325e5552bc8f'
    + '28ff26559445531a30fa60';

  function badge(passed) {
    if (passed === null || passed === undefined) return CB.badge(true, '跳过', '跳过');
    return CB.badge(!!passed);
  }

  CB.register({
    key: 'randomness',
    cat: 'ability',
    title: '随机数检测',
    desc: 'NIST SP 800-22 常用子集：频数、块内频数、游程、最长游程、累积和、近似熵、序列、离散傅里叶，并可生成随机数',
    help: [
      { title: '标准依据', items: ['检测项实现依据 NIST SP 800-22 Rev.1a，共 8 类检测、9 个 P 值。', '原站采用 GM/T 0005-2021 的 29 项检测，本工具按其常用交集实现本地可复现的版本。'] },
      { title: '结果判定', items: ['单项 P 值 ≥ 0.01 判定通过（序列检测要求 P1、P2 同时通过）。', '全部检测项通过则总体结论为“通过”，否则说明序列可能存在非随机特征。'] },
      { title: '数据要求', items: ['至少 128 比特；离散傅里叶检测对超过 131072 比特的数据会自动跳过（纯 Python FFT 耗时限制）。', '可直接输入 HEX / Base64 / 字符串，或上传二进制文件。'] }
    ],
    state: { data: '', dataFormat: 'HEX', bits: 256, genFormat: 'HEX' },
    fields: [
      {
        name: 'data', label: '待检测数据', type: 'textarea', formatField: 'dataFormat',
        formats: [['HEX', '十六进制'], ['BASE64', 'Base64'], ['TEXT', '字符串']], rows: 6,
        placeholder: '请输入待检测的随机数序列（HEX / Base64 / 字符串），或上传二进制文件'
      },
      {
        name: 'fileBin', label: '上传二进制文件', type: 'file', accept: '.bin,.dat,.rand,.rnd',
        placeholder: '选择文件后将自动按 Base64 读入上方输入框',
        onFile: (file, ctx) => {
          ctx.set('data', file.b64);
          ctx.set('dataFormat', 'BASE64');
          CB.toast('文件已读入（' + file.bytes.length + ' 字节）', 'success');
          ctx.refresh();
        }
      },
      { name: 'bits', label: '生成随机数位数', type: 'number', min: 8, max: 1048576, step: 8, tip: '调用操作系统 CSPRNG（os.urandom）生成' },
      { name: 'genFormat', label: '生成结果格式', type: 'radio', options: [['HEX', '十六进制'], ['BASE64', 'Base64']] }
    ],
    actions: [
      {
        name: 'detect', label: '开始检测', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/random/detect', {
            data: ctx.val('data'), dataFormat: ctx.val('dataFormat')
          });
          const passed = data.passedCount + '/' + data.total;
          ctx.setResult('summary', [
            '总体结论：' + (data.passed ? '通过' : '不通过'),
            '样本长度：' + data.bits + ' 比特（' + data.bytes + ' 字节）',
            '通过项数：' + passed + '（判定门限 P ≥ ' + data.threshold + '）',
            data.conclusion
          ].join('\n'));
          ctx.setResult('report', data);
          CB.toast('检测完成：' + (data.passed ? '通过' : '不通过'), data.passed ? 'success' : 'warn');
        }
      },
      {
        name: 'generate', label: '生成随机数',
        run: async (ctx) => {
          const data = await CB.api('/api/random/generate', {
            bits: ctx.val('bits'), format: ctx.val('genFormat')
          });
          ctx.setResult('sequence', data.value);
          ctx.setResult('summary', '已生成 ' + data.bits + ' 比特随机数（' + data.bytes + ' 字节），来源：' + data.source);
          CB.toast('生成成功', 'success');
        }
      }
    ],
    results: [
      { name: 'summary', label: '检测结论', type: 'textarea', rows: 5 },
      { name: 'sequence', label: '生成的随机数', type: 'textarea', rows: 4 },
      {
        name: 'report', label: '逐项检测结果', type: 'custom',
        render: (box, ctx) => {
          box.setAttribute('data-result', 'report');
          const paint = (data) => {
            box.innerHTML = '';
            if (!data) {
              box.appendChild(el('div', { class: 'muted' }, ['请输入或生成随机数后点击“开始检测”']));
              return;
            }
            const head = el('div', { class: 'input-bar' }, [
              el('span', { class: 'field-label' }, ['总体结论：' + (data.passed ? '通过' : '不通过')]),
              badge(data.passed),
              el('span', { class: 'field-tip' }, [
                '　样本 ' + data.bits + ' 比特　通过 ' + data.passedCount + '/' + data.total +
                '　门限 P ≥ ' + data.threshold + '　' + data.standard
              ])
            ]);
            box.appendChild(head);
            const rows = data.tests.map((t, i) => ({
              idx: String(i + 1),
              name: t.name,
              stat: t.statistic === null || t.statistic === undefined ? '-' : String(t.statistic),
              p1: t.pvalue === null || t.pvalue === undefined ? '-' : Number(t.pvalue).toFixed(6),
              p2: t.pvalue2 === null || t.pvalue2 === undefined ? '-' : Number(t.pvalue2).toFixed(6),
              verdict: t.passed === null || t.passed === undefined ? '跳过' : (t.passed ? '通过' : '不通过')
            }));
            box.appendChild(CB.table([
              { key: 'idx', label: '#' },
              { key: 'name', label: '检测项' },
              { key: 'stat', label: '统计量' },
              { key: 'p1', label: 'P 值' },
              { key: 'p2', label: 'P 值 2' },
              { key: 'verdict', label: '结论' }
            ], rows));
            const notes = el('div', { class: 'field-tip mt12' });
            data.tests.forEach((t, i) => {
              notes.appendChild(el('div', {}, ['[' + (i + 1) + '] ' + t.name + '：' + (t.note || '-')]));
            });
            box.appendChild(notes);
          };
          ctx.onResult = (name, value) => { if (name === 'report') paint(value); };
          paint(ctx.result('report'));
        }
      }
    ],
    samples: {
      detect: { data: SAMPLE_DATA },
      generate: { bits: 256, genFormat: 'HEX' }
    }
  });
})();
