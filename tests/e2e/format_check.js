/* 全站页面格式校验：逐模块执行动作后，检查结果区是否有渲染/格式问题 */
const { openPage, waitFor, sleep } = require('./harness');

const BAD_TOKENS = [
  ['undefined', '未定义值 undefined'],
  ['NaN', '数值 NaN'],
  ['[object Object]', '对象未展开'],
  ['Infinity', '无穷大 Infinity'],
  ['Invalid Date', '无效日期']
];

function inspectResult(doc) {
  const issues = [];
  const card = doc.querySelector('.results-card');
  if (!card) return issues;
  const txt = card.textContent || '';

  BAD_TOKENS.forEach(([tok, label]) => {
    if (tok === 'NaN') {
      if (/(^|[^A-Za-z0-9])NaN([^A-Za-z0-9]|$)/.test(txt)) issues.push(label);
    } else if (txt.includes(tok)) issues.push(label);
  });
  if (txt.includes('\uFFFD')) issues.push('出现乱码替换符 \uFFFD');

  const tables = Array.from(card.querySelectorAll('table'));
  tables.forEach((t, i) => {
    const headRow = t.querySelector('thead tr');
    const headCells = headRow ? headRow.children.length : 0;
    const rows = Array.from(t.querySelectorAll('tbody tr'));
    if (!rows.length && headCells) issues.push('表' + (i + 1) + ' 只有表头没有数据');
    rows.forEach((tr, ri) => {
      if (headCells && tr.children.length !== headCells) {
        issues.push('表' + (i + 1) + ' 第' + (ri + 1) + '行列数 ' + tr.children.length + ' ≠ 表头 ' + headCells);
      }
      if (tr.children.length === 1 && headCells > 1) issues.push('表' + (i + 1) + ' 第' + (ri + 1) + '行只有一列（疑似合并错乱）');
    });
  });

  const names = Array.from(card.querySelectorAll('[data-result]')).map((n) => n.getAttribute('data-result'));
  const dup = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))];
  if (dup.length) issues.push('重复结果容器：' + dup.join(','));

  if (/<\/?[a-z][a-z0-9]*\s[^>]*>/i.test(txt)) issues.push('文本中出现疑似未转义的 HTML 标签');

  return issues;
}

(async () => {
  const { win, doc, errors } = await openPage('home');
  await waitFor(() => win.CB && win.CB.modules, 8000, '框架');
  const keys = Object.keys(win.CB.modules);
  const problems = [];
  let actionCount = 0;

  for (const key of keys) {
    const mod = win.CB.modules[key];
    const actions = mod.actions || [];
    if (!actions.length) continue;
    for (const action of actions) {
      const sample = mod.samples && mod.samples[action.name];
      if (!sample) continue;
      win.location.hash = '#/' + key;
      await sleep(260);
      try {
        for (const [k, v] of Object.entries(sample)) {
          const holder = doc.querySelector('[data-field="' + k + '"]') || doc.querySelector('[data-format="' + k + '"]');
          if (!holder) continue;
          if (holder.tagName === 'SELECT') {
            holder.value = String(v);
            holder.dispatchEvent(new doc.defaultView.Event('change', { bubbles: true }));
          } else if (holder.tagName === 'INPUT' || holder.tagName === 'TEXTAREA') {
            holder.value = String(v);
            holder.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
          } else if (holder.classList.contains('radio-group')) {
            const btn = holder.querySelector('button[data-value="' + v + '"]');
            if (btn) btn.click();
          }
          await sleep(20);
        }
        const btn = doc.querySelector('[data-action="' + action.name + '"]');
        if (!btn) { problems.push({ key, action: action.name, issues: ['找不到动作按钮'] }); continue; }
        btn.click();
        actionCount += 1;
        await sleep(1200);
        const issues = inspectResult(doc);
        if (issues.length) problems.push({ key, action: action.name, issues });
      } catch (e) {
        problems.push({ key, action: action.name, issues: ['执行异常：' + e.message] });
      }
    }
  }

  console.log('模块数：', keys.length, '　已执行动作：', actionCount);
  if (!problems.length) {
    console.log('✓ 所有页面结果区格式正常（无 undefined / NaN / 未展开对象 / 乱码 / 列数错乱 / 空表）');
  } else {
    console.log('发现问题：', problems.length);
    problems.forEach((p) => console.log('  ' + p.key + '/' + p.action + ' -> ' + p.issues.join('；')));
  }
  const realErrors = errors.filter((e) => !e.includes('scrollTo'));
  console.log('页面错误：', JSON.stringify(realErrors));
  win.close();
  process.exit(problems.length ? 1 : 0);
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
