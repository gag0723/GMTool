/* 全站下拉巡检：逐个模块打开页面，检查是否存在“空下拉条（无可选项）” */
const { openPage, waitFor, sleep } = require('./harness');

(async () => {
  const { win, doc, errors } = await openPage('home');
  await waitFor(() => win.CB && win.CB.modules, 8000, '框架');
  const keys = Object.keys(win.CB.modules);
  const problems = [];
  const report = [];

  for (const key of keys) {
    win.location.hash = '#/' + key;
    await sleep(420);
    const selects = Array.from(doc.querySelectorAll('select'));
    const empty = selects.filter((s) => s.options.length === 0)
      .map((s) => s.getAttribute('data-field') || s.getAttribute('data-format') || s.className);
    const radios = Array.from(doc.querySelectorAll('.radio-group'))
      .filter((g) => g.querySelectorAll('button').length === 0).length;
    if (selects.length || radios) {
      report.push(key + '：select ' + selects.length + ' 个' + (empty.length ? '，空选项 ' + empty.length : '') +
        (radios ? '，空单选组 ' + radios : ''));
    }
    if (empty.length) problems.push({ key, empty });
  }

  console.log('模块总数：', keys.length);
  console.log(report.join('\n'));
  console.log('\n空下拉问题：', problems.length ? JSON.stringify(problems, null, 1) : '无');
  const realErrors = errors.filter((e) => !e.includes('scrollTo'));
  console.log('页面错误：', JSON.stringify(realErrors));
  win.close();
  process.exit(problems.length ? 1 : 0);
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
