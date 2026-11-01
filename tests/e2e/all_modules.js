/* 全模块 E2E：遍历 CB.modules 的每个 action，用 samples 填表并断言有结果 */
const h = require('./harness');

(async () => {
  const { dom, win, doc, errors } = await h.openPage('home');
  const mods = Object.values(win.CB.modules);
  const results = [];
  const failures = [];
  let totalActions = 0;

  console.log('已注册模块：', mods.length);
  for (const mod of mods) {
    const actions = (mod.actions || []).filter((a) => a.name !== 'clean' && a.name !== 'clear');
    if (!actions.length) {
      results.push({ module: mod.key, skipped: true, reason: mod.render ? '自定义页面（单独测试）' : '无 action' });
      continue;
    }
    for (const a of actions) {
      totalActions += 1;
      const sample = mod.samples && mod.samples[a.name];
      if (!sample) { failures.push(`${mod.key}/${a.name}: 缺少 samples`); continue; }
      win.location.hash = '#/' + mod.key;
      await h.sleep(180);
      try {
        for (const [k, v] of Object.entries(sample)) {
          if (v && typeof v === 'object') {
            // 文件类字段：直接注入已解码的文件内容
            const b64 = v.b64 || '';
            const bin = Buffer.from(b64, 'base64');
            win.CB.current.files[k] = {
              name: v.name || 'fixture.bin',
              b64,
              text: bin.toString('utf8'),
              bytes: new Uint8Array(bin)
            };
            continue;
          }
          await h.setField(doc, k, v);
        }
        await h.clickAction(doc, a.name);
        await h.waitFor(() => {
          const t = h.lastToast(doc);
          if (/失败|错误|非法|请检查|不支持/.test(t)) throw new Error(t);
          const outs = (mod.results || []).map((r) => h.resultText(doc, r.name)).filter(Boolean);
          return /成功|完成|通过/.test(t) || outs.length > 0 || (mod.customResult && mod.customResult(doc));
        }, 15000, `${mod.key}/${a.name}`);
        await h.sleep(100);
        const outs = (mod.results || []).map((r) => h.resultText(doc, r.name)).filter(Boolean);
        if (outs.length === 0 && !/成功|完成|通过/.test(h.lastToast(doc))) {
          throw new Error('无结果输出');
        }
        results.push({ module: mod.key, action: a.name, outputs: outs.map((x) => String(x).slice(0, 60)) });
      } catch (e) {
        failures.push(`${mod.key}/${a.name}: ${e.message}（toast: ${h.lastToast(doc)}）`);
      }
    }
  }

  console.log('\n===== 结果 =====');
  results.forEach((r) => {
    if (r.skipped) return;
    console.log(`✔ ${r.module}/${r.action}  ->  ${(r.outputs[0] || '').slice(0, 48)}`);
  });
  const skipped = results.filter((r) => r.skipped);
  if (skipped.length) console.log('\n跳过（自定义页面）：', skipped.map((s) => s.module).join(', '));
  if (failures.length) {
    console.log('\n===== 失败 ' + failures.length + ' =====');
    failures.forEach((f) => console.log('✘ ' + f));
  }
  console.log(`\n动作总数 ${totalActions}，通过 ${results.filter((r) => !r.skipped).length}，失败 ${failures.length}`);
  if (errors.length) console.log('页面错误：', errors.filter((e) => !/scrollTo/.test(e)).slice(0, 8));
  dom.window.close();
  process.exitCode = failures.length ? 1 : 0;
})();
