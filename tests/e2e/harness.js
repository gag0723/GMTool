/* 通用 E2E 测试框架：jsdom 驱动真实页面 + 真实后端 */
const { JSDOM, VirtualConsole } = require('jsdom');

const BASE = process.env.CB_BASE || 'http://127.0.0.1:18080';

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function waitFor(fn, timeout = 8000, label = '条件') {
  const start = Date.now();
  let lastErr = null;
  while (Date.now() - start < timeout) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) { lastErr = e; }
    await sleep(60);
  }
  throw new Error('等待超时：' + label + (lastErr ? '（' + lastErr.message + '）' : ''));
}

async function openPage(hash = 'home') {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => errors.push('jsdom: ' + e.message));
  vc.on('error', (m) => errors.push('console.error: ' + m));
  const dom = await JSDOM.fromURL(BASE + '/#/' + hash, {
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
    virtualConsole: vc
  });
  const win = dom.window;
  await waitFor(() => win.CB && win.CB.modules && Object.keys(win.CB.modules).length > 0, 8000, '前端框架加载');
  win.fetch = (url, opts) => fetch(new URL(url, BASE).toString(), opts);
  if (!win.crypto || !win.crypto.getRandomValues) {
    win.crypto = { getRandomValues: (arr) => require('crypto').randomFillSync(arr) };
  }
  await sleep(120);
  if (win.location.hash !== '#/' + hash) {
    win.location.hash = '#/' + hash;
    await sleep(150);
  }
  return { dom, win, doc: win.document, errors };
}

async function setField(doc, name, value) {
  const holder = doc.querySelector('[data-field="' + name + '"]') ||
    doc.querySelector('[data-format="' + name + '"]');
  if (!holder) throw new Error('找不到字段：' + name);
  if (holder.tagName === 'DIV' && holder.classList.contains('radio-group')) {
    const btn = holder.querySelector('button[data-value="' + value + '"]');
    if (!btn) throw new Error('找不到单选值：' + name + '=' + value);
    btn.click();
    await sleep(30);
    return;
  }
  if (holder.tagName === 'SELECT') {
    holder.value = String(value);
    holder.dispatchEvent(new doc.defaultView.Event('change', { bubbles: true }));
    await sleep(30);
    return;
  }
  if (holder.tagName === 'TEXTAREA' || holder.tagName === 'INPUT') {
    holder.value = String(value);
    holder.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
    await sleep(20);
    return;
  }
  throw new Error('字段类型不支持：' + name + ' ' + holder.tagName);
}

async function clickAction(doc, action) {
  const btn = doc.querySelector('[data-action="' + action + '"]');
  if (!btn) throw new Error('找不到按钮：' + action);
  btn.click();
  return btn;
}

function resultText(doc, name) {
  const node = doc.querySelector('[data-result="' + name + '"]');
  if (!node) return null;
  return node.tagName === 'TEXTAREA' || node.tagName === 'INPUT' ? node.value : node.textContent;
}

function lastToast(doc) {
  const items = doc.querySelectorAll('.toast');
  return items.length ? items[items.length - 1].textContent : '';
}

async function runModuleSamples(win, doc, mod, results, failures) {
  for (const action of mod.actions || []) {
    const sample = mod.samples && mod.samples[action.name];
    if (!sample) { failures.push(`${mod.key}/${action.name}: 缺少 sample`); continue; }
    win.location.hash = '#/' + mod.key;
    await sleep(200);
    try {
      for (const [k, v] of Object.entries(sample)) await setField(doc, k, v);
      await clickAction(doc, action.name);
      await waitFor(() => {
        const t = lastToast(doc);
        if (t.includes('失败') || t.includes('错误') || t.includes('非法') || t.includes('请检查')) throw new Error(t);
        return t.includes('成功') || t.includes('完成') || t.includes('通过') || (mod.results || []).some((r) => resultText(doc, r.name));
      }, 10000, `${mod.key}/${action.name} 结果`);
      await sleep(120);
      const outputs = (mod.results || []).map((r) => ({ name: r.name, value: resultText(doc, r.name) || '' }));
      results.push({ module: mod.key, action: action.name, outputs });
    } catch (e) {
      failures.push(`${mod.key}/${action.name}: ${e.message}（提示：${lastToast(doc)}）`);
    }
  }
}

module.exports = { BASE, sleep, waitFor, openPage, setField, clickAction, resultText, lastToast, runModuleSamples };
