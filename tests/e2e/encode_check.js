/* 编码转换工具（自定义页面）5 个子页签巡检：下拉是否有选项、动作是否出结果 */
const { openPage, waitFor, sleep } = require('./harness');

function fill(doc, sel, value) {
  const node = doc.querySelector(sel);
  if (!node) throw new Error('找不到输入框 ' + sel);
  node.value = value;
  node.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
}

function optionReport(doc, label) {
  const sels = Array.from(doc.querySelectorAll('.tabs ~ div select'));
  const info = sels.map((s) => (s.getAttribute('data-field') || 'select') + '=' + s.options.length);
  const empty = sels.filter((s) => s.options.length === 0).map((s) => s.getAttribute('data-field') || 'select');
  return label + ' 下拉：' + (info.join(' ') || '无') + (empty.length ? '  ❌空选项：' + empty.join(',') : '  ✓');
}

async function click(doc, selector) {
  const node = doc.querySelector(selector);
  if (!node) throw new Error('找不到元素 ' + selector);
  node.click();
}

(async () => {
  const { win, doc, errors } = await openPage('encode');
  const toast = () => {
    const items = doc.querySelectorAll('.toast');
    return items.length ? items[items.length - 1].textContent : '';
  };
  let fails = 0;

  // 1) 编码转换
  await click(doc, '[data-tab="convert"]'); await sleep(150);
  console.log(optionReport(doc, '编码转换'));
  fill(doc, '[data-field="convert-input"]', 'hello');
  await click(doc, '[data-action="convert"]'); await sleep(500);
  let out = doc.querySelector('[data-result="convert-out"]');
  console.log('  convert 结果：', out && out.value ? out.value.slice(0, 40) : '❌空');
  if (!out || !out.value) fails += 1;

  // 2) 字符集转换
  await click(doc, '[data-tab="charset"]'); await sleep(150);
  console.log(optionReport(doc, '字符集转换'));
  const src = doc.querySelector('[data-field="charset-source"]');
  const dst = doc.querySelector('[data-field="charset-target"]');
  console.log('  源字符集选项：', src ? src.options.length : '无', ' 目标字符集选项：', dst ? dst.options.length : '无');
  if (!src || src.options.length === 0 || !dst || dst.options.length === 0) fails += 1;
  fill(doc, '[data-field="charset-input"]', '你好');
  await click(doc, '[data-action="charset-convert"]'); await sleep(500);
  out = doc.querySelector('[data-result="charset-out"]');
  console.log('  charset 结果：', out && out.value ? out.value.slice(0, 40) : '❌空', '|', toast());
  if (!out || !out.value) fails += 1;

  // 3) ASN.1 解析
  await click(doc, '[data-tab="asn1"]'); await sleep(150);
  console.log(optionReport(doc, 'ASN.1 解析'));
  fill(doc, '[data-field="asn1-input"]', '3006020101020102');
  await click(doc, '[data-action="asn1-parse"]'); await sleep(600);
  const tree = doc.querySelector('[data-result="asn1-tree"]');
  console.log('  asn1 结果：', tree && tree.textContent.trim() ? tree.textContent.trim().slice(0, 60) : '❌空');
  if (!tree || !tree.textContent.trim()) fails += 1;

  // 4) URL 解码
  await click(doc, '[data-tab="url"]'); await sleep(150);
  console.log(optionReport(doc, 'URL 解码'));
  fill(doc, '[data-field="url-input"]', '%E4%BD%A0%E5%A5%BD%20a%2Bb');
  await click(doc, '[data-action="url-decode"]'); await sleep(500);
  out = doc.querySelector('[data-result="url-out"]');
  console.log('  url 结果：', out && out.value ? out.value : '❌空');
  if (!out || !out.value) fails += 1;

  // 5) 算法识别
  await click(doc, '[data-tab="identify"]'); await sleep(150);
  console.log(optionReport(doc, '算法识别'));
  fill(doc, '[data-field="identify-input"]', '0123456789abcdeffedcba9876543210');
  await click(doc, '[data-action="identify"]'); await sleep(600);
  const idOut = doc.querySelector('[data-result="identify-out"]');
  console.log('  identify 结果：', idOut && idOut.textContent.trim() ? idOut.textContent.trim().slice(0, 60) : '❌空');
  if (!idOut || !idOut.textContent.trim()) fails += 1;

  console.log('页面错误：', JSON.stringify(errors.filter((e) => !e.includes('scrollTo'))));
  console.log(fails ? '❌ 失败项：' + fails : '✓ 编码转换工具 5 个子页签全部可用');
  win.close();
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
