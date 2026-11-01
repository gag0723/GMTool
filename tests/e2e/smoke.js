/* 冒烟：哈希 / 编码转换 两个示例模块的真实交互 */
const h = require('./harness');

(async () => {
  const { dom, win, doc, errors } = await h.openPage('hash');
  try {
    console.log('模块数量：', Object.keys(win.CB.modules).length);
    await h.setField(doc, 'type', 'SM3');
    await h.setField(doc, 'message', 'abc');
    await h.clickAction(doc, 'digest');
    await h.waitFor(() => (doc.querySelector('[data-result="result"]') || {}).value, 8000, '哈希结果');
    const v = doc.querySelector('[data-result="result"]').value;
    console.log('SM3(abc) =', v);
    if (!v.startsWith('66c7f0f4')) throw new Error('SM3 结果不正确');

    win.location.hash = '#/encode';
    await h.sleep(250);
    const ta = doc.querySelector('[data-field="convert-input"]');
    ta.value = 'abc';
    ta.dispatchEvent(new win.Event('input', { bubbles: true }));
    doc.querySelector('[data-action="convert"]').click();
    await h.waitFor(() => (doc.querySelector('[data-result="convert-out"]') || {}).value, 8000, '编码结果');
    console.log('TEXT->HEX =', doc.querySelector('[data-result="convert-out"]').value);
    if (doc.querySelector('[data-result="convert-out"]').value !== '616263') throw new Error('编码转换结果不正确');
    console.log('示例模块冒烟通过');
  } catch (e) {
    console.error('失败：', e.message, 'toast=', h.lastToast(doc));
    process.exitCode = 1;
  } finally {
    if (errors.length) console.log('页面错误：', errors.slice(0, 5));
    dom.window.close();
  }
})();
