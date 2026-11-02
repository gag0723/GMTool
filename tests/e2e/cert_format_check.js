/* 证书格式检查页面：自签证书实测 + 节点切换后结果归属校验 */
const fs = require('fs');
const { openPage, waitFor, sleep } = require('./harness');

const CA_PEM = fs.readFileSync(process.env.CA_PEM_FILE || '/root/.hermes/cache/scratch/ca.pem', 'utf8');
const LEAF_PEM = fs.readFileSync(process.env.LEAF_PEM_FILE || '/root/.hermes/cache/scratch/leaf.pem', 'utf8');

function treeRow(doc, name) {
  return Array.from(doc.querySelectorAll('.tree-row')).find((r) => r.textContent.includes(name));
}

async function selectNode(doc, name) {
  const row = treeRow(doc, name);
  if (!row) throw new Error('找不到节点：' + name);
  row.click();
  await sleep(300);
}

async function setCert(doc, pem) {
  const ta = doc.querySelector('[data-field="cert"]');
  if (!ta) throw new Error('找不到证书输入框');
  ta.value = pem;
  ta.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
  await sleep(120);
}

async function verify(doc) {
  doc.querySelector('[data-action="formatCheck"]').click();
  await waitFor(() => {
    const box = doc.querySelector('[data-result="formatResult"]');
    return box && box.textContent.includes('证书信息') && !box.textContent.includes('正在');
  }, 15000, '格式验证结果');
  await sleep(200);
  return doc.querySelector('[data-result="formatResult"]');
}

function sections(box) {
  return Array.from(box.querySelectorAll('.card-title')).map((n) => n.textContent.trim());
}

(async () => {
  const { win, doc, errors } = await openPage('cert/format/check');
  await waitFor(() => doc.querySelector('[data-field="cert"]'), 8000, '证书输入框');
  let fails = 0;
  const bad = (m) => { console.log('❌', m); fails += 1; };
  const ok = (m) => console.log('✓', m);

  // 1) 终端证书节点：用本地 CA 签发的终端证书
  await selectNode(doc, '终端证书');
  await setCert(doc, LEAF_PEM);
  let box = await verify(doc);
  const text1 = box.textContent;
  const sec1 = sections(box);
  console.log('分区标题：', sec1.join(' / '));
  if (sec1.length === 3 && sec1[0] === '证书信息' && /检查项（\d+ 项）/.test(sec1[1]) && /扩展项（\d+ 项）/.test(sec1[2])) {
    ok('结果分为「证书信息 / 检查项 / 扩展项」三段');
  } else bad('分区标题异常：' + sec1.join(','));
  if (text1.includes('节点：终端证书')) ok('结果归属终端证书节点'); else bad('结果未标注终端证书节点');
  if (text1.includes('测试站点证书')) ok('终端证书主题正确'); else bad('终端证书主题缺失');
  if (text1.includes('待验证')) ok('非自签证书签名状态为“待验证”'); else bad('非自签证书签名状态异常');

  const tables = Array.from(box.querySelectorAll('table'));
  const cols = tables.map((t) => Array.from(t.querySelectorAll('thead th')).map((th) => th.textContent.trim()));
  console.log('表格列：', JSON.stringify(cols));
  if (tables.length === 3 && cols[0].join('|') === '项目|值' &&
      cols[1].join('|') === '检查项|值|说明|检查结果' && cols[2].join('|') === '扩展项|OID|关键|内容') {
    ok('三张表列头正确');
  } else bad('表格列头异常');

  const rowCounts = new Set(tables.map((t) => t.querySelectorAll('tbody tr').length));
  console.log('各表行数：', [...rowCounts].join(','));

  // 2) 切到根证书节点（自签），验证结果应切换到该节点自己的数据
  await selectNode(doc, '根证书');
  await sleep(200);
  let boxAfterSwitch = doc.querySelector('[data-result="formatResult"]');
  if (boxAfterSwitch.textContent.includes('暂无格式验证结果')) ok('切换节点后不残留上一节点结果');
  else bad('切换节点后仍显示上一节点结果：' + boxAfterSwitch.textContent.slice(0, 60));

  await setCert(doc, CA_PEM);
  box = await verify(doc);
  const text2 = box.textContent;
  if (text2.includes('节点：根证书')) ok('根证书结果归属正确'); else bad('根证书结果归属错误');
  if (text2.includes('CipherBox 本地根 CA')) ok('根证书主题正确'); else bad('根证书主题缺失');
  if (text2.includes('签名验证通过（自签证书）')) ok('自签证书签名验证通过'); else bad('自签证书签名验证未通过');

  // 3) 切回终端证书，结果必须是终端证书自己的数据（不是根证书的）
  await selectNode(doc, '终端证书');
  await sleep(200);
  const back = doc.querySelector('[data-result="formatResult"]').textContent;
  if (back.includes('节点：终端证书') && back.includes('使用者CN=测试站点证书') &&
      !back.includes('使用者CN=CipherBox 本地根 CA')) {
    ok('切回终端证书后显示其自身结果');
  } else bad('切回后结果错乱：' + back.slice(0, 80));

  // 4) 清空结果容器不重复
  const boxes = doc.querySelectorAll('[data-result="formatResult"]');
  if (boxes.length === 1) ok('结果容器唯一（无重复渲染）'); else bad('结果容器重复：' + boxes.length);

  // 5) 证书链验证：批量导入 根 → 终端，应验证通过
  const bulk = doc.querySelector('[data-field="chainCerts"]');
  if (bulk) {
    bulk.value = CA_PEM.trim() + '\n' + LEAF_PEM.trim();
    bulk.dispatchEvent(new doc.defaultView.Event('input', { bubbles: true }));
    await sleep(150);
    doc.querySelector('[data-action="chainCheck"]').click();
    await waitFor(() => {
      const box = doc.querySelector('[data-result="chainResult"]');
      return box && box.textContent.trim().length > 0 && !box.textContent.includes('暂无证书链验证结果');
    }, 20000, '证书链验证结果');
    await sleep(300);
    const chain = doc.querySelector('[data-result="chainResult"]').textContent;
    if (/CipherBox 本地根 CA/.test(chain) && /测试站点证书/.test(chain)) ok('证书链结果含根证书与终端证书节点');
    else bad('证书链结果缺节点信息');
    if (!/undefined|NaN|\[object Object\]/.test(chain)) ok('证书链结果无异常标记'); else bad('证书链结果含异常标记');
    const chainTables = doc.querySelectorAll('[data-result="chainResult"] table');
    const chainCols = chainTables.length ? Array.from(chainTables[0].querySelectorAll('thead th')).map((t) => t.textContent.trim()) : [];
    if (chainCols.join('|') === '检查项|值|说明|检查结果') ok('证书链结果表列头正确');
    else bad('证书链结果表列头异常：' + chainCols.join('|'));
  }

  const pageErrors = errors.filter((e) => !e.includes('scrollTo'));
  if (pageErrors.length) bad('页面报错：' + JSON.stringify(pageErrors)); else ok('页面无报错');
  console.log(fails ? '\n❌ 失败项：' + fails : '\n✓ 证书格式检查页面全部通过');
  win.close();
  process.exit(fails ? 1 : 0);
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
