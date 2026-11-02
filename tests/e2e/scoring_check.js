/* 量化评估模块专项检查：模型是否自动加载、表格是否渲染、切换级别是否裁剪、计算是否出结果 */
const { openPage, waitFor, sleep } = require('./harness');

(async () => {
  const { win, doc, errors } = await openPage('scoring');
  const body = () => doc.body.textContent;

  await waitFor(() => body().includes('物理和环境安全'), 10000, '指标模型渲染');
  const hasPending = body().includes('指标模型尚未加载');
  console.log('模型自动加载:', hasPending ? '失败（仍提示尚未加载）' : '成功');
  console.log('渲染层面数:', (body().match(/政策|物理和环境安全|网络和通信安全|设备和计算安全|应用和数据安全|管理制度|人员管理|建设运行|应急处置/g) || []).length);
  console.log('含管理层面:', body().includes('管理制度') && body().includes('应急处置'));
  console.log('含表格下拉:', doc.querySelectorAll('select').length + ' 个 select');

  // 切换为第二级：视频记录/安全接入认证等三级指标应被裁剪
  const gradeBtn = doc.querySelector('[data-field="grade"] button[data-value="2"]');
  if (gradeBtn) {
    gradeBtn.click();
    await sleep(600);
    const t = body();
    console.log('二级裁剪(视频记录应消失):', t.includes('视频记录数据存储完整性') ? '失败' : '成功');
    console.log('二级裁剪(身份鉴别仍在):', t.includes('身份鉴别') ? '成功' : '失败');
    gradeBtn.parentElement.querySelector('button[data-value="3"]').click();
    await sleep(600);
  }

  // 计算总分
  const btn = doc.querySelector('[data-action="evaluate"]');
  btn.click();
  await waitFor(() => {
    const node = doc.querySelector('[data-result="summary"]');
    return node && node.value && node.value.includes('总分');
  }, 15000, '评估结论');
  const summary = doc.querySelector('[data-result="summary"]').value;
  const report = doc.querySelector('[data-result="report"]').textContent;
  console.log('--- 结论 ---');
  console.log(summary);
  console.log('报告含结论/明细:', /结论|测评明细/.test(report) ? '成功' : '失败');
  console.log('页面错误:', JSON.stringify(errors));
  win.close();
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
