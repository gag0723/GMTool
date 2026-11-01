/* 量化评估（GB/T 39786-2021 四个技术层面） */
(function () {
  'use strict';
  const el = CB.el;

  let MODEL = null;          // 当前等级的指标模型
  let loading = false;

  const LAYER_COLOR = {
    physical: '#2d9cdb',
    network: '#6b6bff',
    device: '#f2994a',
    app: '#27ae60'
  };

  function loadModel(ctx, grade) {
    loading = true;
    CB.api('/api/scoring/model', { grade: grade }).then((m) => {
      MODEL = m;
      loading = false;
      if (!ctx.val('objects') || !ctx.val('objects').length) {
        return CB.api('/api/scoring/default', { grade: grade });
      }
      return null;
    }).then((def) => {
      if (def && def.objects) ctx.set('objects', def.objects);
      ctx.refresh();
    }).catch((e) => {
      loading = false;
      CB.toast('指标模型加载失败：' + e.message, 'error');
    });
  }

  function objectOf(ctx, layerKey) {
    const list = ctx.val('objects') || [];
    return list.filter((o) => o.layer === layerKey);
  }

  function addObject(ctx, layer) {
    const list = (ctx.val('objects') || []).slice();
    const count = list.filter((o) => o.layer === layer.key).length + 1;
    const scores = {};
    layer.items.forEach((it) => { scores[it.key] = 3; });
    list.push({ layer: layer.key, name: layer.objectLabel + count, scores: scores });
    ctx.set('objects', list);
    ctx.refresh();
  }

  function removeObject(ctx, obj) {
    const list = (ctx.val('objects') || []).filter((o) => o !== obj);
    ctx.set('objects', list);
    ctx.refresh();
  }

  function layerTable(layer, ctx) {
    const wrap = el('div', { class: 'card mt12' });
    const head = el('div', { class: 'input-bar' }, [
      el('span', { class: 'card-title' }, [layer.name]),
      el('span', { class: 'field-tip' }, ['　层面权重 25%　指标 ' + layer.items.length + ' 项']),
      el('button', {
        class: 'btn btn-mini', type: 'button', 'data-add': layer.key,
        onclick: () => addObject(ctx, layer)
      }, ['添加' + layer.objectLabel])
    ]);
    wrap.appendChild(head);

    const table = el('table', { class: 'grid mt12' });
    const headCells = [el('th', {}, ['名称'])];
    layer.items.forEach((it) => headCells.push(el('th', { title: it.desc }, [it.name + '（' + it.weight + '）'])));
    headCells.push(el('th', {}, ['操作']));
    table.appendChild(el('thead', {}, [el('tr', {}, headCells)]));

    const tbody = el('tbody', {});
    const objs = objectOf(ctx, layer.key);
    if (!objs.length) {
      tbody.appendChild(el('tr', {}, [
        el('td', { colspan: String(layer.items.length + 2), class: 'muted' }, ['暂无对象，请点击右上角添加'])
      ]));
    }
    objs.forEach((obj) => {
      const tr = el('tr', {});
      const nameTd = el('td', {});
      const nameInput = el('input', { class: 'input', value: obj.name || '', placeholder: layer.objectPlaceholder });
      nameInput.addEventListener('input', () => { obj.name = nameInput.value; });
      nameTd.appendChild(nameInput);
      tr.appendChild(nameTd);
      layer.items.forEach((it) => {
        const td = el('td', {});
        const sel = el('select', { class: 'input', 'data-score': layer.key + ':' + it.key });
        [['NA', '不适用'], ['0', '0 分'], ['1', '1 分'], ['2', '2 分'], ['3', '3 分']].forEach((pair) => {
          const cur = obj.scores ? obj.scores[it.key] : null;
          const selected = (cur === null || cur === undefined) ? pair[0] === 'NA' : String(cur) === pair[0];
          sel.appendChild(el('option', { value: pair[0], selected: selected }, [pair[1]]));
        });
        sel.addEventListener('change', () => {
          if (!obj.scores) obj.scores = {};
          obj.scores[it.key] = sel.value === 'NA' ? null : Number(sel.value);
        });
        td.appendChild(sel);
        tr.appendChild(td);
      });
      const opTd = el('td', {});
      opTd.appendChild(el('button', {
        class: 'btn btn-mini', type: 'button', onclick: () => removeObject(ctx, obj)
      }, ['删除']));
      tr.appendChild(opTd);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function scoreCards(data) {
    const grid = el('div', { class: 'quick-grid' });
    data.layers.forEach((l) => {
      const card = el('div', { class: 'card' });
      const color = LAYER_COLOR[l.key] || '#4f7cff';
      const score = l.score === null ? '不适用' : l.score.toFixed(2);
      card.appendChild(el('div', { class: 'card-title' }, [l.name]));
      card.appendChild(el('div', { style: 'font-size:28px;font-weight:700;color:' + color }, [String(score)]));
      const bar = el('div', { style: 'height:8px;background:#eee;border-radius:4px;margin:8px 0' });
      bar.appendChild(el('div', {
        style: 'height:8px;border-radius:4px;background:' + color + ';width:' +
          (l.ratio === null ? 0 : Math.round(l.ratio * 100)) + '%'
      }));
      card.appendChild(bar);
      card.appendChild(el('div', { class: 'field-tip' }, [
        '权重 25%　得分率 ' + (l.ratio === null ? '-' : (l.ratio * 100).toFixed(2) + '%') +
        '　对象 ' + l.objectCount + ' 个　适用指标 ' + l.applicableItems + '/' + l.itemCount
      ]));
      grid.appendChild(card);
    });
    return grid;
  }

  CB.register({
    key: 'scoring',
    cat: 'ability',
    title: '量化评估',
    desc: '按 GB/T 39786-2021 四个技术层面（物理、网络、设备、应用）录入测评对象分值，计算总分、等级与整改建议',
    help: [
      {
        title: '评分模型', items: [
          '四个技术层面各占 25% 权重；层面内部按指标权重（1.0 / 0.7）加权。',
          '单元分值 = 该指标下所有适用对象分值的平均值；层面得分率 = Σ(单元分值 ÷ 3 × 权重) ÷ Σ权重。',
          '总分 = Σ(层面得分率 × 25%)，满分 100 分；全部指标不适用的层面不参与计算，权重重新归一。'
        ]
      },
      {
        title: '等级判定', items: [
          '总分 ≥ 90 分：符合；70 ≤ 总分 < 90：基本符合；总分 < 70：不符合。',
          '任一层面得分率为 0（该层面所有指标均为 0 分）时直接判定不符合。'
        ]
      },
      { title: '使用建议', items: ['可为每个层面添加多个机房 / 通道 / 设备 / 应用对象，逐个对象填写分值或标记“不适用”。'] }
    ],
    state: {
      projectName: '某信息系统密码应用量化评估',
      grade: 3,
      objects: []
    },
    fields: [
      { name: 'projectName', label: '项目名称', type: 'input', placeholder: '请输入评估项目名称' },
      {
        name: 'grade', label: '系统等级', type: 'radio',
        options: [['2', '二级'], ['3', '三级'], ['4', '四级']],
        onChange: (value, ctx) => { loadModel(ctx, value); }
      },
      {
        name: 'objects', label: '测评对象与分值（可编辑表格）', type: 'custom', span: 2,
        render: (wrap, ctx) => {
          if (!MODEL) {
            wrap.appendChild(el('div', { class: 'field-tip' }, [loading ? '正在加载指标模型…' : '指标模型尚未加载']));
            return;
          }
          wrap.appendChild(el('div', { class: 'field-tip' }, [
            '当前等级：' + MODEL.gradeLabel + '　指标合计 ' +
            MODEL.layers.reduce((n, l) => n + l.items.length, 0) + ' 项　分值为 0~3 分或“不适用”'
          ]));
          MODEL.layers.forEach((layer) => wrap.appendChild(layerTable(layer, ctx)));
        }
      }
    ],
    actions: [
      {
        name: 'evaluate', label: '计算总分', primary: true,
        run: async (ctx) => {
          let objects = ctx.val('objects') || [];
          if (!objects.length) {
            const def = await CB.api('/api/scoring/default', { grade: ctx.val('grade') });
            objects = def.objects;
            ctx.set('objects', objects);
            ctx.refresh();
          }
          const data = await CB.api('/api/scoring/evaluate', {
            projectName: ctx.val('projectName'),
            grade: ctx.val('grade'),
            objects: objects
          });
          ctx.setResult('summary', [
            '项目：' + (ctx.val('projectName') || '未命名'),
            '总分：' + data.total + ' 分（满分 ' + data.maxScore + '）',
            '等级：' + data.grade + '（' + data.gradeReason + '）',
            '层面得分：' + data.layers.map((l) => l.name + ' ' + (l.score === null ? '不适用' : l.score)).join('；'),
            '整改建议：' + data.suggestions.length + ' 条'
          ].join('\n'));
          ctx.setResult('report', data);
          CB.toast('评估完成：' + data.grade, data.grade === '符合' ? 'success' : 'warn');
        }
      },
      {
        name: 'reset', label: '恢复默认分值',
        run: async (ctx) => {
          const def = await CB.api('/api/scoring/default', { grade: ctx.val('grade') });
          ctx.set('objects', def.objects);
          ctx.refresh();
          ctx.setResult('summary', '已恢复默认测评对象与分值，可重新计算。');
          CB.toast('已恢复默认', 'success');
        }
      }
    ],
    results: [
      { name: 'summary', label: '评估结论', type: 'textarea', rows: 6 },
      {
        name: 'report', label: '层面得分与明细', type: 'custom',
        render: (box, ctx) => {
          box.setAttribute('data-result', 'report');
          const paint = (data) => {
            box.innerHTML = '';
            if (!data) {
              box.appendChild(el('div', { class: 'muted' }, ['填写分值后点击“计算总分”']));
              return;
            }
            const color = data.total >= 90 ? '#27ae60' : (data.total >= 70 ? '#f2994a' : '#eb5757');
            const banner = el('div', { class: 'card', style: 'border-left:4px solid ' + color });
            banner.appendChild(el('div', { style: 'font-size:30px;font-weight:700' }, [data.total + ' 分']));
            const line = el('div', { class: 'input-bar' }, [el('span', { class: 'field-label' }, ['结论：' + data.grade])]);
            line.appendChild(CB.badge(data.grade === '符合', '符合', data.grade));
            line.appendChild(el('span', { class: 'field-tip' }, ['　' + data.gradeReason + '　' + data.standard]));
            banner.appendChild(line);
            box.appendChild(banner);
            box.appendChild(scoreCards(data));

            box.appendChild(el('div', { class: 'card-title mt12' }, ['得分明细（共 ' + data.details.length + ' 条）']));
            box.appendChild(CB.table([
              { key: 'layer', label: '层面' },
              { key: 'item', label: '测评指标' },
              { key: 'object', label: '测评对象' },
              { key: 'score', label: '对象分值' },
              { key: 'label', label: '评价' },
              { key: 'weight', label: '指标权重' }
            ], data.details.map((d) => Object.assign({}, d, { score: String(d.score) }))));

            box.appendChild(el('div', { class: 'card-title mt12' }, ['整改建议（' + data.suggestions.length + ' 条）']));
            if (!data.suggestions.length) {
              box.appendChild(el('div', { class: 'field-tip' }, ['所有指标均为满分，无需整改。']));
            } else {
              const list = el('div', {});
              data.suggestions.forEach((s, i) => {
                list.appendChild(el('div', { class: 'log-item' }, [
                  el('div', { class: 'log-title' }, [
                    '[' + (i + 1) + '][' + s.level + '风险] ' + s.layer + ' / ' + s.item +
                    '（' + s.object + '，' + s.score + ' 分）'
                  ]),
                  el('div', { class: 'log-desc' }, [s.text])
                ]));
              });
              box.appendChild(list);
            }
          };
          ctx.onResult = (name, value) => { if (name === 'report') paint(value); };
          paint(ctx.result('report'));
        }
      }
    ],
    samples: {
      evaluate: { projectName: '某信息系统密码应用量化评估', grade: 3 },
      reset: { projectName: '某信息系统密码应用量化评估', grade: 3 }
    }
  });
})();
