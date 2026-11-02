/* 量化评估（《商用密码应用安全性评估量化评估规则》2023 版） */
(function () {
  'use strict';
  const el = CB.el;

  let MODEL = null;          // 当前等级的指标模型
  let loading = false;

  const LAYER_COLOR = {
    physical: '#2d9cdb',
    network: '#6b6bff',
    device: '#f2994a',
    app: '#27ae60',
    manage_policy: '#8e44ad',
    manage_people: '#16a085',
    manage_build: '#d35400',
    manage_emergency: '#c0392b'
  };

  // 与后端一致的表2 / 表3 选项（模型加载前也要能渲染表单）
  const RA_OPTIONS = [
    ['0.2', '安全强度 < 80 比特（不匹配）'],
    ['0.5', '80 ≤ 安全强度 < 112 比特（一定程度上可保障）'],
    ['1', '安全强度 ≥ 112 比特（可较好保障）']
  ];
  const MODULE_LEVELS = [
    ['0', '未使用 / 不满足 GM/T 0115 5.5 其他要求'],
    ['1', '一级密码模块且满足其他要求'],
    ['2', '二级密码模块且满足其他要求'],
    ['3', '三级密码模块且满足其他要求']
  ];
  const TECH_STATUSES = [
    ['full', '符合'],
    ['partial_compliance', '部分符合·合规性问题'],
    ['partial_key', '部分符合·密钥管理问题'],
    ['partial_both', '部分符合·两者均有问题'],
    ['none', '不符合'],
    ['na', '不适用']
  ];
  const MANAGE_STATUSES = [
    ['full', '符合'],
    ['partial', '部分符合'],
    ['none', '不符合'],
    ['na', '不适用']
  ];

  function loadModel(ctx, grade, resetRows) {
    loading = true;
    return CB.api('/api/scoring/model', { grade: grade }).then((m) => {
      MODEL = m;
      loading = false;
      if (resetRows || !(ctx.val('rows') || []).length) {
        return CB.api('/api/scoring/default', { grade: grade }).then((def) => {
          ctx.set('rows', def.rows || []);
        });
      }
      return null;
    }).then(() => {
      ctx.refresh();
    }).catch((e) => {
      loading = false;
      CB.toast('指标模型加载失败：' + e.message, 'error');
      ctx.refresh();
    });
  }

  function allRows(ctx) {
    const list = ctx.val('rows');
    return Array.isArray(list) ? list : [];
  }

  function rowsOf(ctx, layerKey) {
    return allRows(ctx).filter((r) => r.layer === layerKey);
  }

  function targetsOf(ctx, layerKey) {
    const names = [];
    rowsOf(ctx, layerKey).forEach((r) => {
      if (names.indexOf(r.target) < 0) names.push(r.target);
    });
    return names;
  }

  function findRow(ctx, layerKey, unitKey, target) {
    return allRows(ctx).find((r) => r.layer === layerKey && r.unit === unitKey && r.target === target);
  }

  function setStatus(ctx, layerKey, unitKey, target, status) {
    const row = findRow(ctx, layerKey, unitKey, target);
    const list = allRows(ctx).slice();
    if (!row) {
      list.push({ layer: layerKey, unit: unitKey, target: target, status: status });
    } else {
      list.forEach((r) => {
        if (r.layer === layerKey && r.unit === unitKey && r.target === target) r.status = status;
      });
    }
    ctx.set('rows', list);
  }

  function setCompensate(ctx, layerKey, target, donor) {
    const list = allRows(ctx).slice();
    list.forEach((r) => {
      if (r.layer === layerKey && r.target === target) r.compensate = donor;
    });
    ctx.set('rows', list);
  }

  function addTarget(ctx, layer) {
    const rows = allRows(ctx).slice();
    const names = targetsOf(ctx, layer.key);
    let idx = names.length + 1;
    let name = layer.target + idx;
    while (names.indexOf(name) >= 0) { idx += 1; name = layer.target + idx; }
    layer.units.forEach((unit) => {
      rows.push({ layer: layer.key, unit: unit.key, target: name, status: 'full' });
    });
    ctx.set('rows', rows);
    ctx.refresh();
  }

  function removeTarget(ctx, layer, name) {
    ctx.set('rows', allRows(ctx).filter((r) => !(r.layer === layer.key && r.target === name)));
    ctx.refresh();
  }

  function cellSelect(value, options, onPick) {
    const sel = el('select', { class: 'input', style: 'min-width:132px' });
    options.forEach((pair) => {
      sel.appendChild(el('option', { value: pair[0], selected: pair[0] === value }, [pair[1]]));
    });
    sel.addEventListener('change', () => onPick(sel.value));
    return sel;
  }

  function techLayerCard(layer, ctx) {
    const wrap = el('div', { class: 'card mt12' });
    const targets = targetsOf(ctx, layer.key);
    wrap.appendChild(el('div', { class: 'input-bar' }, [
      el('span', { class: 'card-title' }, [layer.index + '. ' + layer.name]),
      el('span', { class: 'field-tip' }, [
        '　层面权重 ' + layer.weight + '　测评单元 ' + layer.units.length + ' 项　对象 ' + targets.length + ' 个'
      ]),
      el('button', {
        class: 'btn btn-mini', type: 'button', 'data-add': layer.key,
        onclick: () => addTarget(ctx, layer)
      }, ['添加' + layer.target])
    ]));

    const box = el('div', { style: 'overflow-x:auto' });
    const table = el('table', { class: 'grid mt12' });
    const head = [
      el('th', { style: 'white-space:nowrap' }, ['测评对象']),
      el('th', { style: 'white-space:nowrap' }, ['弥补来源'])
    ].concat(layer.units.map((u) => el('th', {
      style: 'white-space:nowrap', title: u.suggestion
    }, [u.name + '（' + u.weight + '）']))).concat([el('th', {}, ['操作'])]);
    table.appendChild(el('thead', {}, [el('tr', {}, head)]));

    const tbody = el('tbody', {});
    if (!targets.length) {
      tbody.appendChild(el('tr', {}, [
        el('td', { colspan: String(layer.units.length + 3), class: 'muted' }, ['暂无测评对象，点击右上角添加'])
      ]));
    }
    targets.forEach((name) => {
      const tr = el('tr', {});
      tr.appendChild(el('td', { style: 'white-space:nowrap;font-weight:600' }, [name]));

      const compTd = el('td', { style: 'white-space:nowrap' });
      const current = (rowsOf(ctx, layer.key).find((r) => r.target === name) || {}).compensate || '';
      const compSel = el('select', { class: 'input', style: 'min-width:104px' });
      compSel.appendChild(el('option', { value: '', selected: !current }, ['无']));
      targets.filter((n) => n !== name).forEach((n) => {
        compSel.appendChild(el('option', { value: n, selected: n === current }, [n]));
      });
      compSel.addEventListener('change', () => setCompensate(ctx, layer.key, name, compSel.value));
      compTd.appendChild(compSel);
      tr.appendChild(compTd);

      layer.units.forEach((unit) => {
        const row = findRow(ctx, layer.key, unit.key, name);
        const td = el('td', {});
        td.appendChild(cellSelect(row ? row.status : 'full', TECH_STATUSES, (value) => {
          setStatus(ctx, layer.key, unit.key, name, value);
        }));
        tr.appendChild(td);
      });

      const opTd = el('td', {});
      opTd.appendChild(el('button', {
        class: 'btn btn-mini', type: 'button', onclick: () => removeTarget(ctx, layer, name)
      }, ['删除']));
      tr.appendChild(opTd);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    box.appendChild(table);
    wrap.appendChild(box);
    return wrap;
  }

  function manageLayerCard(layer, ctx) {
    const wrap = el('div', { class: 'card mt12' });
    wrap.appendChild(el('div', { class: 'input-bar' }, [
      el('span', { class: 'card-title' }, [layer.index + '. ' + layer.name]),
      el('span', { class: 'field-tip' }, ['　层面权重 ' + layer.weight + '　测评单元 ' + layer.units.length + ' 项'])
    ]));
    const table = el('table', { class: 'grid mt12' });
    table.appendChild(el('thead', {}, [el('tr', {}, [
      el('th', {}, ['测评单元']), el('th', { style: 'white-space:nowrap' }, ['指标权重']),
      el('th', { style: 'white-space:nowrap' }, ['判定结果'])
    ])]));
    const tbody = el('tbody', {});
    layer.units.forEach((unit) => {
      const row = findRow(ctx, layer.key, unit.key, layer.target);
      const tr = el('tr', {});
      tr.appendChild(el('td', { title: unit.suggestion }, [unit.name]));
      tr.appendChild(el('td', { style: 'white-space:nowrap' }, [String(unit.weight)]));
      const td = el('td', {});
      td.appendChild(cellSelect(row ? row.status : 'full', MANAGE_STATUSES, (value) => {
        setStatus(ctx, layer.key, unit.key, layer.target, value);
      }));
      tr.appendChild(td);
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }

  function layerCards(data) {
    const grid = el('div', { class: 'quick-grid' });
    data.layers.forEach((l) => {
      const card = el('div', { class: 'card' });
      const color = LAYER_COLOR[l.key] || '#4f7cff';
      card.appendChild(el('div', { class: 'card-title' }, [l.name]));
      card.appendChild(el('div', { style: 'font-size:26px;font-weight:700;color:' + color }, [
        l.score === null ? '不适用' : l.score.toFixed(4)
      ]));
      const bar = el('div', { style: 'height:8px;background:#eee;border-radius:4px;margin:8px 0' });
      bar.appendChild(el('div', {
        style: 'height:8px;border-radius:4px;background:' + color + ';width:' +
          (l.score === null ? 0 : Math.round(Math.max(0, Math.min(1, l.score)) * 100)) + '%'
      }));
      card.appendChild(bar);
      card.appendChild(el('div', { class: 'field-tip' }, [
        '层面权重 ' + l.weight + '　适用单元 ' + l.units.length + ' 项'
      ]));
      grid.appendChild(card);
    });
    return grid;
  }

  CB.register({
    key: 'scoring',
    cat: 'ability',
    title: '量化评估',
    desc: '按《商用密码应用安全性评估量化评估规则》(2023版) 录入 8 个安全层面的测评结果，计算总分、结论与整改建议',
    help: [
      {
        title: '量化评估模型（2023 版）', items: [
          '技术要求：物理和环境安全 10、网络和通信安全 20、设备和计算安全 10、应用和数据安全 30，合计 70 分；',
          '管理要求：管理制度 8、人员管理 8、建设运行 8、应急处置 6，合计 30 分。',
          '总分 S = Σ(wi·Si)[1~4]/Σwi × 70 + Σ(wi·Si)[5~8]/Σwi × 30，四舍五入取 2 位小数；阈值 60 分。'
        ]
      },
      {
        title: '测评对象分值（表1）', items: [
          '符合 → 1；不符合 → 0；不适用 → 不参与计算。',
          '部分符合且算法/技术不合规 → 0.5Ra；密钥管理有问题 → 0.5Rk；两者都有问题 → 0.25RaRk。',
          'Ra（表2）：< 80 比特 0.2；80~112 比特 0.5；≥ 112 比特 1。',
          'Rk（表3）：第一/二级 1；第三级用一级密码模块且满足其他要求 1.2；第四级用二级密码模块且满足其他要求 1.5。'
        ]
      },
      {
        title: '计算规则', items: [
          '测评单元 Si,j = 单元内适用测评对象分值的算术平均值（4 位小数）。',
          '安全层面 Si = Σ(wi,j·Si,j)/Σwi,j（仅统计适用测评单元，4 位小数）。',
          '弥补：A 弥补 B 时，B 的分值修正为 MAX(0.5×PA, PB)。'
        ]
      },
      { title: '使用建议', items: ['先选密码应用级别（模型按等级自动裁剪），再逐个层面填写对象与判定；管理层面按测评单元直接判定。'] }
    ],
    state: {
      projectName: '某信息系统密码应用量化评估',
      grade: '3',
      ra: '1',
      moduleLevel: '1',
      rows: []
    },
    onMount: function (ctx) {
      loadModel(ctx, ctx.val('grade'), true);
    },
    fields: [
      { name: 'projectName', label: '项目名称', type: 'input', placeholder: '请输入评估项目名称' },
      {
        name: 'grade', label: '密码应用级别', type: 'radio',
        options: [['1', '第一级'], ['2', '第二级'], ['3', '第三级'], ['4', '第四级']],
        onChange: (value, ctx) => { loadModel(ctx, value, true); }
      },
      { name: 'ra', label: '密码算法/技术安全强度（Ra）', type: 'select', options: RA_OPTIONS },
      { name: 'moduleLevel', label: '使用的密码模块级别（推导 Rk）', type: 'select', options: MODULE_LEVELS },
      {
        name: 'rows', label: '测评对象与判定结果（可编辑表格）', type: 'custom', span: 2,
        render: (wrap, ctx) => {
          if (!MODEL) {
            wrap.appendChild(el('div', { class: 'field-tip' }, [
              loading ? '正在加载指标模型…' : '指标模型尚未加载，请切换一次密码应用级别后重试'
            ]));
            return;
          }
          wrap.appendChild(el('div', { class: 'field-tip' }, [
            MODEL.gradeLabel + '　技术要求 ' + MODEL.techWeightSum + ' 分 + 管理要求 ' +
            MODEL.manageWeightSum + ' 分　阈值 ' + MODEL.threshold + ' 分'
          ]));
          MODEL.layers.forEach((layer) => {
            wrap.appendChild(layer.kind === 'manage' ? manageLayerCard(layer, ctx) : techLayerCard(layer, ctx));
          });
        }
      }
    ],
    actions: [
      {
        name: 'evaluate', label: '计算总分', primary: true,
        run: async (ctx) => {
          let rows = allRows(ctx);
          if (!rows.length) {
            const def = await CB.api('/api/scoring/default', { grade: ctx.val('grade') });
            rows = def.rows || [];
            ctx.set('rows', rows);
            ctx.refresh();
          }
          const data = await CB.api('/api/scoring/evaluate', {
            projectName: ctx.val('projectName'),
            grade: ctx.val('grade'),
            ra: ctx.val('ra'),
            moduleLevel: ctx.val('moduleLevel'),
            rows: rows
          });
          ctx.setResult('summary', [
            '项目：' + (data.projectName || '未命名'),
            '级别：' + data.gradeLabel + '　Ra = ' + data.ra + '　Rk = ' + data.rk,
            '总分：' + data.total + ' 分（满分 100，阈值 ' + data.threshold + '）',
            '结论：' + data.conclusion + '（' + data.gradeReason + '）',
            '技术要求得分率：' + (data.techScore === null ? '-' : data.techScore + '%') +
              '　管理要求得分率：' + (data.manageScore === null ? '-' : data.manageScore + '%'),
            '层面得分：' + data.layers.map((l) => l.name + ' ' + (l.score === null ? '不适用' : l.score)).join('；'),
            '弥补记录：' + data.compensations.length + ' 条　整改建议：' + data.suggestions.length + ' 条'
          ].join('\n'));
          ctx.setResult('report', data);
          CB.toast('评估完成：' + data.total + ' 分（' + data.conclusion + '）',
            data.conclusion === '通过' ? 'success' : 'warn');
        }
      },
      {
        name: 'reset', label: '恢复默认判定',
        run: async (ctx) => {
          const def = await CB.api('/api/scoring/default', { grade: ctx.val('grade') });
          ctx.set('rows', def.rows || []);
          ctx.refresh();
          ctx.setResult('summary', '已恢复默认测评对象与判定结果，可重新计算。');
          CB.toast('已恢复默认', 'success');
        }
      }
    ],
    results: [
      { name: 'summary', label: '评估结论', type: 'textarea', rows: 8 },
      {
        name: 'report', label: '层面得分与明细', type: 'custom',
        render: (box, ctx) => {
          box.setAttribute('data-result', 'report');
          const paint = (data) => {
            box.innerHTML = '';
            if (!data) {
              box.appendChild(el('div', { class: 'muted' }, ['填写判定后点击“计算总分”']));
              return;
            }
            const color = data.total >= data.threshold ? '#27ae60' : '#eb5757';
            const banner = el('div', { class: 'card', style: 'border-left:4px solid ' + color });
            banner.appendChild(el('div', { style: 'font-size:30px;font-weight:700' }, [data.total + ' 分']));
            const line = el('div', { class: 'input-bar' }, [
              el('span', { class: 'field-label' }, ['结论：' + data.conclusion])
            ]);
            line.appendChild(CB.badge(data.conclusion === '通过', '通过', data.conclusion));
            line.appendChild(el('span', { class: 'field-tip' }, [
              '　' + data.gradeReason + '　' + data.gradeLabel + '　Ra=' + data.ra + '　Rk=' + data.rk
            ]));
            banner.appendChild(line);
            banner.appendChild(el('div', { class: 'field-tip' }, [
              '技术要求（权重 ' + data.techWeight + '）得分率 ' +
              (data.techScore === null ? '-' : data.techScore + '%') +
              '　管理要求（权重 ' + data.manageWeight + '）得分率 ' +
              (data.manageScore === null ? '-' : data.manageScore + '%')
            ]));
            box.appendChild(banner);
            box.appendChild(layerCards(data));

            if (data.compensations && data.compensations.length) {
              box.appendChild(el('div', { class: 'card-title mt12' }, [
                '分值弥补记录（' + data.compensations.length + ' 条）'
              ]));
              data.compensations.forEach((c) => {
                box.appendChild(el('div', { class: 'log-desc' }, [
                  c.layer + ' / ' + c.unit + '：' + c.target + ' 由 ' + c.donor + ' 弥补，' +
                  (c.before === null ? '不适用' : c.before) + ' → ' + c.after
                ]));
              });
            }

            box.appendChild(el('div', { class: 'card-title mt12' }, ['测评明细（' + data.details.length + ' 条）']));
            const tableBox = el('div', { style: 'overflow-x:auto' });
            tableBox.appendChild(CB.table([
              { key: 'layer', label: '安全层面' },
              { key: 'unit', label: '测评单元' },
              { key: 'object', label: '测评对象' },
              { key: 'status', label: '判定' },
              { key: 'score', label: '分值' },
              { key: 'weight', label: '权重' },
              { key: 'compensatedBy', label: '弥补来源' }
            ], data.details.map((d) => Object.assign({}, d, {
              score: d.score === null ? '不适用' : String(d.score),
              weight: String(d.weight),
              compensatedBy: d.compensatedBy || '-'
            }))));
            box.appendChild(tableBox);

            box.appendChild(el('div', { class: 'card-title mt12' }, ['整改建议（' + data.suggestions.length + ' 条）']));
            if (!data.suggestions.length) {
              box.appendChild(el('div', { class: 'field-tip' }, ['所有指标均符合要求，无需整改。']));
            } else {
              const list = el('div', {});
              data.suggestions.forEach((s, i) => {
                list.appendChild(el('div', { class: 'log-item' }, [
                  el('div', { class: 'log-title' }, [
                    '[' + (i + 1) + '][' + s.level + '风险] ' + s.layer + ' / ' + s.item +
                    '（' + s.object + '，' + s.status + '）'
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
      evaluate: { projectName: '某信息系统密码应用量化评估', grade: '3', ra: '1', moduleLevel: '1' },
      reset: { projectName: '某信息系统密码应用量化评估', grade: '3', ra: '1', moduleLevel: '1' }
    }
  });
})();
