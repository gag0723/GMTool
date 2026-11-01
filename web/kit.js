/* 密码工具百宝箱 · 本地版 —— 前端框架
 * 纯原生 JS，无构建步骤、无外部依赖。所有工具模块通过 CB.register 注册。
 */
(function () {
  'use strict';

  const CB = (window.CB = window.CB || {});
  CB.modules = {};
  CB.order = [];

  const FORMAT_LABEL = {
    TEXT: '字符串', HEX: '十六进制', BASE64: 'Base64', BIN: '二进制'
  };

  /* ---------------- 基础工具 ---------------- */
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') node.className = v;
        else if (k === 'html') node.innerHTML = v;
        else if (k === 'text') node.textContent = v;
        else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v === true) node.setAttribute(k, '');
        else node.setAttribute(k, v);
      }
    }
    (children || []).forEach((c) => {
      if (c === null || c === undefined || c === false) return;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return node;
  }

  function toast(msg, type) {
    const box = document.getElementById('toast-box');
    if (!box) return;
    const item = el('div', { class: 'toast toast-' + (type || 'info') }, [msg]);
    box.appendChild(item);
    setTimeout(() => item.classList.add('toast-out'), 2200);
    setTimeout(() => item.remove(), 2600);
  }

  async function copyText(text) {
    if (!text) { toast('没有可复制的内容', 'warn'); return false; }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = el('textarea', { style: 'position:fixed;left:-9999px' });
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
      }
      toast('复制成功', 'success');
      return true;
    } catch (e) {
      toast('复制失败，请手动复制', 'error');
      return false;
    }
  }

  async function api(path, payload) {
    const resp = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {})
    });
    if (!resp.ok) throw new Error('请求失败：HTTP ' + resp.status);
    const json = await resp.json();
    if (json.code !== 0) throw new Error(json.msg || '计算失败');
    return json.data;
  }

  function fmtSelect(state, formatField, formats, onChange) {
    const sel = el('select', { class: 'fmt-select', 'data-format': formatField });
    formats.forEach(([v, l]) => sel.appendChild(el('option', { value: v, selected: state[formatField] === v }, [l || FORMAT_LABEL[v] || v])));
    sel.addEventListener('change', () => {
      state[formatField] = sel.value;
      if (onChange) onChange(sel.value);
    });
    return sel;
  }

  /* ---------------- 字段渲染 ---------------- */
  function renderField(f, ctx) {
    const state = ctx.state;
    if (f.show && !f.show(state)) return null;
    const wrap = el('div', { class: 'field span-' + (f.span || 1) + (f.type === 'textarea' ? ' field-wide' : '') });

    if (f.type === 'custom') {
      f.render(wrap, ctx);
      return wrap;
    }

    const label = el('div', { class: 'field-label' }, [
      f.label,
      f.hint ? el('span', { class: 'field-hint', title: f.hint }, ['?']) : null
    ]);
    wrap.appendChild(label);

    if (f.type === 'radio') {
      const group = el('div', { class: 'radio-group', 'data-field': f.name });
      (f.options || []).forEach(([v, l]) => {
        const btn = el('button', {
          type: 'button',
          class: 'radio-btn' + (String(state[f.name]) === String(v) ? ' active' : ''),
          'data-value': v
        }, [l]);
        btn.addEventListener('click', () => {
          state[f.name] = v;
          if (f.onChange) f.onChange(v, ctx);
          ctx.refresh();
        });
        group.appendChild(btn);
      });
      wrap.appendChild(group);
    } else if (f.type === 'select') {
      const sel = el('select', { class: 'input', 'data-field': f.name });
      (f.options || []).forEach(([v, l]) => sel.appendChild(el('option', { value: v, selected: String(state[f.name]) === String(v) }, [l])));
      sel.addEventListener('change', () => {
        state[f.name] = sel.value;
        if (f.onChange) f.onChange(sel.value, ctx);
        ctx.refresh();
      });
      wrap.appendChild(sel);
    } else if (f.type === 'textarea') {
      const bar = el('div', { class: 'input-bar' });
      if (f.formats) bar.appendChild(fmtSelect(state, f.formatField, f.formats, () => ctx.refresh()));
      const ta = el('textarea', {
        class: 'textarea', rows: f.rows || 4, placeholder: f.placeholder || '',
        'data-field': f.name, spellcheck: 'false'
      });
      ta.value = state[f.name] || '';
      ta.addEventListener('input', () => { state[f.name] = ta.value; });
      wrap.appendChild(bar);
      wrap.appendChild(ta);
    } else if (f.type === 'number') {
      const inp = el('input', { class: 'input', type: 'number', 'data-field': f.name, min: f.min, max: f.max, step: f.step || 1 });
      inp.value = state[f.name] === undefined ? '' : state[f.name];
      inp.addEventListener('input', () => { state[f.name] = inp.value === '' ? '' : Number(inp.value); });
      wrap.appendChild(inp);
    } else if (f.type === 'checkbox') {
      const lab = el('label', { class: 'checkbox' });
      const inp = el('input', { type: 'checkbox', 'data-field': f.name });
      inp.checked = !!state[f.name];
      inp.addEventListener('change', () => {
        state[f.name] = inp.checked;
        if (f.onChange) f.onChange(inp.checked, ctx);
        ctx.refresh();
      });
      lab.appendChild(inp);
      lab.appendChild(el('span', {}, [f.text || f.label]));
      wrap.appendChild(lab);
    } else if (f.type === 'file') {
      const box = el('div', { class: 'file-box', 'data-field': f.name });
      const input = el('input', { type: 'file', accept: f.accept || '', style: 'display:none' });
      const nameEl = el('span', { class: 'file-name' }, [ctx.files[f.name] ? ctx.files[f.name].name : (f.placeholder || '点击或拖拽文件到此区域上传')]);
      box.appendChild(el('button', { type: 'button', class: 'btn btn-ghost', onclick: () => input.click() }, ['选择文件']));
      box.appendChild(nameEl);
      box.appendChild(input);
      input.addEventListener('change', async () => {
        const file = input.files && input.files[0];
        if (!file) return;
        const buf = await file.arrayBuffer();
        ctx.files[f.name] = {
          name: file.name,
          bytes: new Uint8Array(buf),
          b64: btoa(String.fromCharCode.apply(null, new Uint8Array(buf))),
          text: new TextDecoder('utf-8', { fatal: false }).decode(buf)
        };
        nameEl.textContent = file.name;
        if (f.onFile) await f.onFile(ctx.files[f.name], ctx);
      });
      wrap.appendChild(box);
    } else if (f.type === 'key') {
      const bar = el('div', { class: 'input-bar' });
      if (f.formats) bar.appendChild(fmtSelect(state, f.formatField, f.formats, () => ctx.refresh()));
      if (f.random) {
        bar.appendChild(el('button', {
          type: 'button', class: 'btn btn-mini', 'data-gen': f.name,
          onclick: () => {
            const n = typeof f.random === 'function' ? f.random(state) : f.random;
            const bytes = new Uint8Array(n);
            crypto.getRandomValues(bytes);
            const fmt = state[f.formatField] || 'HEX';
            state[f.name] = fmt === 'BASE64' ? btoa(String.fromCharCode.apply(null, bytes)) : Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
            ctx.refresh();
          }
        }, ['生成密钥']));
      }
      const inp = el('input', { class: 'input', 'data-field': f.name, placeholder: f.placeholder || '' });
      inp.value = state[f.name] || '';
      inp.addEventListener('input', () => { state[f.name] = inp.value; });
      wrap.appendChild(bar);
      wrap.appendChild(inp);
    } else {
      const inp = el('input', { class: 'input', 'data-field': f.name, placeholder: f.placeholder || '' });
      inp.value = state[f.name] === undefined ? '' : state[f.name];
      inp.addEventListener('input', () => { state[f.name] = inp.value; });
      wrap.appendChild(inp);
    }
    if (f.tip) wrap.appendChild(el('div', { class: 'field-tip' }, [f.tip]));
    return wrap;
  }

  /* ---------------- 结果渲染 ---------------- */
  function renderResult(r, ctx) {
    const box = el('div', { class: 'result-block', 'data-result-box': r.name });
    if (r.type === 'custom') {
      r.render(box, ctx);
      return box;
    }
    const head = el('div', { class: 'result-head' }, [el('span', {}, [r.label || ''])]);
    if (r.type === 'textarea' && r.copy !== false) {
      head.appendChild(el('button', { type: 'button', class: 'btn btn-mini', onclick: () => copyText(ctx.results[r.name] || '') }, ['复制']));
    }
    box.appendChild(head);
    if (r.type === 'textarea') {
      if (r.formats) box.appendChild(fmtSelect(ctx.resultFormats, r.formatField, r.formats, () => ctx.refresh()));
      const ta = el('textarea', { class: 'textarea result-text', rows: r.rows || 5, readonly: true, 'data-result': r.name });
      ta.value = ctx.results[r.name] || '';
      box.appendChild(ta);
    } else if (r.type === 'json') {
      const pre = el('pre', { class: 'json-view', 'data-result': r.name }, [ctx.results[r.name] || '']);
      box.appendChild(pre);
    } else if (r.type === 'html') {
      const div = el('div', { class: 'html-result', 'data-result': r.name });
      div.innerHTML = ctx.results[r.name] || '';
      box.appendChild(div);
    } else {
      const div = el('div', { class: 'text-result', 'data-result': r.name }, [ctx.results[r.name] || '']);
      box.appendChild(div);
    }
    return box;
  }

  /* ---------------- 页面渲染 ---------------- */
  function renderModule(mod, root) {
    root.innerHTML = '';
    const state = mod.state || {};
    const results = {};
    const files = {};
    const resultFormats = {};

    const ctx = {
      mod, state, results, files, resultFormats,
      val: (n) => state[n],
      set: (n, v) => { state[n] = v; },
      result: (n) => results[n],
      setResult: (n, v) => {
        results[n] = v;
        const node = root.querySelector('[data-result="' + n + '"]');
        if (node) {
          if (node.tagName === 'TEXTAREA') node.value = v || '';
          else node.textContent = v || '';
        }
        if (ctx.onResult) ctx.onResult(n, v);
      },
      refresh: () => scheduleRefresh(),
      api,
      toast,
      el,
      copyText,
      file: (n) => files[n],
      payload: (extra) => Object.assign({}, state, extra || {})
    };
    CB.current = ctx;

    const page = el('div', { class: 'page', 'data-module': mod.key });
    const head = el('div', { class: 'page-head' }, [
      el('div', {}, [
        el('h1', { class: 'page-title' }, [mod.title]),
        mod.desc ? el('p', { class: 'page-desc' }, [mod.desc]) : null
      ]),
      mod.help ? el('button', { type: 'button', class: 'btn btn-ghost', 'data-help': '1', onclick: () => showHelp(mod) }, ['注意事项']) : null
    ]);
    page.appendChild(head);

    const body = el('div', { class: 'page-body' });
    page.appendChild(body);
    root.appendChild(page);

    if (mod.render) {
      mod.render(body, ctx);
      return;
    }

    const formCard = el('div', { class: 'card' });
    const form = el('div', { class: 'form-grid' });
    formCard.appendChild(form);
    body.appendChild(formCard);

    const actionsBar = el('div', { class: 'actions-bar' });
    (mod.actions || []).forEach((a) => {
      const btn = el('button', {
        type: 'button',
        class: 'btn ' + (a.primary ? 'btn-primary' : 'btn-default'),
        'data-action': a.name
      }, [a.label]);
      btn.addEventListener('click', async () => {
        if (btn.disabled) return;
        btn.disabled = true;
        btn.classList.add('loading');
        try {
          if (mod.validate) mod.validate(ctx, a);
          await a.run(ctx);
        } catch (e) {
          toast((e && e.message) || '计算失败', 'error');
        } finally {
          btn.disabled = false;
          btn.classList.remove('loading');
        }
      });
      actionsBar.appendChild(btn);
    });
    if (mod.cleanup !== false) {
      actionsBar.appendChild(el('button', { type: 'button', class: 'btn btn-ghost', 'data-action': 'clean', onclick: () => {
        ['message', 'cipherData', 'cipher', 'data', 'key', 'iv', 'tweak', 'input'].forEach((n) => {
          if (typeof state[n] === 'string') state[n] = state[n].replace(/\s+/g, '');
        });
        toast('空格和换行已清理', 'success');
        scheduleRefresh();
      } }, ['清理空格和换行']));
      actionsBar.appendChild(el('button', { type: 'button', class: 'btn btn-ghost', 'data-action': 'clear', onclick: () => {
        if (mod.onClear) mod.onClear(ctx); else {
          Object.keys(state).forEach((k) => {
            if (mod.formats && mod.formats.includes(k)) return;
            state[k] = typeof state[k] === 'boolean' ? false : '';
          });
          if (mod.defaults) Object.assign(state, JSON.parse(JSON.stringify(mod.defaults)));
        }
        Object.keys(results).forEach((k) => { results[k] = ''; });
        toast('数据已清空', 'success');
        scheduleRefresh();
      } }, ['清空']));
    }
    formCard.appendChild(actionsBar);

    if (mod.results) {
      const resCard = el('div', { class: 'card results-card' });
      const resGrid = el('div', { class: 'result-grid' });
      mod.results.forEach((r) => resGrid.appendChild(renderResult(r, ctx)));
      resCard.appendChild(resGrid);
      body.appendChild(resCard);
    }
    if (mod.panels) {
      mod.panels.forEach((p) => {
        const c = el('div', { class: 'card' });
        if (p.title) c.appendChild(el('div', { class: 'card-title' }, [p.title]));
        p.render(c, ctx);
        body.appendChild(c);
      });
    }

    let timer = null;
    function scheduleRefresh() {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        const active = document.activeElement;
        const focusField = active && active.getAttribute ? active.getAttribute('data-field') : null;
        const selStart = active && active.selectionStart;
        form.innerHTML = '';
        (mod.fields || []).forEach((f) => {
          const node = renderField(f, ctx);
          if (node) form.appendChild(node);
        });
        if (focusField) {
          const n = form.querySelector('[data-field="' + focusField + '"]');
          if (n) { n.focus(); try { n.setSelectionRange(selStart, selStart); } catch (e) {} }
        }
      }, 0);
    }

    form.innerHTML = '';
    (mod.fields || []).forEach((f) => {
      const node = renderField(f, ctx);
      if (node) form.appendChild(node);
    });
    ctx.refresh = scheduleRefresh;
    if (mod.onMount) mod.onMount(ctx);
  }

  function showHelp(mod) {
    const mask = el('div', { class: 'drawer-mask', onclick: (e) => { if (e.target === mask) mask.remove(); } });
    const drawer = el('div', { class: 'drawer' });
    drawer.appendChild(el('div', { class: 'drawer-head' }, [
      el('h3', {}, ['注意事项']),
      el('button', { class: 'btn btn-mini', onclick: () => mask.remove() }, ['关闭'])
    ]));
    const content = el('div', { class: 'drawer-body' });
    (mod.help || []).forEach((sec) => {
      content.appendChild(el('h4', {}, [sec.title]));
      (sec.items || []).forEach((t) => content.appendChild(el('p', {}, [t])));
    });
    drawer.appendChild(content);
    mask.appendChild(drawer);
    document.body.appendChild(mask);
  }

  CB.register = function (mod) {
    if (!mod || !mod.key) throw new Error('模块缺少 key');
    CB.modules[mod.key] = mod;
    if (mod.cat) {
      const cat = CB.categories.find((c) => c.id === mod.cat);
      if (cat) cat.modules.push(mod.key);
    }
    CB.order.push(mod.key);
  };
  CB.categories = [
    { id: 'sym', title: '对称密码校验', modules: [] },
    { id: 'hash', title: '哈希算法校验', modules: [] },
    { id: 'asym', title: '非对称算法校验', modules: [] },
    { id: 'cert', title: '数字证书校验', modules: [] },
    { id: 'proto', title: '协议分析工具', modules: [] },
    { id: 'top', title: '独立工具', modules: [] },
    { id: 'ability', title: '能力验证必备', modules: [] },
    { id: 'other', title: '其他常用工具', modules: [] }
  ];
  CB.el = el;
  CB.toast = toast;
  CB.api = api;
  CB.copyText = copyText;
  CB.renderModule = renderModule;
  CB.FORMAT_LABEL = FORMAT_LABEL;
  CB.table = function (columns, rows) {
    const thead = el('thead', {}, [el('tr', {}, columns.map((c) => el('th', {}, [c.label])))]);
    const tbody = el('tbody', {}, (rows || []).map((r) => el('tr', {}, columns.map((c) => {
      const v = typeof c.render === 'function' ? c.render(r) : r[c.key];
      return el('td', { class: c.mono ? 'mono' : '' }, [v === undefined || v === null ? '' : String(v)]);
    }))));
    return el('table', { class: 'grid' }, [thead, tbody]);
  };
  CB.badge = function (ok, textOk, textBad) {
    return el('span', { class: 'badge ' + (ok ? 'badge-ok' : 'badge-bad') }, [ok ? (textOk || '通过') : (textBad || '不通过')]);
  };
  CB.ready = true;
})();
