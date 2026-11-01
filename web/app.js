/* 密码工具百宝箱 · 本地版 —— 路由与页面框架 */
(function () {
  'use strict';
  const el = CB.el;
  const view = document.getElementById('view');
  const sidebar = document.getElementById('sidebar');
  const crumb = document.getElementById('crumb');

  function catOf(mod) {
    return (CB.categories.find((c) => c.id === mod.cat) || {}).title || '工具';
  }

  function buildSidebar(keyword) {
    sidebar.innerHTML = '';
    const kw = (keyword || '').trim().toLowerCase();
    CB.categories.forEach((cat) => {
      const mods = cat.modules
        .map((k) => CB.modules[k])
        .filter((m) => m && (!kw || m.title.toLowerCase().includes(kw) || (m.desc || '').toLowerCase().includes(kw)));
      if (!mods.length) return;
      const group = el('div', { class: 'menu-group' });
      group.appendChild(el('div', { class: 'menu-group-title' }, [cat.title]));
      mods.forEach((m) => {
        const a = el('a', { class: 'menu-item' + (location.hash === '#/' + m.key ? ' active' : ''), href: '#/' + m.key }, [m.title]);
        group.appendChild(a);
      });
      sidebar.appendChild(group);
    });
    if (!sidebar.children.length) sidebar.appendChild(el('div', { class: 'menu-empty' }, ['没有匹配的工具']));
  }

  function setActive(key) {
    document.querySelectorAll('.menu-item').forEach((n) => {
      n.classList.toggle('active', n.getAttribute('href') === '#/' + key);
    });
  }

  function route() {
    const hash = location.hash.replace(/^#\/?/, '') || 'home';
    const mod = CB.modules[hash];
    window.scrollTo(0, 0);
    if (!mod) {
      renderHome();
      setActive('home');
      crumb.textContent = '首页';
      document.title = '密码工具百宝箱 · 本地版';
      return;
    }
    crumb.textContent = catOf(mod) + ' / ' + mod.title;
    document.title = mod.title + ' · 密码工具百宝箱';
    CB.renderModule(mod, view);
    setActive(mod.key);
    if (window.innerWidth < 900) document.body.classList.remove('nav-open');
  }

  function renderHome() {
    view.innerHTML = '';
    const page = el('div', { class: 'page home-page' });

    const hero = el('div', { class: 'hero' });
    hero.appendChild(el('div', { class: 'hero-main' }, [
      el('h1', {}, ['商用密码检测工具箱']),
      el('p', {}, ['离线本地版 · 覆盖对称/非对称/杂凑/证书/协议/签章等全部检测工具，无广告、无授权、无外部依赖']),
      el('div', { class: 'hero-tags' }, [
        el('span', { class: 'tag' }, ['纯本地运行']),
        el('span', { class: 'tag' }, ['SM2 / SM3 / SM4 / SM9 / ZUC']),
        el('span', { class: 'tag' }, ['X.509 / CRL / ASN.1']),
        el('span', { class: 'tag' }, ['TLS / SSH / IPSec / UKey'])
      ])
    ]));
    const today = new Date();
    hero.appendChild(el('div', { class: 'hero-side' }, [
      el('div', { class: 'hero-date' }, [today.getFullYear() + ' 年 ' + (today.getMonth() + 1) + ' 月 ' + today.getDate() + ' 日']),
      el('div', { class: 'hero-week' }, ['星期' + '日一二三四五六'[today.getDay()]]),
      el('div', { class: 'hero-count' }, [Object.keys(CB.modules).length + ' 个工具模块'])
    ]));
    page.appendChild(hero);

    const quick = el('div', { class: 'card' });
    quick.appendChild(el('div', { class: 'card-title' }, ['快捷入口']));
    const grid = el('div', { class: 'quick-grid' });
    const quickItems = [
      ['sm2', 'SM2', '#4f7cff'],
      ['cert/format/check', '数字证书', '#1fb6a6'],
      ['tls', 'TLS 分析', '#6b6bff'],
      ['encode', '编码转换', '#f2994a'],
      ['hash', '杂凑函数', '#eb5757'],
      ['signatrue', '电子签章', '#2d9cdb'],
      ['scoring', '量化评估', '#27ae60'],
      ['ukey', 'APDU 分析', '#9b51e0']
    ];
    quickItems.forEach(([key, title, color]) => {
      const mod = CB.modules[key];
      if (!mod) return;
      const a = el('a', { class: 'quick-item', href: '#/' + key });
      a.appendChild(el('span', { class: 'quick-icon', style: 'background:' + color }, [title.slice(0, 1)]));
      a.appendChild(el('span', {}, [title]));
      grid.appendChild(a);
    });
    quick.appendChild(grid);
    page.appendChild(quick);

    const row = el('div', { class: 'home-row' });

    const log = el('div', { class: 'card' });
    log.appendChild(el('div', { class: 'card-title' }, ['更新日志']));
    const logs = [
      ['本地版 v1.0', '全部工具模块实现本地化计算，移除广告、外链与授权校验'],
      ['工具覆盖', '对称密码、杂凑、非对称、证书、协议解析、签章、时间戳、随机数、量化评估'],
      ['离线可用', '不依赖任何外部接口，断网环境下全部功能可用']
    ];
    logs.forEach(([t, d]) => {
      const item = el('div', { class: 'log-item' });
      item.appendChild(el('div', { class: 'log-title' }, [t]));
      item.appendChild(el('div', { class: 'log-desc' }, [d]));
      log.appendChild(item);
    });
    row.appendChild(log);

    const msg = el('div', { class: 'card' });
    msg.appendChild(el('div', { class: 'card-title' }, ['留言与建议']));
    const list = el('div', { class: 'msg-list' });
    const key = 'cipherbox_messages';
    const load = () => JSON.parse(localStorage.getItem(key) || '[]');
    const paint = () => {
      list.innerHTML = '';
      const items = load();
      if (!items.length) list.appendChild(el('div', { class: 'msg-empty' }, ['暂无留言，欢迎提出使用建议']));
      items.slice().reverse().forEach((m) => {
        list.appendChild(el('div', { class: 'msg-item' }, [
          el('div', { class: 'msg-time' }, [m.time]),
          el('div', {}, [m.text])
        ]));
      });
    };
    const input = el('textarea', { class: 'textarea', rows: 3, placeholder: '请输入留言内容（仅保存在本机浏览器）', 'data-field': 'home-message' });
    const btn = el('button', { class: 'btn btn-primary', 'data-action': 'home-leave-message' }, ['提交留言']);
    btn.addEventListener('click', () => {
      const text = input.value.trim();
      if (!text) { CB.toast('请输入留言内容', 'warn'); return; }
      const items = load();
      items.push({ text, time: new Date().toLocaleString('zh-CN') });
      localStorage.setItem(key, JSON.stringify(items.slice(-50)));
      input.value = '';
      paint();
      CB.toast('留言已保存到本地', 'success');
    });
    msg.appendChild(list);
    msg.appendChild(input);
    msg.appendChild(btn);
    paint();
    row.appendChild(msg);

    page.appendChild(row);
    page.appendChild(el('div', { class: 'foot-note' }, ['本工具完全在本地计算，数据不会离开你的设备。']));
    view.appendChild(page);
  }

  document.getElementById('search').addEventListener('input', (e) => buildSidebar(e.target.value));
  window.addEventListener('hashchange', route);
  window.addEventListener('DOMContentLoaded', () => {});
  buildSidebar('');
  route();

  document.getElementById('toggle-nav').addEventListener('click', () => {
    document.body.classList.toggle('nav-open');
  });
})();
