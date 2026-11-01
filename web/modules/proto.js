/* 协议分析工具：TLS / SSH / IPSec / UKey(CCID-APDU) 流量包解析 */
(function () {
  'use strict';
  const el = CB.el;

  /* 内置样例：由 tests/make_fixtures.py 生成的真实 pcap（base64） */
  const TLS_PCAP = '1MOyoQIABAAAAAAAAAAAAAAABAABAAAAALlVadAHAAA2AAAANgAAAAIAAAAAAgIAAAAAAQgARQAAKAABQABABiOtCgoBBQoKAgrIIgG7AAAD5wAAAABQAv//yvsAAAC5VWm4CwAANgAAADYAAAACAAAAAAICAAAAAAEIAEUAACgAAUAAQAYjrQoKAgoKCgEFAbvIIgAAE4cAAAPoUBL//7djAAAAuVVpoA8AADYAAAA2AAAAAgAAAAACAgAAAAABCABFAAAoAAFAAEAGI60KCgEFCgoCCsgiAbsAAAPoAAATiFAQ//+3ZAAAALlVaSgjAABbAAAAWwAAAAIAAAAAAgIAAAAAAQgARQAATQABQABABiOICgoBBQoKAgrIIgG7AAAD6AAAE4hQGP//q5IAABYDAwClAQAAoQMDAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkAuVVpyDIAALsAAAC7AAAAAgAAAAACAgAAAAABCABFAACtAAFAAEAGIygKCgEFCgoCCsgiAbsAAAQNAAATiFAY//9S2gAAGhscHR4fIBERERERERERERERERERERERERERERERERERERERERERAArAK8AvAJwTARMCAQAATgAAAA8ADQAACnRlc3QubG9jYWwACgAGAAQAHQAXAAsAAgEAAA0ACAAGBAMEAQUDABAADgAOAmgyCGh0dHAvMS4xABcAAAArAAUEAwQDAwC5VWloQgAAlgAAAJYAAAACAAAAAAICAAAAAAEIAEUAAIgAAUAAQAYjTQoKAgoKCgEFAbvIIgAAE4gAAASSUBj//935AAAWAwMAWwIAAFcDAyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/IBERERERERERERERERERERERERERERERERERERERERERwCsAAA8ACwACAQAAFwAA/wEAAQAAuVVpCFIAAK4DAACuAwAAAgAAAAACAgAAAAABCABFAAOgAAFAAEAGIDUKCgIKCgoBBQG7yCIAABPoAAAEklAY//+ksAAAFgMDA3MLAANvAANsAAGvMIIBqzCCAVKgAwIBAgIUXJpgtea6bFuOQ9FaUTEVi+9lH5UwCgYIKoZIzj0EAwIwRzELMAkGA1UEBhMCQ04xFzAVBgNVBAoMDkNpcGhlckJveCBUZXN0MR8wHQYDVQQDDBZDaXBoZXJC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ABYDAwBaAgAAVgMDYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8AEwEAAC4AKwACAwQAMwAkAB0AIN0OluuDbkI3506A1V4zM6JQ+ZCNmeKBf9F8lTU9SL4lHrlVaWhCAABrAAAAawAAAAIAAAAAAgIAAAAAAQgARQAAXQABQABABiN3CgoCCgoKAQYBu5y6AAAT5wAABHNQGP//1uAAABcDAwAwXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dXV1dHrlVaQhSAABjAAAAYwAAAAIAAAAAAgIAAAAAAQgARQAAVQABQABABiN/CgoBBgoKAgqcugG7AAAEcwAAFBxQGP//lWoAABcDAwAoGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh65VWmoYQAAewEAAHsBAAACAAAAAAICAAAAAAEIAEUAAW0AAUAAQAYiZwoKAgoKCgEGAbucugAAFBwAAASgUBj//4szAAAXAwMBQCsrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysr';
  const SSH_PCAP = '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';
  const IPSEC_PCAP = '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';
  const UKEY_PCAP = '1MOyoQIABAAAAAAAAAAAAAAABAD5AAAAyLlVaQAAAAAlAAAAJQAAABsAAQAAAAAAAAAAAAAACQAAAQACAAEDCgAAAGUAAAAAAAAAAADIuVVpECcAADQAAAA0AAAAGwABAAAAAAAAAAAAAAAJAAABAAIAgQMZAAAAgA8AAAAAAAAAADuflYA/x6CAMeBz/iEbZ8i5VWkgTgAAMgAAADIAAAAbAAEAAAAAAAAAAAAAAAkAAAEAAgABAxcAAABvDQAAAAAAAAAAAKQEAAigAAAAYwAAF8i5VWkwdQAARwAAAEcAAAAbAAEAAAAAAAAAAAAAAAkAAAEAAgCBAywAAACAIgAAAAAAAAAAbxqECKAAAABjAAAXRmVpdGlhbiBlUGFzczMwMDMgR02QAMi5VWlAnAAAKgAAACoAAAAbAAEAAAAAAAAAAAAAAAkAAAEAAgABAw8AAABvBQAAAAABAAAAAMAAACDIuVVpUMMAACkAAAApAAAAGwABAAAAAAAAAAAAAAAJAAABAAIAgQMOAAAAgAQAAAAAAQAAAG8AkADIuVVpYOoAACoAAAAqAAAAGwABAAAAAAAAAAAAAAAJAAABAAIAAQMPAAAAbwUAAAAAAgAAAACwAAD/yLlVaXARAQC5AQAAuQEAABsAAQAAAAAAAAAAAAAACQAAAQACAIEDngEAAICUAQAAAAIAAAAwggGOMIIBNKADAgECAhRULf0gnWX3lJtk80SZoaDreEo/nDAKBggqhkjOPQQDAjBCMQswCQYDVQQGEwJDTjEXMBUGA1UECgwOQ2lwaGVyQm94IFRlc3QxGjAYBgNVBAMMEVVLZXkgVGVzdCBSb290IENBMB4XDTI1MTIzMTIzMDAwMFoXDTI3MDEwMTAwMDAwMFowOjELMAkGA1UEBhMCQ04xFzAVBgNVBAoMDkNpcGhlckJveCBUZXN0MRIwEAYDVQQDDAl1a2V5LXVzZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS7mnEmdOdRRT510S16Po57EFqhKMo9AcJbV+HnO27BODKvnWwNingAzw9MrkrDuk8P9GN9eA+e92Pr9bz0BsEZoxAwDjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDFJHrPxvrhZSNkOmFyJs5dFCbiEljiCleRNCRLrGqOOwIgPVWDZcUBNB0ToHouhjKriGKzM1h6d1/ZBVsTKYeqLmiQAA==';

  const FORMATS = [['BASE64', 'Base64'], ['HEX', '十六进制']];

  /* ---------------- 通用渲染 ---------------- */
  function kv(label, value, mono) {
    const v = (value === null || value === undefined || value === '') ? '-' : value;
    const box = el('div', { class: 'kv' }, [el('span', { class: 'kv-label' }, [label])]);
    if (v instanceof Node) {
      box.appendChild(el('span', { class: 'kv-value' }, [v]));
    } else {
      box.appendChild(el('span', { class: 'kv-value' + (mono ? ' mono' : '') }, [String(v)]));
    }
    return box;
  }

  function descGrid(items) {
    const grid = el('div', { class: 'desc-grid' });
    items.forEach((it) => {
      if (!it) return;
      grid.appendChild(kv(it[0], it[1], it[2]));
    });
    return grid;
  }

  function badge(ok, textOk, textBad) {
    return el('span', { class: 'badge ' + (ok ? 'badge-ok' : 'badge-bad') }, [ok ? (textOk || '通过') : (textBad || '不通过')]);
  }

  function badgeInfo(text) {
    return el('span', { class: 'badge' }, [text]);
  }

  function downloadPem(name, pem) {
    try {
      const blob = new Blob([pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = el('a', { href: url, download: String(name).replace(/[\\/:*?"<>|]/g, '_') + '.pem', style: 'display:none' });
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 500);
      CB.toast('证书已导出', 'success');
    } catch (e) {
      CB.toast('导出失败，请手动复制 PEM 内容', 'error');
    }
  }

  function certBlock(cert, idx) {
    const wrap = el('div', { class: 'cert-block' });
    wrap.appendChild(el('div', { class: 'cert-title' }, ['证书 ' + idx + '：' + (cert.subject || '(未解析)')]));
    wrap.appendChild(descGrid([
      ['颁发者', cert.issuer, true],
      ['序列号', cert.serial, true],
      ['有效期', (cert.notBefore || '') + ' ~ ' + (cert.notAfter || ''), true],
      ['签名算法', cert.signatureAlgorithm],
      ['公钥算法', (cert.publicKeyAlgorithm || '') + (cert.keyBits ? ' / ' + cert.keyBits + ' bit' : '')],
      ['是否 CA', cert.isCA ? '是' : '否'],
      ['SHA-256', cert.sha256, true],
      ['SAN', (cert.san || []).join(', '), true]
    ]));
    if (cert.pem) {
      wrap.appendChild(el('button', {
        type: 'button', class: 'btn btn-mini', 'data-export': cert.subject || '',
        onclick: () => downloadPem(cert.subject || 'certificate', cert.pem)
      }, ['导出证书']));
    }
    return wrap;
  }

  function sessionCard(no, title, bodyNodes) {
    const card = el('div', { class: 'session-card' });
    const head = el('div', { class: 'session-head' }, [
      el('span', { class: 'session-no' }, ['会话 ' + no]),
      el('span', { class: 'session-title' }, [title])
    ]);
    card.appendChild(head);
    (bodyNodes || []).forEach((n) => { if (n) card.appendChild(n); });
    return card;
  }

  function subTitle(text) {
    return el('div', { class: 'session-sub' }, [text]);
  }

  function listText(arr) {
    return (arr || []).join('；');
  }

  /* ---------------- 解析入口 ---------------- */
  function sourcePayload(ctx) {
    const f = ctx.file('file');
    if (f && f.b64) {
      return { file: f.b64, fileName: f.name || '' };
    }
    return { pcap: ctx.val('pcap') || '', pcapFormat: ctx.val('pcapFormat') || 'BASE64', fileName: '' };
  }

  function mergePayload(ctx, endpoint, extra) {
    const base = sourcePayload(ctx);
    const payload = Object.assign({
      srcAddr: (ctx.val('srcAddr') || '').trim(),
      dstAddr: (ctx.val('dstAddr') || '').trim(),
      srcPort: ctx.val('srcPort'),
      dstPort: ctx.val('dstPort')
    }, base, extra || {});
    return CB.api(endpoint, payload);
  }

  function metaLine(data) {
    const meta = data.meta || {};
    return '文件格式：' + (meta.format || '-') + '，报文数：' + (meta.packets || 0) +
      (meta.tlsFlows ? '，TLS 流：' + meta.tlsFlows : '') +
      (meta.ikeMessages ? '，IKE 报文：' + meta.ikeMessages : '') +
      (meta.ccidBlocks ? '，CCID 块：' + meta.ccidBlocks : '') +
      '，解析耗时：' + (meta.elapsedMs || 0) + ' ms';
  }

  /* ---------------- TLS ---------------- */
  function tlsCard(s) {
    const nodes = [];
    nodes.push(descGrid([
      ['协议版本', s.protocol],
      ['是否完成握手', badge(s.successHandshake, '是', '否')],
      ['认证方式', s.authMode],
      ['服务端选择的密码套件', s.serverCipherSuite || '-'],
      ['SNI', s.sni],
      ['ALPN', (s.alpn || []).join(', ')],
      ['客户端随机数', s.clientRandom, true],
      ['服务端随机数', s.serverRandom, true],
      ['源 / 目的', s.addressInfo.srcAddr + ':' + s.addressInfo.srcPort + ' → ' + s.addressInfo.dstAddr + ':' + s.addressInfo.dstPort, true],
      ['记录数', s.recordCount],
      ['时间范围', (s.firstPacket || '') + ' ~ ' + (s.lastPacket || '')]
    ]));
    if ((s.clientCipherSuites || []).length) {
      nodes.push(subTitle('客户端密码套件列表（' + s.clientCipherSuites.length + '）'));
      nodes.push(el('div', { class: 'mono small' }, [(s.clientCipherSuites || []).join('，')]));
    }
    if ((s.serverCertList || []).length) {
      nodes.push(subTitle('服务端证书链（' + s.serverCertList.length + '）'));
      s.serverCertList.forEach((c, i) => nodes.push(certBlock(c, i + 1)));
    } else if (s.protocol !== 'TLS 1.3') {
      nodes.push(subTitle('服务端证书链'));
      nodes.push(el('div', { class: 'muted' }, ['未解析到服务端证书，此流量包可能存在问题']));
    }
    if ((s.clientCertList || []).length) {
      nodes.push(subTitle('客户端证书链（' + s.clientCertList.length + '）'));
      s.clientCertList.forEach((c, i) => nodes.push(certBlock(c, i + 1)));
    }
    const skx = s.serverKeyExchange || {};
    if (skx.present) {
      nodes.push(subTitle('服务端密钥交换消息验签'));
      nodes.push(descGrid([
        ['验签结果', skx.checked ? badge(skx.result, '通过', '不通过') : badgeInfo('未验证')],
        ['签名算法', skx.signatureAlgorithm],
        ['椭圆曲线', skx.curve],
        ['签名值', skx.signature, true],
        ['签名原文', skx.plaintext, true],
        ['说明', skx.reason]
      ]));
    }
    const cvs = [
      ['服务端 CertificateVerify', s.serverCertVerify],
      ['客户端 CertificateVerify', s.clientCertVerify]
    ];
    cvs.forEach((entry) => {
      const cv = entry[1] || {};
      if (!cv.present) return;
      nodes.push(subTitle(entry[0]));
      nodes.push(descGrid([
        ['验签结果', cv.checked ? badge(cv.result, '通过', '不通过') : badgeInfo('未验证')],
        ['签名算法', cv.signatureAlgorithm],
        ['签名值', cv.signature, true],
        ['签名原文', cv.plaintext, true],
        ['说明', cv.reason]
      ]));
    });
    if ((s.timeline || []).length) {
      nodes.push(subTitle('握手时间线（' + s.timeline.length + ' 个事件）'));
      nodes.push(CB.table([
        { key: 'time', label: '时间', mono: true },
        { key: 'from', label: '方向' },
        { key: 'message', label: '握手消息' },
        { key: 'detail', label: '说明' }
      ], s.timeline));
    }
    if ((s.notes || []).length) {
      nodes.push(subTitle('解析说明'));
      s.notes.forEach((n) => nodes.push(el('div', { class: 'muted small' }, ['· ' + n])));
    }
    return sessionCard(s.index, s.protocol + '　' + s.addressInfo.srcAddr + ':' + s.addressInfo.srcPort +
      ' → ' + s.addressInfo.dstAddr + ':' + s.addressInfo.dstPort, nodes);
  }

  function paintTls(wrap, data) {
    wrap.innerHTML = '';
    if (!data) {
      wrap.appendChild(el('div', { class: 'muted' }, ['请选择或粘贴流量包后点击“解析流量包”']));
      return;
    }
    wrap.appendChild(el('div', { class: 'result-heading' }, [
      '共解析出 ' + data.count + ' 组会话数据，解析时间：' + data.parsedAt
    ]));
    wrap.appendChild(el('div', { class: 'muted small' }, [metaLine(data)]));
    (data.sessions || []).forEach((s) => wrap.appendChild(tlsCard(s)));
  }

  /* ---------------- SSH ---------------- */
  function sshCard(s) {
    const nodes = [];
    const verify = s.signVerify || {};
    nodes.push(descGrid([
      ['协议版本', s.protocolVersion],
      ['客户端版本', s.clientVersion],
      ['服务端版本', s.serverVersion],
      ['对称加密算法', s.encryptAlgorithm],
      ['MAC 算法', s.macAlgorithm],
      ['密钥交换算法', s.kexAlgorithms],
      ['主机密钥算法', s.hostKeyAlgorithm],
      ['压缩算法', s.compression],
      ['主机密钥类型', s.hostKeyType + (s.hostKeyBits ? ' / ' + s.hostKeyBits + ' bit' : '')],
      ['主机密钥指纹', s.hostKeyFingerprint, true]
    ]));
    nodes.push(subTitle('服务端支持的算法（来自 KEXINIT）'));
    nodes.push(descGrid([
      ['加密算法列表', listText(s.serverEncryptAlgorithms), true],
      ['完整性算法列表', listText(s.serverMacAlgorithms), true],
      ['密钥交换算法列表', listText(s.serverKexAlgorithms), true],
      ['主机密钥算法列表', listText(s.serverHostKeyAlgorithms), true]
    ]));
    nodes.push(subTitle('客户端协商的算法（来自 KEXINIT）'));
    nodes.push(descGrid([
      ['加密算法列表', listText(s.clientEncryptAlgorithms), true],
      ['完整性算法列表', listText(s.clientMacAlgorithms), true],
      ['密钥交换算法列表', listText(s.clientKexAlgorithms), true]
    ]));
    nodes.push(subTitle('DH 参数与签名'));
    nodes.push(descGrid([
      ['客户端协商 DH 参数', s.clientDHQc, true],
      ['服务端协商 DH 参数', s.serverDHQc, true],
      ['服务端签名类型', s.signatureAlgorithm],
      ['服务端签名值', s.signature, true],
      ['验签结果', verify.checked ? badge(verify.result, '通过', '不通过') : badgeInfo('无法验证')],
      ['验签说明', verify.reason]
    ]));
    return sessionCard(s.index, s.protocolVersion + '　' + s.addressInfo.srcAddr + ':' + s.addressInfo.srcPort +
      ' → ' + s.addressInfo.dstAddr + ':' + s.addressInfo.dstPort, nodes);
  }

  function paintSsh(wrap, data) {
    wrap.innerHTML = '';
    if (!data) {
      wrap.appendChild(el('div', { class: 'muted' }, ['请选择或粘贴流量包后点击“解析流量包”']));
      return;
    }
    wrap.appendChild(el('div', { class: 'result-heading' }, [
      '共解析出 ' + data.count + ' 组会话数据，解析时间：' + data.parsedAt
    ]));
    wrap.appendChild(el('div', { class: 'muted small' }, [metaLine(data)]));
    (data.sessions || []).forEach((s) => wrap.appendChild(sshCard(s)));
  }

  /* ---------------- IPSec ---------------- */
  function ipsecCard(s) {
    const nodes = [];
    nodes.push(descGrid([
      ['协议版本', s.protocol + ' ' + s.version],
      ['加密算法', s.encAlgorithm + (s.encKeyLength ? '，密钥长度：' + s.encKeyLength : '')],
      ['MAC 算法', s.macAlgorithm],
      ['认证算法（PRF）', s.prfAlgorithm],
      ['非对称算法 / DH 组', s.dhGroup],
      ['密钥更新周期', s.lifeType ? s.lifeDuration + ' ' + s.lifeType : '-'],
      ['发起方 SPI', s.initiatorSPI, true],
      ['响应方 SPI', s.responderSPI, true],
      ['发起方 / 响应方', s.addressInfo.srcAddr + ':' + s.addressInfo.srcPort + ' → ' + s.addressInfo.dstAddr + ':' + s.addressInfo.dstPort, true],
      ['客户端身份', s.clientIdentity, true],
      ['服务端身份', s.serverIdentity, true],
      ['客户端 Nonce', s.clientNonce, true],
      ['服务端 Nonce', s.serverNonce, true]
    ]));
    if ((s.clientCertList || []).length) {
      nodes.push(subTitle('客户端证书链（' + s.clientCertList.length + '）'));
      s.clientCertList.forEach((c, i) => nodes.push(certBlock(c, i + 1)));
    }
    if ((s.serverCertList || []).length) {
      nodes.push(subTitle('服务端证书链（' + s.serverCertList.length + '）'));
      s.serverCertList.forEach((c, i) => nodes.push(certBlock(c, i + 1)));
    }
    if ((s.messages || []).length) {
      nodes.push(subTitle('会话分组报文（' + s.messages.length + ' 条）'));
      nodes.push(CB.table([
        { key: 'time', label: '时间', mono: true },
        { key: 'from', label: '方向' },
        { key: 'exchange', label: '交换类型' },
        { key: 'messageId', label: '消息 ID' },
        { key: 'payloads', label: '载荷', render: (r) => (r.payloads || []).join(' / ') }
      ], s.messages));
    }
    if ((s.notes || []).length) {
      nodes.push(subTitle('解析说明'));
      s.notes.forEach((n) => nodes.push(el('div', { class: 'muted small' }, ['· ' + n])));
    }
    return sessionCard(s.index, s.protocol + '　' + s.initiatorSPI.slice(0, 16) + ' / ' + s.responderSPI.slice(0, 16), nodes);
  }

  function paintIpsec(wrap, data) {
    wrap.innerHTML = '';
    if (!data) {
      wrap.appendChild(el('div', { class: 'muted' }, ['请选择或粘贴流量包后点击“解析流量包”']));
      return;
    }
    wrap.appendChild(el('div', { class: 'result-heading' }, [
      '共解析出 ' + data.count + ' 组会话数据，解析时间：' + data.parsedAt
    ]));
    wrap.appendChild(el('div', { class: 'muted small' }, [metaLine(data)]));
    (data.sessions || []).forEach((s) => wrap.appendChild(ipsecCard(s)));
  }

  /* ---------------- UKey ---------------- */
  function ukeyView(data) {
    const nodes = [];
    nodes.push(descGrid([
      ['UKEY 厂商', data.vendor],
      ['识别依据', data.vendorEvidence],
      ['识别置信度', data.vendorConfidence === 'high' ? '高' : (data.vendorConfidence === 'manual' ? '用户指定' : '低')],
      ['ATR', data.atr, true],
      ['命令数', data.apduCount],
      ['解析时间', data.parsedAt]
    ]));
    if ((data.apdus || []).length) {
      nodes.push(subTitle('APDU 指令与响应（' + data.apdus.length + ' 条）'));
      nodes.push(CB.table([
        { key: 'index', label: '#' },
        { key: 'time', label: '时间', mono: true },
        { key: 'direction', label: '方向' },
        { key: 'name', label: '指令' },
        { key: 'cla', label: 'CLA', mono: true },
        { key: 'ins', label: 'INS', mono: true },
        { key: 'p1', label: 'P1', mono: true },
        { key: 'p2', label: 'P2', mono: true },
        { key: 'lc', label: 'Lc' },
        { key: 'le', label: 'Le' },
        { key: 'sw', label: '状态字', mono: true },
        { key: 'description', label: '说明' }
      ], data.apdus));
    }
    if ((data.certificates || []).length) {
      nodes.push(subTitle('证书（' + data.certificates.length + '）'));
      data.certificates.forEach((c, i) => nodes.push(certBlock(c, i + 1)));
    } else {
      nodes.push(el('div', { class: 'muted' }, ['APDU 响应中未发现完整的 DER 证书']));
    }
    if ((data.publicKeys || []).length) {
      nodes.push(subTitle('公钥（' + data.publicKeys.length + '）'));
      data.publicKeys.forEach((k, i) => {
        nodes.push(descGrid([
          ['公钥 ' + (i + 1), (k.algorithm || '') + ' / ' + (k.bits || 0) + ' bit'],
          ['公钥内容', k.text, true]
        ]));
      });
    }
    if ((data.notes || []).length) {
      nodes.push(subTitle('解析说明'));
      data.notes.forEach((n) => nodes.push(el('div', { class: 'muted small' }, ['· ' + n])));
    }
    return nodes;
  }

  function paintUkey(wrap, data) {
    wrap.innerHTML = '';
    if (!data) {
      wrap.appendChild(el('div', { class: 'muted' }, ['请选择或粘贴 UKey 抓包后点击“解析流量包”']));
      return;
    }
    wrap.appendChild(el('div', { class: 'result-heading' }, [
      '识别 UKey 厂商：' + data.vendor + '，解析时间：' + data.parsedAt
    ]));
    wrap.appendChild(el('div', { class: 'muted small' }, [metaLine(data)]));
    ukeyView(data).forEach((n) => wrap.appendChild(n));
  }

  function customResult(name, painter) {
    return {
      name: name, type: 'custom',
      render: (box, ctx) => {
        const wrap = el('div', { 'data-result': name });
        box.appendChild(wrap);
        painter(wrap, ctx.result(name));
        ctx.onResult = (n, v) => { if (n === name) painter(wrap, v); };
      }
    };
  }

  /* ---------------- 注册：TLS ---------------- */
  CB.register({
    key: 'tls', cat: 'proto', title: 'TLS 流量包解析',
    desc: '上传 pcap/pcapng，解析 TLS 握手、密码套件、证书链与签名验签结果',
    help: [
      { title: '使用提示', items: [
        '如果抓包文件名没有按要求命名，可以手动填写源 IP 和目标 IP。',
        '文件上传与 Base64 粘贴二选一，上传优先。',
        'TLS 1.3 的握手在 ServerHello 之后加密，证书链与签名无法被动解析。'
      ] },
      { title: '解析范围', items: [
        '自动识别 443 及自定义端口上的 TLS 记录层与握手消息。',
        '证书使用 cryptography 解析，可导出 PEM。',
        'ServerKeyExchange / CertificateVerify 会用证书公钥做真实验签。'
      ] }
    ],
    state: { pcapFormat: 'BASE64', pcap: '', srcAddr: '', dstAddr: '', srcPort: '', dstPort: '' },
    fields: [
      { name: 'file', label: '流量包文件', type: 'file', accept: '.pcap,.pcapng', span: 2, placeholder: '点击或拖拽 pcap / pcapng 文件到此区域上传' },
      { name: 'pcap', label: '或粘贴流量包内容', type: 'textarea', formatField: 'pcapFormat', formats: FORMATS, rows: 2, span: 2, placeholder: 'Base64 编码的 pcap / pcapng 内容' },
      { name: 'srcAddr', label: '发起方 IP', type: 'input', placeholder: '留空表示不过滤，例如 10.10.1.5' },
      { name: 'dstAddr', label: '接收端 IP', type: 'input', placeholder: '留空表示不过滤' },
      { name: 'srcPort', label: '发起方端口', type: 'number', min: 0, max: 65535 },
      { name: 'dstPort', label: '接收端端口', type: 'number', min: 0, max: 65535 }
    ],
    actions: [{
      name: 'parse', label: '解析流量包', primary: true,
      run: async (ctx) => {
        const data = await mergePayload(ctx, '/api/proto/tls/parse', {});
        ctx.setResult('sessions', data);
        ctx.setResult('summary', '共解析出 ' + data.count + ' 组会话数据，解析时间：' + data.parsedAt);
        CB.toast('解析成功', 'success');
      }
    }],
    results: [
      customResult('sessions', paintTls),
      { name: 'summary', label: '解析摘要', type: 'textarea', rows: 2 }
    ],
    samples: {
      parse: { pcap: TLS_PCAP }
    },
    cleanup: false
  });

  /* ---------------- 注册：SSH ---------------- */
  CB.register({
    key: 'ssh', cat: 'proto', title: 'SSH 流量包解析',
    desc: '解析 SSH 版本协商、KEXINIT 算法列表、DH 参数与主机密钥签名',
    help: [
      { title: '使用提示', items: [
        '如果目标端口不是 22，请按实际情况修改端口。',
        '如果抓包文件名没有按要求命名，可以手动填写源 IP 和目标 IP。'
      ] },
      { title: '签名说明', items: [
        '主机密钥签名覆盖交换哈希 H，其中包含共享秘密 K。',
        '被动抓包无法获得 K，若需验签请在“共享密钥 K”中按十六进制填写。'
      ] }
    ],
    state: { pcapFormat: 'BASE64', pcap: '', srcAddr: '', dstAddr: '', sshPort: 22, kexSecret: '' },
    fields: [
      { name: 'file', label: '流量包文件', type: 'file', accept: '.pcap,.pcapng', span: 2, placeholder: '点击或拖拽 pcap / pcapng 文件到此区域上传' },
      { name: 'pcap', label: '或粘贴流量包内容', type: 'textarea', formatField: 'pcapFormat', formats: FORMATS, rows: 2, span: 2, placeholder: 'Base64 编码的 pcap / pcapng 内容' },
      { name: 'sshPort', label: '目标端口', type: 'number', min: 0, max: 65535 },
      { name: 'kexSecret', label: '共享密钥 K（可选）', type: 'input', placeholder: '十六进制，填写后可验证主机密钥签名' },
      { name: 'srcAddr', label: '发起方 IP', type: 'input', placeholder: '留空表示不过滤' },
      { name: 'dstAddr', label: '接收端 IP', type: 'input', placeholder: '留空表示不过滤' }
    ],
    actions: [{
      name: 'parse', label: '解析流量包', primary: true,
      run: async (ctx) => {
        const data = await mergePayload(ctx, '/api/proto/ssh/parse', {
          sshPort: ctx.val('sshPort') || 22,
          kexSecret: (ctx.val('kexSecret') || '').trim()
        });
        ctx.setResult('sessions', data);
        ctx.setResult('summary', '共解析出 ' + data.count + ' 组会话数据，解析时间：' + data.parsedAt);
        CB.toast('解析成功', 'success');
      }
    }],
    results: [
      customResult('sessions', paintSsh),
      { name: 'summary', label: '解析摘要', type: 'textarea', rows: 2 }
    ],
    samples: {
      parse: { pcap: SSH_PCAP }
    },
    cleanup: false
  });

  /* ---------------- 注册：IPSec ---------------- */
  CB.register({
    key: 'ipsec', cat: 'proto', title: 'IPSec 流量包解析',
    desc: '解析 IPSec/IKE 会话：SPI、加密算法与密钥长度、Nonce、证书链与会话分组',
    help: [
      { title: '使用提示', items: [
        '默认监听 UDP 500/4500，如果抓包使用了自定义端口请填写端口。',
        '如果抓包文件名没有按要求命名，可以手动填写源 IP 和目标 IP。'
      ] },
      { title: '解析范围', items: [
        'IKEv2：SA 提案（加密/PRF/完整性/DH/生命周期）、KE、Nonce、ID、CERT、AUTH。',
        'IKEv1：报文头、SA 提案、Nonce 与 Cookie。',
        'IKE_AUTH 的 SK 载荷已加密，无法解密，证书仅在明文 CERT 载荷中可见。'
      ] }
    ],
    state: { pcapFormat: 'BASE64', pcap: '', srcAddr: '', dstAddr: '', srcPort: '', dstPort: '' },
    fields: [
      { name: 'file', label: '流量包文件', type: 'file', accept: '.pcap,.pcapng', span: 2, placeholder: '点击或拖拽 pcap / pcapng 文件到此区域上传' },
      { name: 'pcap', label: '或粘贴流量包内容', type: 'textarea', formatField: 'pcapFormat', formats: FORMATS, rows: 2, span: 2, placeholder: 'Base64 编码的 pcap / pcapng 内容' },
      { name: 'srcAddr', label: '发起方 IP', type: 'input', placeholder: '留空表示不过滤' },
      { name: 'dstAddr', label: '接收端 IP', type: 'input', placeholder: '留空表示不过滤' },
      { name: 'srcPort', label: '发起方端口', type: 'number', min: 0, max: 65535 },
      { name: 'dstPort', label: '接收端端口', type: 'number', min: 0, max: 65535 }
    ],
    actions: [{
      name: 'parse', label: '解析流量包', primary: true,
      run: async (ctx) => {
        const data = await mergePayload(ctx, '/api/proto/ipsec/parse', {});
        ctx.setResult('sessions', data);
        ctx.setResult('summary', '共解析出 ' + data.count + ' 组会话数据，解析时间：' + data.parsedAt);
        CB.toast('解析成功', 'success');
      }
    }],
    results: [
      customResult('sessions', paintIpsec),
      { name: 'summary', label: '解析摘要', type: 'textarea', rows: 2 }
    ],
    samples: {
      parse: { pcap: IPSEC_PCAP }
    },
    cleanup: false
  });

  /* ---------------- 注册：UKey ---------------- */
  CB.register({
    key: 'ukey', cat: 'proto', title: 'UKey 流量包解析',
    desc: '从 USB CCID 抓包中提取 APDU 指令，识别 UKEY 厂商并解析证书/公钥',
    help: [
      { title: '使用提示', items: [
        '下拉框中没有的厂商表示暂未接入，可继续补充样本以加快适配。',
        'UKEY 解析基于报文特征识别，即使未找到签名值，也不一定代表数据中不存在该字段。'
      ] },
      { title: '解析范围', items: [
        '支持 USBPcap（LINKTYPE 249）与 USB_LINUX（LINKTYPE 189）抓包。',
        '提取 CCID 数据块（PC_to_RDR_XfrBlock / RDR_to_PC_DataBlock）与 SELECT / GET RESPONSE / READ BINARY 等 APDU。',
        'APDU 响应中包含完整 DER 证书或公钥时会自动解析。'
      ] }
    ],
    state: { pcapFormat: 'BASE64', pcap: '', factory: '', publicKey: '' },
    fields: [
      { name: 'file', label: '流量包文件', type: 'file', accept: '.pcap,.pcapng', span: 2, placeholder: '点击或拖拽 pcap / pcapng 文件到此区域上传' },
      { name: 'pcap', label: '或粘贴流量包内容', type: 'textarea', formatField: 'pcapFormat', formats: FORMATS, rows: 2, span: 2, placeholder: 'Base64 编码的 pcap / pcapng 内容' },
      { name: 'factory', label: 'UKEY 厂商', type: 'select', options: [
        ['', '自动识别'], ['符合 0017 标准规范', '符合 0017 标准规范'], ['山东渔翁', '山东渔翁'],
        ['海泰方圆', '海泰方圆'], ['上海华申', '上海华申'], ['三未信安', '三未信安'],
        ['飞天诚信', '飞天诚信'], ['北京 CA', '北京 CA'], ['中金国信（CFCA）', '中金国信（CFCA）']
      ] },
      { name: 'publicKey', label: '公钥 / 证书（可选）', type: 'textarea', rows: 3, placeholder: '请输入或上传公钥/证书' }
    ],
    actions: [{
      name: 'parse', label: '解析流量包', primary: true,
      run: async (ctx) => {
        const base = sourcePayload(ctx);
        const data = await CB.api('/api/proto/ukey/parse', Object.assign({}, base, {
          factory: ctx.val('factory') || '',
          publicKey: ctx.val('publicKey') || ''
        }));
        ctx.setResult('report', data);
        ctx.setResult('summary', 'UKEY 厂商：' + data.vendor + '，APDU 指令 ' + data.apduCount + ' 条，解析时间：' + data.parsedAt);
        CB.toast('解析成功', 'success');
      }
    }],
    results: [
      customResult('report', paintUkey),
      { name: 'summary', label: '解析摘要', type: 'textarea', rows: 2 }
    ],
    samples: {
      parse: { pcap: UKEY_PCAP }
    },
    cleanup: false
  });
})();
