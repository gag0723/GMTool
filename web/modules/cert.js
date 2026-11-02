/* 数字证书校验：格式检查（含证书链）/ 证书状态检查（CRL、OCSP）/ CRL 有效性校验 / 证书签发（CSR、PFX）/ ASN.1 解析 */
(function () {
  'use strict';
  const el = CB.el;

  /* ======================= 固定示例数据 =======================
   * 由 tests/test_cert.py 生成并固化的示例证书（不依赖运行时生成）：
   * SM2 根证书 + SM2 终端证书、RSA 根证书 + RSA 终端证书、
   * 由 SM2 根 CA 签发并吊销了 SM2 终端证书的 CRL、
   * 由 RSA 根 CA 签发的 OCSP 响应（GOOD）、SM2 证书请求（P10）。
   */
  const SAMPLE = {
  sm2Root: `-----BEGIN CERTIFICATE-----
MIICADCCAaagAwIBAgIRAI86EcChssPU5fYHGCk6S1wwCgYIKoEcz1UBg3UwTjEL
MAkGA1UEBhMCQ04xGTAXBgNVBAoMEENpcGhlckJveCBTYW1wbGUxJDAiBgNVBAMM
G0NpcGhlckJveCDnpLrkvosgU00yIOaguSBDQTAeFw0yNTAxMDEwMDAwMDBaFw00
NTAxMDEwMDAwMDBaME4xCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJCb3gg
U2FtcGxlMSQwIgYDVQQDDBtDaXBoZXJCb3gg56S65L6LIFNNMiDmoLkgQ0EwWDAT
BgcqhkjOPQIBBggqgRzPVQGCLQNBAGLaiHl8v6kfvDMRNTmCDi/t/pYyVcG4iZ96
Tkyh77AmQ+CmETvQIFeKURYA6DM+CdO5W4zjNcvWuMW9aTVnl7ajZjBkMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTWmtbLRLsa
alghPPBgmuasZH24hTAfBgNVHSMEGDAWgBTWmtbLRLsaalghPPBgmuasZH24hTAK
BggqgRzPVQGDdQNIADBFAiEA8vkXeG7LwAH/jhn4XMyskYGMR4k7SwhUqQefqFtX
0FECIFklkw4qIKt7rXwiW0tC+CLve/NSwwSnyHNrVFthVyFG
-----END CERTIFICATE-----`,
  sm2Leaf: `-----BEGIN CERTIFICATE-----
MIICxzCCAm2gAwIBAgIRAKGyw9Tl9gcYKTpLXG1+j5AwCgYIKoEcz1UBg3UwTjEL
MAkGA1UEBhMCQ04xGTAXBgNVBAoMEENpcGhlckJveCBTYW1wbGUxJDAiBgNVBAMM
G0NpcGhlckJveCDnpLrkvosgU00yIOaguSBDQTAeFw0yNTAxMDEwMDAwMDBaFw0z
NTAxMDEwMDAwMDBaMEIxCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJCb3gg
U2FtcGxlMRgwFgYDVQQDDA9zbTIuZXhhbXBsZS5jb20wWDATBgcqhkjOPQIBBggq
gRzPVQGCLQNBAN1anj0lokOenGBXLGV27ZlJA2aLVH6AqfQyLg5ntvjep8oprT9i
mUSohCfaH5YtHFIrDdaT3wiOfSsHgGJTGmejggE3MIIBMzAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
LwYDVR0RBCgwJoIPc20yLmV4YW1wbGUuY29tghN3d3cuc20yLmV4YW1wbGUuY29t
MB0GA1UdDgQWBBQZD8X9cTrnkXldzOO+7R17w16D8TAfBgNVHSMEGDAWgBTWmtbL
RLsaalghPPBgmuasZH24hTA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0
dHA6Ly9vY3NwLmNpcGhlcmJveC5sb2NhbC8wEwYDVR0gBAwwCjAIBgZngQwBAgEw
NAYDVR0fBC0wKzApoCegJYYjaHR0cDovL2NybC5jaXBoZXJib3gubG9jYWwvcm9v
dC5jcmwwCgYIKoEcz1UBg3UDSAAwRQIhAL8+vr9OhSKplI4UJTpybwkNGiENpB+2
3xX+ZmE2f3QkAiBBr9LsGiRb9oIrqFkmSFnL0k03HpL6s0qwChv/eEGb9A==
-----END CERTIFICATE-----`,
  rsaRoot: `-----BEGIN CERTIFICATE-----
MIIDjTCCAnWgAwIBAgIRAJpLItGyw9Tl9gcYKTpLXG0wDQYJKoZIhvcNAQELBQAw
TjELMAkGA1UEBhMCQ04xGTAXBgNVBAoMEENpcGhlckJveCBTYW1wbGUxJDAiBgNV
BAMMG0NpcGhlckJveCDnpLrkvosgUlNBIOaguSBDQTAeFw0yNTAxMDEwMDAwMDBa
Fw00NTAxMDEwMDAwMDBaME4xCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJC
b3ggU2FtcGxlMSQwIgYDVQQDDBtDaXBoZXJCb3gg56S65L6LIFJTQSDmoLkgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtf8gmlgbvU4wijwU6wXQL
x8XtVx+VLkSo4M/A9wEZa+6D44ZITOV0faBv0X0eVxkQUMwnmISP0zGlBEe/261Y
MVB8RzUfYvbGJ0epL6vKIP5CPSOfBqMZR0FVYLB3XfN1rfqU9nocoxpz+iy0aEGa
4EkP09Xre1a7J8/JEjA+sI34X9DASibrVtoIguKjYIkgqhErnEejPidNiCYvjeZv
C8E24e6Qg0TeUKL8QyZ7Y+EqUzKrZfuX51Qw6bcp+wPv3LncP3sxbA/5Ty0MWIWf
npWMicRh5z50TSsjPZNfltIA624/io1txMvc7tq2uqMhpV3UowSN10IRjfGdMtPd
AgMBAAGjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgGGMB0G
A1UdDgQWBBQdP/JTWNPkZ5J+D/52/PtWojjBmzAfBgNVHSMEGDAWgBQdP/JTWNPk
Z5J+D/52/PtWojjBmzANBgkqhkiG9w0BAQsFAAOCAQEAkO5tdiH7KVo7iks0PQrC
pVYpql+CXqumjxkrdi+TDo1ei9Ce56Q9zhoU0gjz966qRMpsMc4fSeG2Dsu604BM
oO9+IhX0HxL+qDBTOBpUvaa8fMs5okCCmW017/85cCB86BhchnTPB9EsJNl9hlqr
+pNoHSKfZKDbd2PIy4jVegYwMQzRdUUfWrUVo1rzKUhZu5uEzeXdIHWJ6lC5QOl+
pYUBzfhifoTQSfpzZvJRa/ozp7K1VC1G2sokx3RBWCs5ill3ntBhgP5qR9cGxAnc
NsODchbwEzifpGO/+r0YYPfYWBl4nN9pdNde44rIJejmRxaz5L+ZNNrwS4yoARoE
sA==
-----END CERTIFICATE-----`,
  rsaLeaf: `-----BEGIN CERTIFICATE-----
MIIEPzCCAyegAwIBAgIRALLD1OX2BxgpOktcbX6PkKEwDQYJKoZIhvcNAQELBQAw
TjELMAkGA1UEBhMCQ04xGTAXBgNVBAoMEENpcGhlckJveCBTYW1wbGUxJDAiBgNV
BAMMG0NpcGhlckJveCDnpLrkvosgUlNBIOaguSBDQTAeFw0yNTAxMDEwMDAwMDBa
Fw0zNTAxMDEwMDAwMDBaMEIxCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJC
b3ggU2FtcGxlMRgwFgYDVQQDDA9yc2EuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC2VWUlMGWVqT07lhe2qBdcZvlKHPSAjxFt2GeT
Uul+11Eu/wNgmshlMJkrXtwutS3+tMW8krSNaFD5UbOR8Rd9JVVMGpWg2AI4+9FS
qs8S622VIpQMmLJ0KxBBH6XzKCGPg9phCecQlIVQkjWhyTNodGz6POygyWe3psdy
e+okVGj+ef3ySgHYZi70DXR77lhRytQaaqWyHGA7YP6lmv0ccDU9bTYiMVvYotZG
uC1c/CxdejjFLWupg4rYw+MhcS1XztzKBetNad0W/rcat5tvnqW6lpjgpjEwVRBV
seB0d7QyckJF0tg78JnFbX373GQM2u4rSz8+7+u8gsn1YovnAgMBAAGjggEiMIIB
HjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwGgYDVR0RBBMwEYIPcnNhLmV4YW1wbGUuY29tMB0GA1Ud
DgQWBBS2Am/6ut0gcOFtfWDAuWCC3Rmb5jAfBgNVHSMEGDAWgBQdP/JTWNPkZ5J+
D/52/PtWojjBmzA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9v
Y3NwLmNpcGhlcmJveC5sb2NhbC8wEwYDVR0gBAwwCjAIBgZngQwBAgEwNAYDVR0f
BC0wKzApoCegJYYjaHR0cDovL2NybC5jaXBoZXJib3gubG9jYWwvcm9vdC5jcmww
DQYJKoZIhvcNAQELBQADggEBAFd7KG6Lui1+Vt25/bwLRlOpSu//U05jwiJLRUbC
O5df9qijXvPr+dgR59oBZmDpP4vBE0nfR01UX5lXMKVQ/z/73wNM/O+q2MS066CZ
AEc4J+h0yzmtItu5WDh/6Rjmexc6DGpSBAfvE3sdhvTupiwQG5zrG8ln6Z94J4ma
wzC5fde7MwHVDJvqi9GDBasCnSdaz1W4WkmXW/uKoM5/eopiFuG3D4IzuCdna8Rg
rDPDs3DhSA16QhMZ+IZPV4Tg+hUUmf7tRSgnquCFkRK8fbaL/PGtEh5hlGsNQqgz
JET1YkDGsqPeGvYN4ooHzk5ZdRPJ5f+uPxxp10tIgxKV2eU=
-----END CERTIFICATE-----`,
  crlSm2: `-----BEGIN X509 CRL-----
MIIBPDCB4gIBATAKBggqgRzPVQGDdTBOMQswCQYDVQQGEwJDTjEZMBcGA1UECgwQ
Q2lwaGVyQm94IFNhbXBsZTEkMCIGA1UEAwwbQ2lwaGVyQm94IOekuuS+iyBTTTIg
5qC5IENBFw0yNjExMDEwMzU2NTdaFw0zNjEwMjkwMzU2NTdaMDIwMAIRAKGyw9Tl
9gcYKTpLXG1+j5AXDTI2MTEwMTAzNTY1N1owDDAKBgNVHRUEAwoBAaAvMC0wHwYD
VR0jBBgwFoAU1prWy0S7GmpYITzwYJrmrGR9uIUwCgYDVR0UBAMCAQEwCgYIKoEc
z1UBg3UDSQAwRgIhAOrobi5SaxwVHnkmC1/iFxhiLtYPe5kX9o8sYc2gV4MdAiEA
m1MX+z0LbprEkizT9XD2rQtf6b1NgG9GABfGKBSLrYc=
-----END X509 CRL-----`,
  csrSm2: `-----BEGIN CERTIFICATE REQUEST-----
MIH9MIGjAgEAMEIxCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJCb3ggU2Ft
cGxlMRgwFgYDVQQDDA9wMTAuZXhhbXBsZS5jb20wWDATBgcqhkjOPQIBBggqgRzP
VQGCLQNBABDskEA2HlejsGrnZH8G22CVgIz7H7EHDO0Gj2OgZUpSXY7DRXSFvVN3
S0COKHn7XeFnrFn0VsheWQhVYDCzdcmgADAKBggqgRzPVQGDdQNJADBGAiEAnNSU
tzBRLNTbHtqNa9cdwLS4MJ9TPPqfG4ERYDAyvRcCIQCaelo9ojjnT7BGOn0pHJCc
kYYV3kIvBL+bIauekAyLLw==
-----END CERTIFICATE REQUEST-----`,
  ocspRsaB64: `MIIFpwoBAKCCBaAwggWcBgkrBgEFBQcwAQEEggWNMIIFiTCB2aFQME4xCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJCb3ggU2FtcGxlMSQwIgYDVQQDDBtDaXBoZXJCb3gg56S65L6LIFJTQSDmoLkgQ0EYDzIwMjYxMTAxMDM1NjU3WjB0MHIwSjAJBgUrDgMCGgUABBTj27NYsYIwvh4zwNy0yfnplazyMAQUW4p8orVmUZRV2FJZSi362Cn5Wg8CEQCyw9Tl9gcYKTpLXG1+j5ChgAAYDzIwMjYwMTAxMDAwMDAwWqARGA8yMDQwMDEwMTAwMDAwMFowDQYJKoZIhvcNAQELBQADggEBAEUfrdqszVt1xogXqcQxY2rinHz3IkIyvwZKa40XRrxM/e5a/yRjVbzLEMERxqdcfJxEWUOtwSqErFYUAuwejootCef2M4pLLhN7O0wQUxBjrs6/NuNL8hmbCdTbPprX1ShER6JNrRwMxTrlsxNYBRBnJL3Hp97Jocvk0CEDFoHxEkOAtjueXd+cupt65PQX+3P9CFnSFA/SHnSK736NOlnVvE+FpW4t6MT/m28bTHiGWRZZNhprwEGF7ldYukRe9slchFCDgo6YKN8f6oKPiZSZoC/cQnw2h7YWYSn6IQYOvSDfUjdNXOvWj4r0tpk8AOCvxLekPB9Z/RAKKSCHd6+gggOVMIIDkTCCA40wggJ1oAMCAQICEQCaSyLRssPU5fYHGCk6S1xtMA0GCSqGSIb3DQEBCwUAME4xCzAJBgNVBAYTAkNOMRkwFwYDVQQKDBBDaXBoZXJCb3ggU2FtcGxlMSQwIgYDVQQDDBtDaXBoZXJCb3gg56S65L6LIFJTQSDmoLkgQ0EwHhcNMjUwMTAxMDAwMDAwWhcNNDUwMTAxMDAwMDAwWjBOMQswCQYDVQQGEwJDTjEZMBcGA1UECgwQQ2lwaGVyQm94IFNhbXBsZTEkMCIGA1UEAwwbQ2lwaGVyQm94IOekuuS+iyBSU0Eg5qC5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7X/IJpYG71OMIo8FOsF0C8fF7VcflS5EqODPwPcBGWvug+OGSEzldH2gb9F9HlcZEFDMJ5iEj9MxpQRHv9utWDFQfEc1H2L2xidHqS+ryiD+Qj0jnwajGUdBVWCwd13zda36lPZ6HKMac/ostGhBmuBJD9PV63tWuyfPyRIwPrCN+F/QwEom61baCILio2CJIKoRK5xHoz4nTYgmL43mbwvBNuHukINE3lCi/EMme2PhKlMyq2X7l+dUMOm3KfsD79y53D97MWwP+U8tDFiFn56VjInEYec+dE0rIz2TX5bSAOtuP4qNbcTL3O7atrqjIaVd1KMEjddCEY3xnTLT3QIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUHT/yU1jT5GeSfg/+dvz7VqI4wZswHwYDVR0jBBgwFoAUHT/yU1jT5GeSfg/+dvz7VqI4wZswDQYJKoZIhvcNAQELBQADggEBAJDubXYh+ylaO4pLND0KwqVWKapfgl6rpo8ZK3Yvkw6NXovQnuekPc4aFNII8/euqkTKbDHOH0nhtg7LutOATKDvfiIV9B8S/qgwUzgaVL2mvHzLOaJAgpltNe//OXAgfOgYXIZ0zwfRLCTZfYZaq/qTaB0in2Sg23djyMuI1XoGMDEM0XVFH1q1FaNa8ylIWbubhM3l3SB1iepQuUDpfqWFAc34Yn6E0En6c2byUWv6M6eytVQtRtrKJMd0QVgrOYpZd57QYYD+akfXBsQJ3DbDg3IW8BM4n6Rjv/q9GGD32FgZeJzfaXTXXuOKyCXo5kcWs+S/mTTa8EuMqAEaBLA=`,
  };

  const FORMATS = [['PEM', 'PEM 文本'], ['HEX', '十六进制'], ['BASE64', 'Base64']];
  const STATUS_TEXT = { success: '通过', partial: '部分通过', error: '未通过' };

  /* ======================= 通用渲染工具 ======================= */
  function grid(columns, rows) {
    const thead = el('thead', {}, [el('tr', {}, columns.map((c) => el('th', {}, [c.label])))]);
    const tbody = el('tbody', {}, (rows || []).map((r) => el('tr', {}, columns.map((c) => {
      const v = typeof c.render === 'function' ? c.render(r) : (c.key ? r[c.key] : '');
      const td = el('td', { class: c.mono ? 'mono' : '' });
      if (v === undefined || v === null || v === '') td.textContent = '';
      else if (typeof v === 'object' && v.nodeType === 1) td.appendChild(v);
      else td.textContent = String(v);
      return td;
    }))));
    return el('table', { class: 'grid' }, [thead, tbody]);
  }

  function badge(valid) {
    const v = Number(valid);
    const cls = v === 2 ? 'badge-ok' : v === 1 ? 'badge-warn' : 'badge-bad';
    const text = v === 2 ? '符合' : v === 1 ? '部分符合' : '不符合';
    return el('span', { class: 'badge ' + cls }, [text]);
  }

  function itemsTable(items) {
    return grid([
      { label: '检查项', key: 'name' },
      { label: '值', key: 'value', mono: true },
      { label: '说明', key: 'infoMsg' },
      { label: '检查结果', render: (row) => badge(row.valid) }
    ], items || []);
  }

  function kvTable(pairs) {
    const rows = pairs.filter((p) => p && p[1] !== undefined && p[1] !== null && p[1] !== '');
    return grid([
      { label: '项目', key: 'k' },
      { label: '值', key: 'v', mono: true }
    ], rows.map(([k, v]) => ({ k: k, v: Array.isArray(v) ? (v.length ? v.join(', ') : '（无）') : String(v) })));
  }

  function summaryLine(text, status) {
    const cls = status === 'success' ? 'badge-ok' : status === 'partial' ? 'badge-warn' : 'badge-bad';
    return el('div', { class: 'mt8' }, [
      el('span', { class: 'badge ' + cls }, [STATUS_TEXT[status] || '—']),
      el('span', { class: 'muted' }, ['  ' + (text || '')])
    ]);
  }

  function certInfoTable(info) {
    if (!info) return el('div', { class: 'muted' }, ['暂无证书信息']);
    return kvTable([
      ['版本', info.version],
      ['序列号', info.serial],
      ['使用者', info.subject],
      ['颁发者', info.issuer],
      ['有效期', info.notBefore + ' ~ ' + info.notAfter + '（剩余 ' + info.daysLeft + ' 天）'],
      ['签名算法', info.sigAlg],
      ['公钥算法', info.pubAlg + (info.curve ? ' / ' + info.curve : '') + ' · ' + info.keyBits + ' 位'],
      ['CA 证书', info.isCa ? '是（pathLen=' + (info.pathLen === null ? '不限制' : info.pathLen) + '）' : '否'],
      ['密钥用法', info.keyUsage],
      ['扩展密钥用法', info.eku],
      ['主体备用名', info.san],
      ['SKI / AKI', (info.ski || '-') + ' / ' + (info.aki || '-')],
      ['CRL 地址', info.crlUrls],
      ['OCSP 地址', info.ocspUrls],
      ['SHA256 指纹', info.sha256],
      ['SM3 指纹', info.sm3]
    ]);
  }

  function extTable(exts) {
    if (!exts || !exts.length) return el('div', { class: 'muted' }, ['无扩展项']);
    return grid([
      { label: '扩展项', key: 'name' },
      { label: 'OID', key: 'oid', mono: true },
      { label: '关键', render: (r) => (r.critical ? '是' : '否') },
      { label: '内容', key: 'brief', mono: true }
    ], exts);
  }

  function asn1TreeNode(node, depth) {
    const kids = node.children || [];
    const collapsed = depth >= 2 && kids.length > 0;
    const row = el('div', { class: 'tree-row', style: 'cursor:' + (kids.length ? 'pointer' : 'default') });
    const toggle = el('span', { class: 'tree-type' }, [((kids.length ? (collapsed ? '▸ ' : '▾ ') : '· ')) + node.type]);
    row.appendChild(toggle);
    if (node.value) row.appendChild(el('span', { class: 'tree-value' }, ['  ' + node.value]));
    row.appendChild(el('span', { class: 'muted' }, ['  [' + node.contentLength + ' 字节]']));
    const box = el('div', { class: 'tree-children' });
    if (kids.length) {
      kids.forEach((k) => box.appendChild(asn1TreeNode(k, depth + 1)));
      if (collapsed) box.style.display = 'none';
      row.addEventListener('click', () => {
        const open = box.style.display !== 'none';
        box.style.display = open ? 'none' : '';
        toggle.textContent = (open ? '▸ ' : '▾ ') + node.type;
      });
    }
    return el('div', {}, [row, box]);
  }

  function pemBlocks(text) {
    const m = String(text || '').match(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g);
    return m || [];
  }

  /* =======================================================================
   * 1) 证书格式检查（含证书链）
   * ===================================================================== */
  const chainUI = (function () {
    let wrapEl = null;
    let ctxRef = null;
    let formatBox = null;
    let chainBox = null;
    let formatData = null;
    let chainData = null;
    let counter = 1;

    function defaultNodes() {
      return [
        { nodeId: 'root-1', parentId: null, name: '根证书', cert: '', certFormat: 'PEM' },
        { nodeId: 'intermediate-1', parentId: 'root-1', name: '中间证书', cert: '', certFormat: 'PEM' },
        { nodeId: 'terminal-1', parentId: 'intermediate-1', name: '终端证书', cert: '', certFormat: 'PEM' }
      ];
    }

    function list(ctx) {
      if (!Array.isArray(ctx.state.chainNodes) || !ctx.state.chainNodes.length) {
        ctx.state.chainNodes = defaultNodes();
        ctx.state.selectedNode = ctx.state.selectedNode || 'terminal-1';
      }
      return ctx.state.chainNodes;
    }

    function current(ctx) {
      const all = list(ctx);
      return all.find((n) => n.nodeId === ctx.state.selectedNode) || all[all.length - 1];
    }

    function childrenOf(all, id) {
      return all.filter((n) => n.parentId === id);
    }

    function syncFromState(ctx) {
      const node = current(ctx);
      if (!node) return;
      node.cert = ctx.state.cert || '';
      node.certFormat = ctx.state.certFormat || 'PEM';
      if (ctx.state.nodeName) node.name = ctx.state.nodeName;
    }

    function selectNode(ctx, id) {
      syncFromState(ctx);
      ctx.state.selectedNode = id;
      const node = current(ctx);
      ctx.state.cert = node.cert || '';
      ctx.state.certFormat = node.certFormat || 'PEM';
      ctx.state.nodeName = node.name || '';
      // 切换节点后展示该节点自己的验证结果，避免显示上一个节点的数据
      formatData = node.formatData || null;
      chainData = node.chainData || null;
      draw();
      setFormatBox();
      setChainBox();
    }

    function statusBadge(status, emptyText) {
      if (!status) return el('span', { class: 'badge' }, [emptyText || '未校验']);
      const cls = status === 'success' ? 'badge-ok' : status === 'partial' ? 'badge-warn' : 'badge-bad';
      return el('span', { class: 'badge ' + cls }, [STATUS_TEXT[status] || status]);
    }

    function drawRow(all, node, depth, container) {
      const active = ctxRef.state.selectedNode === node.nodeId;
      const row = el('div', {
        class: 'tree-row',
        style: 'cursor:pointer;padding:6px 8px;border-radius:6px;display:flex;gap:8px;align-items:center;' +
          (active ? 'background:#eef4ff;border:1px solid #c7dbff;' : 'border:1px solid transparent;')
      }, [
        el('span', { style: 'width:' + (depth * 14) + 'px;display:inline-block' }),
        el('span', { class: node.cert ? 'mono' : 'muted' }, [(node.cert ? '▣ ' : '▢ ') + (node.name || node.nodeId)]),
        statusBadge(node.formatStatus, '格式未校验'),
        statusBadge(node.chainStatus, '链路未校验')
      ]);
      row.addEventListener('click', (e) => {
        e.stopPropagation();
        selectNode(ctxRef, node.nodeId);
      });
      container.appendChild(row);
      childrenOf(all, node.nodeId).forEach((child) => drawRow(all, child, depth + 1, container));
    }

    function button(text, onClick) {
      const btn = el('button', { type: 'button', class: 'btn btn-ghost btn-mini' }, [text]);
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        onClick();
      });
      return btn;
    }

    function draw() {
      if (!wrapEl || !ctxRef) return;
      const ctx = ctxRef;
      const all = list(ctx);
      const node = current(ctx);
      wrapEl.innerHTML = '';

      const toolbar = el('div', { class: 'input-bar', style: 'gap:6px;flex-wrap:wrap' }, [
        button('新增同级节点', () => {
          if (!node.parentId) { CB.toast('根节点不支持新增同级节点', 'warn'); return; }
          syncFromState(ctx);
          const id = 'node-' + Date.now() + '-' + (counter++);
          all.push({ nodeId: id, parentId: node.parentId, name: '证书节点 ' + counter, cert: '', certFormat: 'PEM' });
          ctx.state.selectedNode = id;
          ctx.state.cert = '';
          ctx.state.nodeName = '证书节点 ' + counter;
          draw();
        }),
        button('新增子节点', () => {
          syncFromState(ctx);
          const id = 'node-' + Date.now() + '-' + (counter++);
          all.push({ nodeId: id, parentId: node.nodeId, name: '证书节点 ' + counter, cert: '', certFormat: 'PEM' });
          ctx.state.selectedNode = id;
          ctx.state.cert = '';
          ctx.state.nodeName = '证书节点 ' + counter;
          draw();
        }),
        button('删除当前节点', () => {
          if (!node.parentId) { CB.toast('根节点不允许删除', 'warn'); return; }
          const remove = new Set([node.nodeId]);
          let grew = true;
          while (grew) {
            grew = false;
            all.forEach((n) => {
              if (n.parentId && remove.has(n.parentId) && !remove.has(n.nodeId)) { remove.add(n.nodeId); grew = true; }
            });
          }
          ctx.state.chainNodes = all.filter((n) => !remove.has(n.nodeId));
          ctx.state.selectedNode = node.parentId;
          const next = current(ctx);
          ctx.state.cert = next.cert || '';
          ctx.state.certFormat = next.certFormat || 'PEM';
          ctx.state.nodeName = next.name || '';
          CB.toast('节点已删除', 'success');
          draw();
        }),
        button('清空当前节点', () => {
          node.cert = '';
          node.formatStatus = null;
          node.chainStatus = null;
          node.formatResults = null;
          node.chainResults = null;
          node.formatData = null;
          node.chainData = null;
          ctx.state.cert = '';
          formatData = null;
          chainData = null;
          draw();
          setFormatBox();
          setChainBox();
          CB.toast('当前节点已清空', 'success');
        }),
        button('重置证书链', () => {
          ctx.state.chainNodes = defaultNodes();
          ctx.state.selectedNode = 'terminal-1';
          ctx.state.cert = '';
          ctx.state.certFormat = 'PEM';
          ctx.state.nodeName = '终端证书';
          formatData = null;
          chainData = null;
          draw();
          CB.toast('证书链树已重置', 'success');
        })
      ]);
      wrapEl.appendChild(toolbar);

      const treeBox = el('div', {
        style: 'border:1px solid var(--border);border-radius:8px;padding:8px;max-height:260px;overflow:auto;background:#fbfcfe'
      });
      const roots = all.filter((n) => !n.parentId || !all.some((x) => x.nodeId === n.parentId));
      (roots.length ? roots : all).forEach((root) => drawRow(all, root, 0, treeBox));
      wrapEl.appendChild(treeBox);

      const editor = el('div', { style: 'margin-top:10px;display:grid;gap:8px' });
      const nameInput = el('input', { class: 'input', 'data-field': 'nodeName', placeholder: '节点名称' });
      nameInput.value = node.name || '';
      nameInput.addEventListener('input', () => {
        node.name = nameInput.value;
        ctx.state.nodeName = nameInput.value;
      });
      const fmtSel = el('select', { class: 'input', 'data-field': 'certFormat' });
      FORMATS.forEach(([v, l]) => fmtSel.appendChild(el('option', { value: v, selected: (node.certFormat || 'PEM') === v }, [l])));
      fmtSel.addEventListener('change', () => {
        node.certFormat = fmtSel.value;
        ctx.state.certFormat = fmtSel.value;
      });
      const fileInput = el('input', { type: 'file', accept: '.pem,.cer,.crt,.der,.txt', style: 'display:none' });
      const fileBtn = button('上传证书文件', () => fileInput.click());
      fileInput.addEventListener('change', async () => {
        const f = fileInput.files && fileInput.files[0];
        if (!f) return;
        const text = (await f.text()).trim();
        const isPem = text.indexOf('-----BEGIN') >= 0;
        node.cert = text;
        node.certFormat = isPem ? 'PEM' : 'BASE64';
        ctx.state.cert = node.cert;
        ctx.state.certFormat = node.certFormat;
        draw();
        CB.toast('已载入 ' + f.name, 'success');
      });

      editor.appendChild(el('div', { class: 'input-bar' }, [nameInput, fmtSel, fileBtn, fileInput]));
      const ta = el('textarea', {
        class: 'textarea', rows: 6, 'data-field': 'cert', spellcheck: 'false',
        placeholder: '粘贴当前节点的证书内容（PEM 整段 / 十六进制 / Base64）'
      });
      ta.value = node.cert || '';
      ta.addEventListener('input', () => {
        node.cert = ta.value;
        ctx.state.cert = ta.value;
      });
      editor.appendChild(ta);
      wrapEl.appendChild(editor);
    }

    function mount(wrap, ctx) {
      wrapEl = wrap;
      ctxRef = ctx;
      if (!ctx.state.selectedNode) ctx.state.selectedNode = 'terminal-1';
      const node = current(ctx);
      ctx.state.cert = node.cert || '';
      ctx.state.certFormat = node.certFormat || 'PEM';
      ctx.state.nodeName = node.name || '';
      draw();
    }

    function section(title, nodes) {
      const box = el('div', { class: 'mt12' });
      box.appendChild(el('div', {
        class: 'card-title',
        style: 'margin-bottom:6px;padding-bottom:4px;border-bottom:1px solid var(--border)'
      }, [title]));
      nodes.forEach((n) => box.appendChild(n));
      return box;
    }

    function setFormatBox() {
      if (!formatBox) return;
      formatBox.innerHTML = '';
      if (!formatData) {
        formatBox.appendChild(el('div', { class: 'muted' }, ['暂无格式验证结果，请选择节点后点击“格式验证”']));
        return;
      }
      const name = formatData.nodeName ||
        (ctxRef ? ((current(ctxRef) || {}).name || '') : '');
      formatBox.appendChild(el('div', { class: 'mt8 mono' }, ['节点：' + (name || '未命名节点')]));
      formatBox.appendChild(summaryLine(formatData.summary, formatData.status));
      formatBox.appendChild(section('证书信息', [certInfoTable(formatData.cert)]));
      formatBox.appendChild(section('检查项（' + ((formatData.items || []).length) + ' 项）', [itemsTable(formatData.items)]));
      formatBox.appendChild(section('扩展项（' + (((formatData.cert || {}).extensions || []).length) + ' 项）',
        [extTable((formatData.cert || {}).extensions)]));
    }

    function setChainBox() {
      if (!chainBox) return;
      chainBox.innerHTML = '';
      if (!chainData) {
        chainBox.appendChild(el('div', { class: 'muted' }, ['暂无证书链验证结果，请点击“证书链验证”']));
        return;
      }
      chainBox.appendChild(summaryLine(chainData.message, chainData.passed ? 'success' : 'error'));
      (chainData.nodeResults || []).forEach((res) => {
        const card = el('div', { style: 'border:1px solid var(--border);border-radius:8px;padding:8px;margin-top:10px' });
        card.appendChild(el('div', { class: 'mono' }, [(res.uploaded ? '▣ ' : '▢ ') + res.name]));
        card.appendChild(summaryLine(res.chainSummary, res.status));
        card.appendChild(el('div', { class: 'mt8' }, [itemsTable(res.chainResults)]));
        chainBox.appendChild(card);
      });
    }

    return {
      mount: mount,
      draw: draw,
      list: list,
      current: current,
      setFormatData: (d) => { formatData = d; setFormatBox(); },
      setChainData: (d) => { chainData = d; setChainBox(); },
      setBox: (kind, node) => {
        if (kind === 'format') { formatBox = node; setFormatBox(); }
        else { chainBox = node; setChainBox(); }
      },
      resetBoxes: () => { formatData = null; chainData = null; setFormatBox(); setChainBox(); }
    };
  })();

  CB.register({
    key: 'cert/format/check',
    cat: 'cert',
    title: '证书格式检查',
    desc: '解析 X.509 证书并逐项校验（版本、序列号、时间格式、密钥用法、SAN 等），支持多级证书链构建与签名关系验证',
    help: [
      { title: '证书格式', items: ['支持 PEM（含多段）、十六进制、Base64 三种输入格式。', '根证书、中间证书、终端证书可分别上传到对应节点。'] },
      { title: '证书链验证', items: ['按“根证书 → 中间证书 → 终端证书”建立节点关系后点击“证书链验证”。', '根节点做自签校验，其余节点校验颁发者匹配、签名关系、CA 约束与路径长度。', '批量导入框可一次粘贴多张 PEM 证书，按 根 → 终端 顺序自动建立节点。'] },
      { title: '检查结果', items: ['符合：符合规范要求；部分符合：可以解析但存在改进项；不符合：存在规范性问题。'] }
    ],
    state: {
      cert: '', certFormat: 'PEM', nodeName: '',
      chainCerts: '', chainCertsFormat: 'PEM',
      chainNodes: null, selectedNode: 'terminal-1'
    },
    fields: [
      {
        name: 'chainCerts', label: '证书链批量导入（可选）', type: 'textarea', rows: 4, span: 2,
        placeholder: '按 根证书 → 中间证书 → 终端证书 顺序粘贴多张证书（PEM 多段），随后点击“证书链验证”'
      },
      { name: 'chainCertsFormat', label: '导入格式', type: 'select', options: FORMATS },
      { type: 'custom', name: 'chainTree', span: 2, render: (wrap, ctx) => chainUI.mount(wrap, ctx) }
    ],
    actions: [
      {
        name: 'formatCheck', label: '格式验证', primary: true,
        run: async (ctx) => {
          const node = chainUI.current(ctx);
          if (!node || !String(node.cert || '').trim()) {
            CB.toast('请先为当前节点上传证书', 'warn');
            return;
          }
          const data = await CB.api('/api/cert/format/check', { cert: node.cert, certFormat: node.certFormat });
          node.formatResults = data.items;
          node.formatStatus = data.status;
          node.formatSummary = data.summary;
          node.formatData = Object.assign({}, data, { nodeName: node.name || '' });
          chainUI.draw();
          chainUI.setFormatData(node.formatData);
          CB.toast(data.status === 'success' ? '格式验证完成：全部符合' : '格式验证完成：存在需关注项', data.status === 'error' ? 'warn' : 'success');
        }
      },
      {
        name: 'chainCheck', label: '证书链验证',
        run: async (ctx) => {
          const bulk = String(ctx.val('chainCerts') || '').trim();
          if (bulk) {
            const blocks = pemBlocks(bulk);
            if (blocks.length > 1) {
              ctx.state.chainNodes = blocks.map((pem, idx) => ({
                nodeId: 'chain-' + (idx + 1),
                parentId: idx === 0 ? null : 'chain-' + idx,
                name: idx === 0 ? '根证书' : (idx === blocks.length - 1 ? '终端证书' : '中间证书 ' + idx),
                cert: pem,
                certFormat: 'PEM'
              }));
              ctx.state.selectedNode = 'chain-' + blocks.length;
            } else {
              const node = chainUI.current(ctx);
              if (node) {
                node.cert = blocks[0] || bulk;
                node.certFormat = blocks.length ? 'PEM' : (ctx.val('chainCertsFormat') || 'BASE64');
                ctx.state.cert = node.cert;
                ctx.state.certFormat = node.certFormat;
              }
            }
            chainUI.resetBoxes();
            chainUI.draw();
          }
          const nodes = chainUI.list(ctx);
          if (!nodes.some((n) => String(n.cert || '').trim())) {
            CB.toast('请先为证书节点上传证书', 'warn');
            return;
          }
          const payload = {
            nodes: nodes.map((n) => ({
              nodeId: n.nodeId, parentId: n.parentId, name: n.name, cert: n.cert, certFormat: n.certFormat
            }))
          };
          const data = await CB.api('/api/cert/chain/check', payload);
          (data.nodeResults || []).forEach((res) => {
            const node = nodes.find((n) => n.nodeId === res.nodeId);
            if (!node) return;
            node.chainResults = res.chainResults;
            node.chainStatus = res.status;
            node.chainSummary = res.chainSummary;
            node.chainData = data;
          });
          chainUI.draw();
          chainUI.setChainData(data);
          CB.toast(data.passed ? '证书链验证通过' : '证书链验证存在异常项', data.passed ? 'success' : 'warn');
        }
      }
    ],
    results: [
      {
        name: 'formatResult', label: '格式验证结果', type: 'custom',
        render: (box) => {
          const inner = el('div', { 'data-result': 'formatResult' });
          box.appendChild(inner);
          chainUI.setBox('format', inner);
        }
      },
      {
        name: 'chainResult', label: '证书链验证结果', type: 'custom',
        render: (box) => {
          const inner = el('div', { 'data-result': 'chainResult' });
          box.appendChild(inner);
          chainUI.setBox('chain', inner);
        }
      }
    ],
    samples: {
      formatCheck: { cert: SAMPLE.sm2Leaf, certFormat: 'PEM' },
      chainCheck: { chainCerts: SAMPLE.sm2Root + '\n' + SAMPLE.sm2Leaf, chainCertsFormat: 'PEM' }
    },
    onClear: (ctx) => {
      ctx.state.chainNodes = null;
      ctx.state.selectedNode = 'terminal-1';
      chainUI.resetBoxes();
    }
  });

  /* =======================================================================
   * 2) 证书撤销检查（CRL / OCSP）
   * ===================================================================== */
  const statusUI = { box: null };

  function drawStatus(data, mode) {
    if (!statusUI.box) return;
    statusUI.box.innerHTML = '';
    const items = data.items || [];
    if (mode === 'CRL') {
      statusUI.box.appendChild(summaryLine(data.crlVerifyMsg, data.crlVerifyResult ? 'success' : 'error'));
      statusUI.box.appendChild(el('div', { class: 'mt8 mono' }, [data.crlRevokeMsg || '']));
      const info = data.crlInfo || {};
      statusUI.box.appendChild(el('div', { class: 'mt12' }, [
        kvTable([
          ['CRL 颁发者', info.issuer],
          ['本次更新', info.thisUpdate],
          ['下次更新', info.nextUpdate],
          ['签名算法', info.sigAlg],
          ['吊销条目', info.entryCount],
          ['SM3 指纹', info.fingerprintSm3]
        ])
      ]));
    } else {
      const info = data.ocspInfo || {};
      statusUI.box.appendChild(summaryLine(data.ocspStatusMsg, data.status));
      statusUI.box.appendChild(el('div', { class: 'mt8 mono' }, [data.ocspVerifyMsg || '']));
      statusUI.box.appendChild(el('div', { class: 'mt12' }, [
        kvTable([
          ['响应状态', info.responseStatus],
          ['证书状态', info.certificateStatus],
          ['序列号', info.serial],
          ['本次更新', info.thisUpdate],
          ['下次更新', info.nextUpdate],
          ['生成时间', info.producedAt],
          ['响应者', info.responder],
          ['签名算法', info.signatureAlg]
        ])
      ]));
    }
    statusUI.box.appendChild(el('div', { class: 'mt12' }, [itemsTable(items)]));
  }

  CB.register({
    key: 'cert/status/check',
    cat: 'cert',
    title: '数字证书状态检查',
    desc: '解析 CRL 并判断证书是否被吊销；离线解析并验证 OCSP 响应（本工具不联网）',
    help: [
      { title: 'CRL 验证', items: ['粘贴待校验证书与 CRL，按序列号比对吊销状态。', '若 CRL 颁发者与证书颁发者不一致，则该 CRL 不适用于此证书。'] },
      { title: 'OCSP 验证', items: ['离线版不支持联网查询 OCSP 地址。', '请把 OCSP 服务返回的响应（DER / Base64 / PEM）粘贴到“OCSP 响应”框，工具会验证响应签名与证书状态。', '只填写 OCSP 地址时会提示离线限制。'] }
    ],
    state: {
      cert: '', certFormat: 'PEM', crl: '', crlFormat: 'PEM',
      ocspResponse: '', ocspResponseFormat: 'BASE64', ocspAddress: '', hashType: 'SM3'
    },
    fields: [
      { name: 'cert', label: '待校验证书', type: 'textarea', rows: 6, span: 2, placeholder: '粘贴证书（PEM / 十六进制 / Base64）' },
      { name: 'certFormat', label: '证书格式', type: 'select', options: FORMATS },
      { name: 'crl', label: 'CRL 吊销列表', type: 'textarea', rows: 6, span: 2, placeholder: '粘贴 CRL（PEM / 十六进制 / Base64）' },
      { name: 'crlFormat', label: 'CRL 格式', type: 'select', options: FORMATS },
      { name: 'ocspResponse', label: 'OCSP 响应（离线）', type: 'textarea', rows: 6, span: 2, placeholder: '粘贴 OCSP 响应：DER 的十六进制 / Base64，或 PEM' },
      { name: 'ocspResponseFormat', label: 'OCSP 响应格式', type: 'select', options: FORMATS },
      { name: 'ocspAddress', label: 'OCSP 地址（仅提示）', type: 'input', placeholder: 'http://ocsp.example.com（离线版不联网）' },
      { name: 'hashType', label: '摘要算法', type: 'select', options: [['SM3', 'SM3'], ['SHA1', 'SHA-1'], ['SHA256', 'SHA-256']] }
    ],
    actions: [
      {
        name: 'crlCheck', label: '证书 CRL 验证', primary: true,
        run: async (ctx) => {
          if (!String(ctx.val('cert') || '').trim()) { CB.toast('请输入待校验证书', 'warn'); return; }
          if (!String(ctx.val('crl') || '').trim()) { CB.toast('请输入 CRL 内容', 'warn'); return; }
          const data = await CB.api('/api/cert/status/check', {
            mode: 'CRL', cert: ctx.val('cert'), certFormat: ctx.val('certFormat'),
            crl: ctx.val('crl'), crlFormat: ctx.val('crlFormat')
          });
          ctx.setResult('statusDetail', (data.crlVerifyMsg || '') + '\n' + (data.crlRevokeMsg || ''));
          drawStatus(data, 'CRL');
          CB.toast(data.revoked ? '证书已吊销' : '证书未被吊销', data.revoked ? 'warn' : 'success');
        }
      },
      {
        name: 'ocspCheck', label: '证书 OCSP 验证',
        run: async (ctx) => {
          const resp = String(ctx.val('ocspResponse') || '').trim();
          if (!resp) {
            CB.toast('离线版不支持联网查询 OCSP，请粘贴 OCSP 响应', 'warn');
            return;
          }
          const data = await CB.api('/api/cert/status/check', {
            mode: 'OCSP', cert: ctx.val('cert'), certFormat: ctx.val('certFormat'),
            ocspResponse: resp, ocspResponseFormat: ctx.val('ocspResponseFormat'),
            ocspAddress: ctx.val('ocspAddress'), hashType: ctx.val('hashType')
          });
          ctx.setResult('statusDetail', (data.ocspVerifyMsg || '') + '\n' + (data.ocspStatusMsg || ''));
          drawStatus(data, 'OCSP');
          CB.toast('OCSP 状态：' + data.ocspStatus, data.status === 'error' ? 'warn' : 'success');
        }
      }
    ],
    results: [
      {
        name: 'statusTable', label: '状态检查结果', type: 'custom',
        render: (box) => {
          const inner = el('div', { 'data-result': 'statusTable' }, [el('div', { class: 'muted' }, ['暂无结果'])]);
          box.appendChild(inner);
          statusUI.box = inner;
        }
      },
      { name: 'statusDetail', label: '结论说明', type: 'textarea', rows: 4 }
    ],
    samples: {
      crlCheck: { cert: SAMPLE.sm2Leaf, certFormat: 'PEM', crl: SAMPLE.crlSm2, crlFormat: 'PEM' },
      ocspCheck: { cert: SAMPLE.rsaLeaf, certFormat: 'PEM', ocspResponse: SAMPLE.ocspRsaB64, ocspResponseFormat: 'BASE64' }
    }
  });

  /* =======================================================================
   * 3) CRL 有效性校验
   * ===================================================================== */
  const crlUI = { box: null };

  CB.register({
    key: 'crl/status/check',
    cat: 'cert',
    title: 'CRL 格式校验',
    desc: '解析 CRL 的颁发者、更新时间与吊销条目，并用上级证书公钥验证 CRL 签名（SM2/SM3 与 RSA/SHA256）',
    help: [
      { title: '使用说明', items: ['CRL 可粘贴 PEM 或十六进制、Base64。', '填写“上级证书”后将校验 CRL 颁发者是否匹配，并使用其公钥验证 CRL 签名。', 'CRL 已过期或签名不匹配时判定为无效。'] }
    ],
    state: { crl: '', crlFormat: 'PEM', baseCert: '', baseCertFormat: 'PEM' },
    fields: [
      { name: 'crl', label: '待校验 CRL', type: 'textarea', rows: 6, span: 2, placeholder: '粘贴 CRL（PEM / 十六进制 / Base64）' },
      { name: 'crlFormat', label: 'CRL 格式', type: 'select', options: FORMATS },
      { name: 'baseCert', label: '上级证书（用于验签）', type: 'textarea', rows: 6, span: 2, placeholder: '粘贴签发该 CRL 的 CA 证书' },
      { name: 'baseCertFormat', label: '上级证书格式', type: 'select', options: FORMATS }
    ],
    actions: [
      {
        name: 'verify', label: 'CRL 有效性验证', primary: true,
        run: async (ctx) => {
          if (!String(ctx.val('crl') || '').trim()) { CB.toast('请输入待校验 CRL', 'warn'); return; }
          const data = await CB.api('/api/cert/crl/status/check', {
            crl: ctx.val('crl'), crlFormat: ctx.val('crlFormat'),
            baseCert: ctx.val('baseCert'), baseCertFormat: ctx.val('baseCertFormat')
          });
          ctx.setResult('crlText', data.crlInfoText || '');
          if (crlUI.box) {
            crlUI.box.innerHTML = '';
            crlUI.box.appendChild(summaryLine(data.msg, data.valid ? 'success' : 'error'));
            crlUI.box.appendChild(el('div', { class: 'mt12' }, [itemsTable(data.items)]));
          }
          CB.toast(data.valid ? 'CRL 有效性验证通过' : 'CRL 有效性验证存在异常', data.valid ? 'success' : 'warn');
        }
      }
    ],
    results: [
      {
        name: 'crlResult', label: '有效性验证结果', type: 'custom',
        render: (box) => {
          const inner = el('div', { 'data-result': 'crlResult' }, [el('div', { class: 'muted' }, ['暂无结果'])]);
          box.appendChild(inner);
          crlUI.box = inner;
        }
      },
      { name: 'crlText', label: 'CRL 信息', type: 'textarea', rows: 10 }
    ],
    samples: {
      verify: { crl: SAMPLE.crlSm2, crlFormat: 'PEM', baseCert: SAMPLE.sm2Root, baseCertFormat: 'PEM' }
    }
  });

  /* =======================================================================
   * 4) 证书签发（CSR / 证书 / PFX）
   * ===================================================================== */
  CB.register({
    key: 'cert/sign/issue',
    cat: 'cert',
    title: '证书签发',
    desc: '生成 SM2 / RSA 密钥与 CSR，使用内置本地 CA 签发证书，支持 P10 请求签发与 PKCS#12 打包',
    help: [
      { title: '本地 CA', items: ['首次使用时在 data/local_ca/ 下自动生成 SM2 与 RSA 两套根 CA 并持久化。', '所有签发均在本地完成，根 CA 私钥不出本机。'] },
      { title: '证书类型', items: ['CA中间证书：basicConstraints CA=TRUE、keyUsage 含 keyCertSign，可继续签发下级。', 'SSL证书：含 SAN、serverAuth/clientAuth，适用于 TLS 服务端。', '用户证书：含 clientAuth/emailProtection，适用于终端用户。'] },
      { title: 'PKCS#12', items: ['RSA 密钥可打包为 PFX（.pfx/.p12，DER 的 Base64 文本）。', '当前离线环境的 cryptography 不支持 SM2 私钥的 PKCS#12 打包，SM2 场景会给出 OpenSSL 转换提示。', '提交 P10 请求签发时，由于本地不持有私钥，无法生成 PFX。'] }
    ],
    state: {
      citem: 'CN', cnitem: '', sitem: '', litem: '', ouitem: '', oitem: '',
      emailAddress: '', algorithm: 'SM2', keyLength: 2048, signAlg: 'SHA256withRSA',
      certType: 'SSL', months: 12, san: '', csr: '', csrFormat: 'PEM',
      withPfx: false, pfxPassword: ''
    },
    fields: [
      { name: 'citem', label: '国家/C', type: 'input', placeholder: 'CN' },
      { name: 'cnitem', label: '主题名称/CN', type: 'input', placeholder: 'example.com' },
      { name: 'sitem', label: '省份/ST', type: 'input', placeholder: 'Zhejiang（可选）' },
      { name: 'litem', label: '城市/L', type: 'input', placeholder: 'Wenzhou（可选）' },
      { name: 'ouitem', label: '部门/OU', type: 'input', placeholder: '（可选）' },
      { name: 'oitem', label: '组织/O', type: 'input', placeholder: '（可选）' },
      { name: 'emailAddress', label: '邮箱/EmailAddress', type: 'input', placeholder: '（可选）' },
      { name: 'algorithm', label: '证书算法', type: 'radio', options: [['SM2', 'SM2'], ['RSA', 'RSA']], span: 2 },
      {
        name: 'keyLength', label: '密钥长度', type: 'radio', show: (v) => v.algorithm === 'RSA',
        options: [['1024', '1024'], ['2048', '2048'], ['3072', '3072'], ['4096', '4096']]
      },
      {
        name: 'signAlg', label: '签名算法', type: 'select', show: (v) => v.algorithm === 'RSA',
        options: [['SHA256withRSA', 'SHA256withRSA'], ['SHA384withRSA', 'SHA384withRSA'], ['SHA512withRSA', 'SHA512withRSA'], ['SM3withRSA', 'SM3withRSA']]
      },
      { name: 'certType', label: '证书类型', type: 'radio', options: [['CA', 'CA中间证书'], ['SSL', 'SSL证书'], ['USER', '用户证书']], span: 2 },
      { name: 'months', label: '有效期（月）', type: 'number', min: 1, max: 120 },
      { name: 'san', label: '备用名 SAN', type: 'input', placeholder: '多个用逗号分隔，留空则使用 CN' },
      { name: 'csr', label: '提交证书请求 P10（可选）', type: 'textarea', rows: 5, span: 2, placeholder: '粘贴 CSR（PEM / Base64 / 十六进制），填写后将按 CSR 的主题与公钥签发' },
      { name: 'csrFormat', label: 'CSR 格式', type: 'select', options: FORMATS },
      { name: 'withPfx', label: '直接生成 PFX 证书', type: 'checkbox', text: '生成 PKCS#12（仅 RSA 私钥可打包）' },
      { name: 'pfxPassword', label: 'PFX 保护口令', type: 'input', placeholder: '留空则不加密' }
    ],
    actions: [
      {
        name: 'genCsr', label: '生成 CSR', primary: true,
        run: async (ctx) => {
          const data = await CB.api('/api/cert/sign/issue', {
            action: 'csr', citem: ctx.val('citem'), cnitem: ctx.val('cnitem'), sitem: ctx.val('sitem'),
            litem: ctx.val('litem'), ouitem: ctx.val('ouitem'), oitem: ctx.val('oitem'),
            emailAddress: ctx.val('emailAddress'), algorithm: ctx.val('algorithm'),
            keyLength: Number(ctx.val('keyLength') || 2048), signAlg: ctx.val('signAlg')
          });
          ctx.setResult('csr', data.csr);
          ctx.setResult('privateKey', data.privateKey);
          ctx.setResult('publicKey', data.publicKey);
          ctx.setResult('note', '算法：' + data.algorithm + ' / ' + data.keyBits + ' 位；签名算法：' + data.signAlg +
            '；CSR 自签名校验：' + (data.signatureValid ? '通过' : '未通过') + '；SM3 指纹：' + data.sm3);
          CB.toast('CSR 生成成功', 'success');
        }
      },
      {
        name: 'issueCert', label: '签发证书',
        run: async (ctx) => {
          const data = await CB.api('/api/cert/sign/issue', {
            action: 'issue', citem: ctx.val('citem'), cnitem: ctx.val('cnitem'), sitem: ctx.val('sitem'),
            litem: ctx.val('litem'), ouitem: ctx.val('ouitem'), oitem: ctx.val('oitem'),
            emailAddress: ctx.val('emailAddress'), algorithm: ctx.val('algorithm'),
            keyLength: Number(ctx.val('keyLength') || 2048), signAlg: ctx.val('signAlg'),
            certType: ctx.val('certType'), months: Number(ctx.val('months') || 12),
            san: ctx.val('san'), csr: ctx.val('csr'), csrFormat: ctx.val('csrFormat'), withPfx: false
          });
          ctx.setResult('cert', data.cert);
          ctx.setResult('chain', data.chain);
          ctx.setResult('privateKey', data.privateKey || '');
          ctx.setResult('publicKey', data.publicKey || '');
          ctx.setResult('csr', data.keySource === 'CSR' ? String(ctx.val('csr') || '') : '');
          ctx.setResult('note', '证书类型：' + data.certType + '；签名算法：' + data.signAlg + '；序列号：' + data.serial +
            '；有效期：' + data.notBefore + ' ~ ' + data.notAfter + '；密钥来源：' + data.keySource +
            '；签发签名校验：' + (data.signatureValid ? '通过' : '未通过') + '；CA：' + data.caFamily);
          CB.toast('证书签发成功', 'success');
        }
      },
      {
        name: 'issuePfx', label: '生成 PFX 证书',
        run: async (ctx) => {
          const data = await CB.api('/api/cert/sign/issue', {
            action: 'issue', citem: ctx.val('citem'), cnitem: ctx.val('cnitem'), sitem: ctx.val('sitem'),
            litem: ctx.val('litem'), ouitem: ctx.val('ouitem'), oitem: ctx.val('oitem'),
            emailAddress: ctx.val('emailAddress'), algorithm: ctx.val('algorithm'),
            keyLength: Number(ctx.val('keyLength') || 2048), signAlg: ctx.val('signAlg'),
            certType: ctx.val('certType'), months: Number(ctx.val('months') || 12),
            san: ctx.val('san'), withPfx: true, pfxPassword: ctx.val('pfxPassword')
          });
          ctx.setResult('cert', data.cert);
          ctx.setResult('chain', data.chain);
          ctx.setResult('privateKey', data.privateKey || '');
          ctx.setResult('csr', '');
          ctx.setResult('pfx', data.pfx || '');
          ctx.setResult('note', (data.pfxMsg || '') + (data.pfxLength ? '（' + data.pfxLength + ' 字节，口令：' + (data.pfxPassword || '无') + '）' : ''));
          CB.toast(data.pfx ? 'PFX 打包成功' : 'PFX 未生成，请查看说明', data.pfx ? 'success' : 'warn');
        }
      }
    ],
    results: [
      { name: 'csr', label: '证书请求 CSR', type: 'textarea', rows: 8 },
      { name: 'privateKey', label: '私钥（PEM，请妥善保管）', type: 'textarea', rows: 8 },
      { name: 'publicKey', label: '公钥（PEM）', type: 'textarea', rows: 6 },
      { name: 'cert', label: '签发证书', type: 'textarea', rows: 8 },
      { name: 'chain', label: '证书链（证书 + CA）', type: 'textarea', rows: 8 },
      { name: 'pfx', label: 'PFX（PKCS#12 · Base64）', type: 'textarea', rows: 6 },
      { name: 'note', label: '签发说明', type: 'text' }
    ],
    samples: {
      genCsr: { citem: 'CN', cnitem: 'csr.example.com', oitem: 'CipherBox', algorithm: 'SM2' },
      issueCert: { citem: 'CN', cnitem: 'server.example.com', oitem: 'CipherBox', algorithm: 'RSA', keyLength: '2048', certType: 'SSL', months: 12 },
      issuePfx: { citem: 'CN', cnitem: 'pfx.example.com', algorithm: 'RSA', keyLength: '2048', certType: 'SSL', months: 12, pfxPassword: '123456' }
    }
  });

  /* =======================================================================
   * 5) ASN.1 解析
   * ===================================================================== */
  const asn1UI = { box: null };

  CB.register({
    key: 'cert/parse/asn1',
    cat: 'cert',
    title: 'ASN.1 解析',
    desc: '把证书 / CSR / CRL 等 DER 数据解析为 ASN.1 树，逐层展示标签、值、长度与内容',
    help: [
      { title: '使用说明', items: ['支持 PEM、十六进制、Base64 三种输入。', '点击节点可展开 / 收起子节点。', 'hexData 为对应标签的内容字节（十六进制）。'] }
    ],
    state: { cert: '', certFormat: 'PEM' },
    fields: [
      { name: 'cert', label: '待解析数据', type: 'textarea', rows: 8, span: 2, placeholder: '粘贴证书 / CSR / CRL 的 PEM 或 DER 十六进制' },
      { name: 'certFormat', label: '数据格式', type: 'select', options: FORMATS }
    ],
    actions: [
      {
        name: 'parse', label: '解析 ASN.1', primary: true,
        run: async (ctx) => {
          if (!String(ctx.val('cert') || '').trim()) { CB.toast('请输入待解析的数据', 'warn'); return; }
          const data = await CB.api('/api/cert/parse/asn1', { cert: ctx.val('cert'), certFormat: ctx.val('certFormat') });
          ctx.setResult('asn1Text', '格式：' + data.format + '，共 ' + data.length + ' 字节，节点数 ' + data.nodes +
            '，最大深度 ' + data.depth + '\n\n' + data.hex.slice(0, 2000));
          if (asn1UI.box) {
            asn1UI.box.innerHTML = '';
            asn1UI.box.appendChild(el('div', { class: 'tree-node' }, [asn1TreeNode(data.tree, 0)]));
          }
          CB.toast('ASN.1 解析完成', 'success');
        }
      }
    ],
    results: [
      {
        name: 'asn1Tree', label: 'ASN.1 结构树', type: 'custom',
        render: (box) => {
          const inner = el('div', { 'data-result': 'asn1Tree', class: 'tree-node' }, [el('div', { class: 'muted' }, ['暂无结果'])]);
          box.appendChild(inner);
          asn1UI.box = inner;
        }
      },
      { name: 'asn1Text', label: '概览 / 原始数据', type: 'textarea', rows: 8 }
    ],
    samples: { parse: { cert: SAMPLE.sm2Leaf, certFormat: 'PEM' } }
  });
})();
