# 密码工具百宝箱 · 本地版 —— 开发规范（所有模块必须遵守）

## 目标
把 https://cipher.huijusa.cn 的全部工具模块**在本地重新实现**（不含广告、外链、授权校验、公众号推广）。
参考实现（原站编译产物）已下载到 `/root/cipher_probe/chunks/*.js`，每个模块一个文件，可直接阅读其中的字段名、
选项数组、按钮文案与计算参数（压缩过但可读）。

## 技术栈
- 后端：Python 3.14 + Flask（`/opt/cipherbox/.venv`），纯本地计算，禁止访问外网。
- 前端：原生 JS（无构建），hash 路由，所有模块由 `web/modules/*.js` 通过 `CB.register()` 注册。
- 测试：pytest（后端） + jsdom（/E2E，由主控统一执行）。

## 目录与文件归属
```
app/core/*.py     纯计算逻辑        app/api/*.py    Flask 蓝图
web/modules/*.js  前端模块          tests/test_*.py pytest
```
**只允许改动分配给你的文件**；`common.py`、`asn1.py`、`kit.js`、`app.js`、`styles.css`、`server.py`、`index.html`
由主控维护，如需扩展请在自己的文件里实现（或在总结里提出）。

## 后端约定
- 蓝图：`bp = Blueprint("<name>", __name__, url_prefix="/api/<name>")`，已在 `server.py` 的 BLUEPRINTS 注册。
- 统一返回：`from ..core.common import ok, ToolError`；成功 `return ok(data)`；失败 `raise ToolError("中文提示")`
  （全局已捕获并返回 `{"code":1,"msg":...}`）。
- 输入解析一律用 `common.parse_bytes(value, "TEXT"|"HEX"|"BASE64"|"BIN")`，输出用 `common.format_bytes`。
- 异常必须给出中文可读信息；禁止未捕获异常。
- 所有计算必须**真算**：禁止返回固定假数据、禁止调用外部网络、禁止把用户数据写盘。

## 前端约定（必须严格照抄 `web/modules/hashmac.js` 与 `web/modules/other.js` 的写法）
```js
CB.register({
  key: 'group', cat: 'sym', title: '分组密码', desc: '一句话说明',
  help: [{ title: '使用说明', items: ['...'] }],
  state: { /* 初始值 */ },
  fields: [
    { name:'type', label:'算法选择', type:'radio', options:[['SM4','SM4'], ...] },
    { name:'message', label:'输入文本', type:'textarea', formatField:'messageFormat',
      formats:[['TEXT','字符串'],['HEX','十六进制'],['BASE64','Base64']], rows:4, placeholder:'...' },
    { name:'key', label:'密钥', type:'key', formatField:'keyFormat', formats:[['HEX','十六进制'],['BASE64','Base64']],
      random: 16 /* 或 (state)=>state.type==='DES'?8:16 */, placeholder:'请输入 16 字节的密钥' },
    { name:'mode', label:'加密模式', type:'select', options:[['ECB','ECB'], ...], show:(v)=>v.type==='SM4' }
  ],
  actions: [
    { name:'encrypt', label:'加密', primary:true, run: async (ctx) => {
        const data = await CB.api('/api/sym/encrypt', { ... });
        ctx.setResult('cipher', data); CB.toast('加密成功','success');
    } }
  ],
  results: [ { name:'cipher', label:'密文文本', type:'textarea', rows:6 } ],
  samples: { encrypt: { type:'SM4', message:'abc', messageFormat:'TEXT', key:'0123456789abcdeffedcba9876543210', keyFormat:'HEX' } }
});
```
- 字段类型：`radio`(按钮组) / `select` / `textarea` / `input` / `number` / `checkbox` / `file` / `key` / `custom`
  （`custom: {type:'custom', name, render(el, ctx)}`）。
- `ctx`：`val(name)`、`set(name,v)`、`setResult(name,v)`、`result(name)`、`refresh()`、`api(path,payload)`、
  `toast(msg,type)`、`file(name)`（file 字段上传后为 `{name,text,b64,bytes}`）、`payload()`。
- `results` 类型：`textarea`、`json`、`html`、`text`；复杂结果（树、表格、自定义面板）用 `{type:'custom', name, render(el,ctx)}`，
  自行用 `CB.el(...)`、`CB.table(columns, rows)`、`CB.badge(ok)` 构建；结果容器需带 `data-result="<name>"` 以便自动化测试。
- **每个 action 都必须在 `samples` 里给出可用的示例参数**（键名与字段 name 一致，radio 填 value），
  自动化测试会按 sample 填表→点击→断言结果非空。
- 按钮文案、字段文案、选项顺序尽量与原站一致（见 chunk 文件）。

## 测试要求（必须自己跑通）
1. `tests/test_<你的模块>.py`：pytest，用 Flask `app.test_client()` 打接口，覆盖每个 action，含标准向量/往返校验。
2. 运行：`cd /opt/cipherbox && .venv/bin/python -m pytest tests/test_xxx.py -q`
3. 前端至少用 node 语法检查：`node --check web/modules/xxx.js`。

## 质量标准
- 算法实现必须符合标准（GB/T 32905 SM3、GB/T 32907 SM4、GB/T 32918 SM2、GM/T 0044 SM9、GM/T 0001 ZUC、
  RFC 8017 RSA、SEC1/ANSI X9.62 ECDSA、RFC 5280 X.509、RFC 3161 时间戳…）。
- 需要外部库时优先：`gmssl`(sm2/sm3/sm4 单块)、`pycryptodome`、`cryptography`、`asn1crypto`、`pyhanko`、`pypdf`、`dpkt`；
  缺失的算法自己实现并加标准测试向量。
- 前端**不得**出现“广告/公众号/授权/机器码/外链推广”，不得请求非本地地址。

## 参考：模块与 chunk 对照
| 模块 key | 原站 chunk |
|---|---|
| group | GroupView-CPDxYtSp.js |
| seq | SequenceView-xzrdzlhd.js |
| gcm | GcmView-ZMT4aYri.js |
| hash | HashView-BEWbVxum.js（已实现，勿改） |
| mac | MacView-hVSK5fLw.js |
| hash/all | HashAllView-CdFTc52f.js |
| sm2 | SM2View-DNGiaTLl.js |
| sm9 | SM9View-CSY_Cw2C.js |
| rsa | RSAView-ILf9QsII.js |
| ecdsa | ECDSAView-9dZPRVRs.js |
| attach | attachView-DhzS-OrW.js |
| compress | CompressView-B01Gd_68.js |
| cert/format/check | CertFormatCheck-DU7aAm3A.js |
| cert/status/check | CertStatusCheck-zAVY_1zp.js |
| crl/status/check | CrlFormatCheck-C3V19rZ9.js |
| cert/sign/issue | CertSignAndIssue-BGIUnZCs.js |
| cert/parse/asn1 | CertFormatASN1-CKMmipct.js |
| tls | TlsView-Bm6mAExj.js |
| ssh | SshView-DD2Bjk1f.js |
| ipsec | IpsecView-nVgTFJrj.js |
| ukey | UkeyView-ZIT5FLfr.js |
| signatrue | SignatureView-UtLEr-eM.js |
| timestamp | TimestampView-ZkBvfBPt.js |
| prf | prf-DdWp22Vf.js |
| kdf | kdf-4qOD06A-.js |
| tlcp | tlcp-BmyuT4vM.js |
| sm2k | sm2k-DtzHFsuP.js |
| unravelSm2 | unravelSm2-D5dxw5A1.js |
| multiply | multiply-1goxMvPF.js |
| pbkdf2 | pbkdf2-DoEXCfzU.js |
| cipher/mode/detector | CipherModeDetectorView-CCvkBYZE.js |
| scoring | scoringView-DUqczdoU.js |
| randomness | randomness-Cop2MhHP.js |
| length | CipherLengthView-C26Bqw9Z.js |
| big/number | BigNumberView-uqNh6THE.js |
| mod/number | ModView-CUpTh0SE.js |
| xor | XORView-OKKzHAyb.js |
| byte/reverse | ByteReverseView-DR7Nv8hu.js |
| encode | EncodingView-D6MamPW6.js（已实现，勿改） |
