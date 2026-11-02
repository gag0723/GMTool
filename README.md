# 密码工具百宝箱 · 本地版

按 <https://cipher.huijusa.cn> 的全部工具模块实现的**纯本地版本**：不含广告弹窗、公众号推广、外链跳转、机器码授权与联网校验。
所有计算在本机完成，输入数据不会离开设备。

## 启动

源码运行（Linux / macOS / Windows 均可，需 Python 3.13+）：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m waitress --host=0.0.0.0 --port=18080 --call app.server:create_app
# 或直接： ./run.sh
```

内网部署脚本（默认 0.0.0.0:18080）：

```bash
/opt/cipherbox/run.sh                 # 默认 0.0.0.0:18080
CIPHERBOX_PORT=9090 /opt/cipherbox/run.sh
```

浏览器打开 `http://<本机IP>:18080/`。

作为系统服务（OpenRC）：

```bash
rc-service cipherbox start
rc-update add cipherbox default
```

## Windows 运行

**方式一：直接下载独立包（推荐，无需装 Python）**

从 Release 下载 `GMTool-windows-x64.zip`，解压后双击 `start.bat`，浏览器自动打开
`http://127.0.0.1:18080/`。包内已内置 Python 3.13 + 全部依赖。详见 `windows/使用说明.txt`。

**方式二：自行打包独立包**

```bash
./scripts/package_win.sh                    # 产物 dist/cipherbox-windows/ 与 dist/GMTool-windows-x64.zip
FORCE_DOWNLOAD=1 ./scripts/package_win.sh   # 重新下载内嵌 Python 与 wheels
```

脚本会下载 Windows embeddable Python（默认 3.13.9）与 win_amd64 依赖 wheels，组装成
`GMTool/` 目录并压缩（UTF-8 文件名，中文不乱码）；`start.bat` 自动转为 CRLF 行尾。

**方式三：已有 Python 环境**

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m waitress --host=0.0.0.0 --port=18080 --call app.server:create_app
```

## 目录

```
app/core/     算法与解析实现（纯 Python）
app/api/      Flask 蓝图，统一 /api/*
app/server.py 应用入口（静态资源 + API）
web/          前端（原生 JS，无构建，hash 路由）
  kit.js      页面框架：表单引擎、结果渲染、toast、抽屉
  modules/    各工具模块（CB.register）
windows/      Windows 独立包用启动脚本与说明（start.bat / 使用说明.txt）
scripts/      打包脚本（package_win.sh）
tests/        pytest 接口/算法测试 + jsdom E2E
data/         本地 CA 与运行期数据
requirements.txt / requirements-dev.txt  运行 / 开发依赖
```

## 模块清单

| 分类 | 模块 |
| --- | --- |
| 对称密码校验 | 分组密码（SM4/AES/DES/3DES，ECB/CBC/CTR/OFB/CFB/XTS）、序列密码 ZUC-128/256、GCM |
| 哈希算法校验 | 哈希算法（SM3/SHA/ SHA3/MD5 + HMAC）、MAC 算法（8 种）、哈希算法猜测 |
| 非对称算法校验 | SM2、SM9、RSA、ECDSA、Attach&Detach、点压缩解压缩 |
| 数字证书校验 | 证书格式检查（含证书链）、证书撤销检查（CRL/OCSP）、CRL 有效性校验、证书签发、ASN.1 解析 |
| 协议分析工具 | TLS、SSH、IPSec、UKey(APDU) 报文解析 |
| 独立工具 | 电子签章校验、编码转换、量化评估、随机数检测、时间戳解析 |
| 能力验证必备 | PRF、KDF、TLCP 密钥生成、SM2 加密-K、签名攻击、点运算、PBKDF2、工作模式检测 |
| 其他常用工具 | 密文长度分析、大数运算、取模运算、逻辑运算、字节逆序 |

## 测试

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cd tests && npm install && cd ..          # E2E 需要 jsdom
./test_all.sh                             # pytest + jsdom E2E（需先启动服务）
```

- `tests/test_*.py`：以 Flask test client 调用每个接口，含标准向量与往返校验。
- `tests/e2e/all_modules.js`：jsdom 打开真实页面，按每个模块的 `samples` 填表、点击、断言结果非空。
- 要求服务已在 18080 端口运行；E2E 通过 `CB_BASE` 环境变量可改地址。

## 说明

- 算法实现遵循 GB/T 32905（SM3）、GB/T 32907（SM4）、GB/T 32918（SM2）、GM/T 0044（SM9）、
  GM/T 0001（ZUC）、RFC 8017（RSA）、RFC 5280（X.509）、RFC 3161（时间戳）等标准。
- 离线环境下 OCSP 联网查询不可用，工具支持粘贴 OCSP 响应进行本地验证。
- 电子签章校验支持 PDF（PAdES）与 OFD（GB/T 33190）签名结构解析。
