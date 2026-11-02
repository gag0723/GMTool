#!/bin/sh
# 打包 Windows x64 独立运行版：内嵌 Python + 依赖 wheels + 应用源码 + start.bat
#
# 用法（在任意目录执行均可）：
#   ./scripts/package_win.sh                # 复用 dist/ 下已缓存的内嵌 Python 与 wheels
#   FORCE_DOWNLOAD=1 ./scripts/package_win.sh   # 强制重新下载内嵌 Python 与全部 wheels
#   PY_VER=3.13.9 ./scripts/package_win.sh      # 指定内嵌 Python 版本
#
# 产物：
#   dist/cipherbox-windows/            解压后可直接双击 start.bat 的目录
#   dist/GMTool-windows-x64.zip        上述目录的压缩包（顶层目录 GMTool/）
#
# 依赖：python3、pip、unzip、curl；打包机器需能访问 python.org 与 PyPI。
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)
DIST="$ROOT/dist"
PY_VER=${PY_VER:-3.13.9}
EMBED_ZIP="$DIST/python-embed.zip"
PKG="$DIST/cipherbox-windows"
ZIP_OUT="$DIST/GMTool-windows-x64.zip"

command -v python3 >/dev/null || { echo "缺少 python3" >&2; exit 1; }
command -v unzip >/dev/null || { echo "缺少 unzip" >&2; exit 1; }

mkdir -p "$DIST"

# 1) 内嵌 Python（Windows embeddable package）
if [ ! -f "$EMBED_ZIP" ] || [ -n "$FORCE_DOWNLOAD" ]; then
  echo "== 下载 Python $PY_VER embeddable ..."
  curl -fL --retry 3 -o "$EMBED_ZIP" \
    "https://www.python.org/ftp/python/$PY_VER/python-$PY_VER-embed-amd64.zip"
fi

# 2) 依赖 wheels（win_amd64 / cp313，纯 Python 包自动兼容）
if [ -z "$FORCE_DOWNLOAD" ] && ls "$DIST"/pylibs/*.whl >/dev/null 2>&1; then
  echo "== 复用已缓存的 wheels：$DIST/pylibs"
else
  echo "== 下载 Windows wheels ..."
  rm -rf "$DIST/pylibs"
  mkdir -p "$DIST/pylibs"
  python3 -m pip download -q -d "$DIST/pylibs" -r "$ROOT/requirements.txt" \
    --only-binary=:all: --platform win_amd64 --implementation cp --python-version 313
fi

# 3) 组装目录
echo "== 组装 $PKG"
rm -rf "$PKG"
mkdir -p "$PKG/pylibs" "$PKG/data" "$PKG/logs"
unzip -q -o "$EMBED_ZIP" -d "$PKG/python"
# 内嵌 Python 的 _pth 需包含 ../pylibs 才能找到依赖（与原包保持一致：启用 import site）
python3 - "$PKG/python" <<'PY'
import glob, os, sys
pydir = sys.argv[1]
pths = glob.glob(os.path.join(pydir, 'python3*._pth'))
pth = pths[0] if pths else os.path.join(pydir, 'python313._pth')
lines = open(pth, encoding='utf-8-sig').read().splitlines() if os.path.exists(pth) else ['python313.zip', '.']
out, has_pylibs = [], False
for ln in lines:
    s = ln.strip()
    if s.endswith('pylibs'):
        has_pylibs = True
    if s == '#import site':
        ln = 'import site'
    out.append(ln)
if not has_pylibs:
    out.append('../pylibs')
if 'import site' not in [x.strip() for x in out]:
    out.append('import site')
open(pth, 'w', encoding='utf-8', newline='\r\n').write('\n'.join(out) + '\n')
print('== _pth 已更新：', pth)
PY
for w in "$DIST"/pylibs/*.whl; do
  unzip -q -o "$w" -d "$PKG/pylibs"
done
# 去掉命令行入口脚本，减小体积（本包只用 python -m waitress）
rm -rf "$PKG"/pylibs/*/bin 2>/dev/null || true
rm -rf "$PKG"/pylibs/*.dist-info/RECORD 2>/dev/null || true

cp -r "$ROOT/app" "$PKG/app"
cp -r "$ROOT/web" "$PKG/web"
cp "$ROOT/windows/start.bat" "$PKG/start.bat"
cp "$ROOT/windows/使用说明.txt" "$PKG/使用说明.txt"
# 清理构建期残留
find "$PKG" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$PKG" -name '*.pyc' -delete 2>/dev/null || true
rm -rf "$PKG/app/data"

# start.bat 必须是 CRLF 行尾
python3 - "$PKG/start.bat" <<'PY'
import sys
p = sys.argv[1]
data = open(p, 'rb').read().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
open(p, 'wb').write(data)
PY

# 4) 打 zip（python3 写入 UTF-8 文件名标记，Windows 资源管理器不会乱码）
echo "== 生成 $ZIP_OUT"
python3 - "$PKG" "$ZIP_OUT" <<'PY'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
if os.path.exists(out):
    os.remove(out)
n = 0
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(src):
        for f in files:
            p = os.path.join(root, f)
            arc = os.path.join('GMTool', os.path.relpath(p, src)).replace(os.sep, '/')
            z.write(p, arc)
            n += 1
    if not any(i.filename.startswith('GMTool/data/') for i in z.infolist()):
        z.writestr('GMTool/data/.keep', '')
print('打包完成：%s（%d 个文件，%.2f MB）' % (out, n, os.path.getsize(out) / 1048576))
PY

echo "== 完成：$PKG"
du -sh "$PKG" "$ZIP_OUT"
