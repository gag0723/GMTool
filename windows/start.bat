@echo off
chcp 65001 >nul
title 密码工具百宝箱 · 本地版
cd /d %~dp0

rem ===== 可配置项 =====
if "%CIPHERBOX_PORT%"=="" set CIPHERBOX_PORT=18080
set CIPHERBOX_DATA=%~dp0data
rem ====================

echo 正在启动密码工具百宝箱（本地版）...
echo 监听端口：%CIPHERBOX_PORT%    数据目录：%CIPHERBOX_DATA%
echo 浏览器将自动打开 http://127.0.0.1:%CIPHERBOX_PORT%/
echo 关闭本窗口或按 Ctrl+C 即停止服务。
echo.

start "" cmd /c "timeout /t 2 >nul & start http://127.0.0.1:%CIPHERBOX_PORT%/"
python\python.exe -m waitress --host=0.0.0.0 --port=%CIPHERBOX_PORT% --threads=8 --call app.server:create_app

echo.
echo 服务已停止，按任意键关闭窗口。
pause >nul
