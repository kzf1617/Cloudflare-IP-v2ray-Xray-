@echo off
chcp 65001 >nul
REM ============================================================
REM  Cloudflare 优选IP 扫描器 - Windows 打包脚本 (Win10/Win11)
REM  产物: dist\CF优选IP.exe  (单文件, 目标机器无需安装 Python)
REM ============================================================
setlocal

cd /d "%~dp0"

echo [1/3] 检查 PyInstaller ...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo     未检测到 PyInstaller, 正在安装 ...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo [错误] PyInstaller 安装失败, 请检查 Python/pip 环境。
        pause
        exit /b 1
    )
)

echo [2/3] 清理旧的构建产物 ...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist CF优选IP.spec del /q CF优选IP.spec

echo [3/3] 开始打包 ...
REM --onefile      打成单个 exe
REM --console      保留控制台(无 GUI 需求)
REM --name         产物名
REM --clean        清理缓存
REM --noconfirm    覆盖已存在产物
python -m PyInstaller ^
    --onefile ^
    --console ^
    --clean ^
    --noconfirm ^
    --name "CF优选IP" ^
    --distpath dist ^
    --workpath build ^
    cloudflare_speedtest.py

if errorlevel 1 (
    echo.
    echo [错误] 打包失败, 请查看上方日志。
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  打包完成:  dist\CF优选IP.exe
echo.
echo  使用方式:
echo    1) 把 CF优选IP.exe 放到任意文件夹(如 D:\cfip)
echo    2) 双击运行一次 -> 会自动生成 config.json
echo    3) 用记事本编辑 config.json 里的 domain 为你的 CF 域名
echo    4) 再次双击运行, 结果会输出到同目录的 out\ 文件夹
echo.
echo  也可以在命令行里带参数运行, 例如:
echo    CF优选IP.exe -d 你的域名.com -p 443 -P /ws
echo ============================================================
pause
