@echo off
cd /d F:\ZHCraking\JB\UPO
set PYTHONIOENCODING=utf-8
"C:\Users\Admin\AppData\Local\Programs\Python\Python313\python.exe" main.py --config bench/new/config.yaml > bench\new\run.log 2>&1
echo %ERRORLEVEL% > bench\new\exit.code
