@echo off
cd /d F:\ZHCraking\JB\UPO
set PYTHONIOENCODING=utf-8
"C:\Users\Admin\AppData\Local\Programs\Python\Python313\python.exe" backup_upo_monolith.py --config bench/old/config.yaml > bench\old\run.log 2>&1
echo %ERRORLEVEL% > bench\old\exit.code
