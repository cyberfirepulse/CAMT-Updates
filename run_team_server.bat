@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
python -m projectmanager.team.server --config team_server_config.json
pause
