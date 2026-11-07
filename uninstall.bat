@echo off
chcp 65001 >nul
schtasks /Delete /F /TN "NetGuard" 2>nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v NetGuard /f 2>nul
echo Autostart entries removed (scheduled task and/or HKCU Run key).
echo To fully clean up, delete this whole folder (D:\Tools\NetGuard).
pause
