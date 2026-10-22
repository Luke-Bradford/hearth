@echo off
rem Makes Hearth start when you sign in to Windows: puts a shortcut to start-hearth.bat in your
rem Startup folder. Run it again with /remove to take the shortcut away. Nothing else changes.
rem Paths go to PowerShell through the environment and there are no ( ) blocks, so a folder or
rem user name with ' or ( ) in it can't break the commands.
setlocal
set "LINK=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Hearth.lnk"
set "HERE=%~dp0"
if /i "%~1"=="/remove" goto :remove
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LINK);" ^
  "$s.TargetPath = $env:HERE + 'start-hearth.bat'; $s.WorkingDirectory = $env:HERE.TrimEnd('\');" ^
  "$s.WindowStyle = 7; $s.Description = 'Hearth - home network monitor'; $s.Save()"
if errorlevel 1 goto :failed
echo Hearth will start when you sign in (shortcut: %LINK%).
echo It runs while you're signed in. To undo: install-startup.bat /remove
goto :end

:remove
if not exist "%LINK%" goto :notset
del "%LINK%"
if exist "%LINK%" goto :failed
echo Hearth will no longer start when you sign in.
goto :end

:notset
echo Hearth wasn't set to start when you sign in.
goto :end

:failed
echo Couldn't change the shortcut in your Startup folder.

:end
endlocal
pause
