Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strPath = fso.GetParentFolderName(WScript.ScriptFullName)

' Run Chetas-Start.bat hidden (0 window)
WshShell.CurrentDirectory = strPath
WshShell.Run "cmd /c node server/index.js", 0, False

' Wait 2 seconds and open default web browser
WScript.Sleep 2000
WshShell.Run "http://localhost:3000"
