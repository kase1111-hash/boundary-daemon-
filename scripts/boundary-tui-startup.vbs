' Boundary Daemon TUI - Silent Startup Script
'
' This VBScript launches the TUI without showing an initial command prompt.
' The TUI will open in its own window after a brief delay.
'
' INSTALLATION:
' 1. Press Win+R, type: shell:startup
' 2. Copy this file into the Startup folder
' 3. The TUI will now start automatically when you log in
'
' To run in Matrix mode, change the last parameter below from "" to "--matrix"

Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")

' Get the directory where this script is located
ScriptPath = WScript.ScriptFullName
ScriptDir = FSO.GetParentFolderName(ScriptPath)
ProjectDir = FSO.GetParentFolderName(ScriptDir)

' Wait a moment for system to stabilize
WScript.Sleep 3000

' Change to project directory
WshShell.CurrentDirectory = ProjectDir

' Build the command - try Python 3.12 first, then fall back
Dim PythonCmd
PythonCmd = ""

' Check for Python 3.12
On Error Resume Next
WshShell.Run "py -3.12 --version", 0, True
If Err.Number = 0 Then
    PythonCmd = "py -3.12"
Else
    Err.Clear
    WshShell.Run "python --version", 0, True
    If Err.Number = 0 Then
        PythonCmd = "python"
    Else
        Err.Clear
        WshShell.Run "py --version", 0, True
        If Err.Number = 0 Then
            PythonCmd = "py"
        End If
    End If
End If
On Error Goto 0

If PythonCmd = "" Then
    MsgBox "Boundary Daemon TUI: Python not found." & vbCrLf & _
           "Please install Python 3.12 from https://www.python.org/downloads/", _
           vbExclamation, "Boundary Daemon"
    WScript.Quit 1
End If

' Launch the TUI in a new window
' Change "" to "--matrix" for Matrix mode
MatrixMode = ""

Cmd = "cmd /c ""cd /d """ & ProjectDir & """ && " & PythonCmd & " -m daemon.tui.dashboard " & MatrixMode & """"
WshShell.Run Cmd, 1, False
