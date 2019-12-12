:: Usage: build_dll.bat <PROGRAM>
:: e.g.,  build_dll.bat sleep.c

@echo off

set PROGRAM=%1
set BASENAME=%PROGRAM:~0,-2%

for /f "tokens=2-4 delims=/ " %%a in ("%DATE%") do (
    set YYYY=%%c
    set MM=%%a
    set DD=%%b
)
for /f "tokens=1-4 delims=/:." %%a in ("%TIME: =0%") do (
    set HH=%%a
    set MI=%%b
    set SS=%%c
    set FF=%%d
)
set DATETIME=%YYYY%%MM%%DD%%HH%%MI%%SS%%FF%

@echo on

for %%a in (x86 amd64) do (
    setlocal
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %%a
    csc /target:module empty.cs
    cl /c %PROGRAM%
    link /DLL /LTCG /CLRIMAGETYPE:IJW /out:%BASENAME%_%DATETIME%_%%a.dll %BASENAME%.obj empty.netmodule
    del %BASENAME%.obj empty.netmodule
    endlocal
)
