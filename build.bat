@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  Compliance Scanner - Build Script
echo ============================================================
echo.

REM ---------------------------------------------------------------
REM 1. Ensure PyInstaller is available
REM ---------------------------------------------------------------
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    python -m pip install pyinstaller --quiet
)

REM ---------------------------------------------------------------
REM 2. Run PyInstaller
REM ---------------------------------------------------------------
echo [BUILD] Running PyInstaller...
python -m PyInstaller compliance_scanner.spec --clean --noconfirm
if errorlevel 1 (
    echo [ERROR] PyInstaller failed. See output above.
    exit /b 1
)
echo [BUILD] PyInstaller succeeded.
echo.

REM ---------------------------------------------------------------
REM 3. Optional code signing
REM    Set SIGN_CERT_PATH and SIGN_CERT_PASSWORD before running,
REM    or set SIGN_THUMBPRINT to use a cert already in the store.
REM
REM    Obtain a certificate from DigiCert, Sectigo, or
REM    Azure Trusted Signing. EV certs skip SmartScreen instantly;
REM    OV/standard certs build reputation over time.
REM ---------------------------------------------------------------
set "EXE_PATH=dist\ComplianceScanner\ComplianceScanner.exe"

REM Locate signtool.exe (Windows SDK)
set "SIGNTOOL="
for %%D in (
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
    "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"
) do (
    if exist %%D (
        set "SIGNTOOL=%%~D"
        goto :found_signtool
    )
)
:found_signtool

if "%SIGNTOOL%"=="" (
    echo [SIGN] signtool.exe not found - skipping signing.
    echo        Install the Windows 10/11 SDK to enable signing.
    goto :build_installer
)

REM Sign using a .pfx file
if defined SIGN_CERT_PATH (
    if defined SIGN_CERT_PASSWORD (
        echo [SIGN] Signing with certificate: %SIGN_CERT_PATH%
        "%SIGNTOOL%" sign ^
            /fd SHA256 ^
            /tr http://timestamp.digicert.com ^
            /td SHA256 ^
            /f "%SIGN_CERT_PATH%" ^
            /p "%SIGN_CERT_PASSWORD%" ^
            "%EXE_PATH%"
        if errorlevel 1 (
            echo [SIGN] Signing failed - check certificate path and password.
        ) else (
            echo [SIGN] Signed successfully.
        )
        goto :build_installer
    )
)

REM Sign using a certificate thumbprint already in the Windows cert store
if defined SIGN_THUMBPRINT (
    echo [SIGN] Signing with thumbprint: %SIGN_THUMBPRINT%
    "%SIGNTOOL%" sign ^
        /fd SHA256 ^
        /tr http://timestamp.digicert.com ^
        /td SHA256 ^
        /sha1 "%SIGN_THUMBPRINT%" ^
        "%EXE_PATH%"
    if errorlevel 1 (
        echo [SIGN] Signing failed - check thumbprint value.
    ) else (
        echo [SIGN] Signed successfully.
    )
    goto :build_installer
)

echo [SIGN] No certificate configured - skipping signing.
echo        To sign, set one of:
echo          SIGN_CERT_PATH + SIGN_CERT_PASSWORD  (use a .pfx file)
echo          SIGN_THUMBPRINT                       (cert already in store)

:build_installer
echo.

REM ---------------------------------------------------------------
REM 4. Optional Inno Setup installer compilation
REM ---------------------------------------------------------------
set "ISCC="
for %%D in (
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    "C:\Program Files\Inno Setup 6\ISCC.exe"
) do (
    if exist %%D (
        set "ISCC=%%~D"
        goto :found_iscc
    )
)
:found_iscc

if "%ISCC%"=="" (
    echo [INSTALLER] Inno Setup not found - skipping installer build.
    echo             Download from https://jrsoftware.org/isinfo.php
    goto :done
)

echo [INSTALLER] Compiling installer with Inno Setup...
"%ISCC%" installer.iss
if errorlevel 1 (
    echo [INSTALLER] Inno Setup compilation failed.
) else (
    echo [INSTALLER] Installer created in dist\installer\

    REM Sign the installer exe as well
    if defined SIGNTOOL (
        if defined SIGN_CERT_PATH (
            if defined SIGN_CERT_PASSWORD (
                "%SIGNTOOL%" sign ^
                    /fd SHA256 ^
                    /tr http://timestamp.digicert.com ^
                    /td SHA256 ^
                    /f "%SIGN_CERT_PATH%" ^
                    /p "%SIGN_CERT_PASSWORD%" ^
                    "dist\installer\ComplianceScannerSetup.exe"
                echo [SIGN] Installer signed.
            )
        ) else if defined SIGN_THUMBPRINT (
            "%SIGNTOOL%" sign ^
                /fd SHA256 ^
                /tr http://timestamp.digicert.com ^
                /td SHA256 ^
                /sha1 "%SIGN_THUMBPRINT%" ^
                "dist\installer\ComplianceScannerSetup.exe"
            echo [SIGN] Installer signed.
        )
    )
)

:done
echo.
echo ============================================================
echo  Build complete.
echo  App folder : dist\ComplianceScanner\
echo  Installer  : dist\installer\ComplianceScannerSetup.exe
echo ============================================================
endlocal
