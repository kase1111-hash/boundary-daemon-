@echo off
REM ============================================================================
REM Boundary Daemon Build Script for Windows
REM Compiles the daemon into a standalone executable using PyInstaller
REM ============================================================================
REM
REM Usage: build.bat [options]
REM
REM Options:
REM   --onefile     Create a single executable (default)
REM   --onedir      Create a directory with executable and dependencies
REM   --debug       Include debug symbols and console output
REM   --clean       Clean build artifacts before building
REM   --skip-deps   Skip dependency installation
REM   --help        Show this help message
REM
REM ============================================================================

setlocal enabledelayedexpansion

REM Configuration
set APP_NAME=boundary-daemon
set MAIN_SCRIPT=run_daemon.py
set BUILD_MODE=onefile
set DEBUG_MODE=0
set CLEAN_BUILD=0
set SKIP_DEPS=0
set ICON_PATH=

REM Colors for output (Windows 10+)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "CYAN=[96m"
set "RESET=[0m"

REM Parse command line arguments
:parse_args
if "%~1"=="" goto main_script
if /i "%~1"=="--onefile" set BUILD_MODE=onefile
if /i "%~1"=="--onedir" set BUILD_MODE=onedir
if /i "%~1"=="--debug" set DEBUG_MODE=1
if /i "%~1"=="--clean" set CLEAN_BUILD=1
if /i "%~1"=="--skip-deps" set SKIP_DEPS=1
if /i "%~1"=="--help" goto show_help
if /i "%~1"=="-h" goto show_help
shift
if not "%~1"=="" goto parse_args

:main_script

REM Record start time
set START_TIME=%TIME%

echo.
echo %CYAN%========================================%RESET%
echo %CYAN% Boundary Daemon Build Script%RESET%
echo %CYAN%========================================%RESET%
echo.
echo Build Mode: %BUILD_MODE%
echo Debug Mode: %DEBUG_MODE%
echo Clean Build: %CLEAN_BUILD%
echo.

REM ============================================================================
REM Pre-build checks
REM ============================================================================
echo %YELLOW%[1/6] Running pre-build checks...%RESET%

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo !RED!ERROR: Python is not installed or not in PATH!RESET!
    echo Please install Python 3.8+ and try again
    goto :build_failed
)

for /f "tokens=2" %%a in ('python --version 2^>^&1') do set PYTHON_VERSION=%%a
echo   Python version: %PYTHON_VERSION%

REM Check Python version is 3.8+
python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>nul
if errorlevel 1 (
    echo !RED!ERROR: Python 3.8 or higher is required!RESET!
    goto :build_failed
)

REM Check if main script exists
if not exist "%MAIN_SCRIPT%" (
    echo !RED!ERROR: Main script not found: !MAIN_SCRIPT!!RESET!
    goto :build_failed
)
echo   Main script: %MAIN_SCRIPT% [OK]

REM Check if daemon package exists
if not exist "daemon\__init__.py" (
    echo !RED!ERROR: daemon package not found!RESET!
    goto :build_failed
)
echo   Daemon package: [OK]

REM Check if api package exists
if not exist "api\__init__.py" (
    echo !RED!ERROR: api package not found!RESET!
    goto :build_failed
)
echo   API package: [OK]

echo %GREEN%   Pre-build checks passed!%RESET%

REM ============================================================================
REM Clean build artifacts if requested
REM ============================================================================
if %CLEAN_BUILD%==1 (
    echo.
    echo !YELLOW![2/6] Cleaning previous build artifacts...!RESET!
    if exist "build" rmdir /s /q "build" 2>nul && echo   Removed: build/
    if exist "dist" rmdir /s /q "dist" 2>nul && echo   Removed: dist/
    if exist "!APP_NAME!.spec" del /f /q "!APP_NAME!.spec" 2>nul && echo   Removed: !APP_NAME!.spec
    for /d %%d in (*__pycache__*) do rmdir /s /q "%%d" 2>nul
    echo !GREEN!   Clean complete!!RESET!
) else (
    echo.
    echo !YELLOW![2/6] Skipping clean ^(use --clean to enable^)!RESET!
)

REM ============================================================================
REM Install dependencies
REM ============================================================================
echo.
if %SKIP_DEPS%==0 (
    echo !YELLOW![3/6] Installing dependencies...!RESET!

    REM Check if PyInstaller is installed
    python -c "import PyInstaller" >nul 2>&1
    if errorlevel 1 (
        echo   Installing PyInstaller...
        pip install pyinstaller --quiet
        if errorlevel 1 (
            echo !RED!ERROR: Failed to install PyInstaller!RESET!
            goto :build_failed
        )
    )
    for /f "tokens=*" %%a in ('python -c "import PyInstaller; print(PyInstaller.__version__)"') do set PYINSTALLER_VERSION=%%a
    echo   PyInstaller version: !PYINSTALLER_VERSION!

    REM Install requirements
    if exist "requirements.txt" (
        echo   Installing project dependencies...
        pip install -r requirements.txt --quiet
        if errorlevel 1 (
            echo !RED!ERROR: Failed to install dependencies from requirements.txt!RESET!
            goto :build_failed
        )
        echo !GREEN!   Dependencies installed!!RESET!
    ) else (
        echo !YELLOW!   Warning: requirements.txt not found!RESET!
    )
) else (
    echo !YELLOW![3/6] Skipping dependency installation ^(--skip-deps^)!RESET!
)

REM ============================================================================
REM Initialize config directory and generate integrity manifest
REM ============================================================================
echo.
echo %YELLOW%[4/6] Initializing config and generating integrity manifest...%RESET%

REM Create config directory if it doesn't exist
if not exist "config" (
    echo   Creating config directory...
    mkdir config
    if errorlevel 1 (
        echo !RED!   ERROR: Failed to create config directory!RESET!
        goto :build_failed
    )
    echo !GREEN!   Created: config\!RESET!
) else (
    echo   Config directory exists: config\
)

REM Generate signing key if it doesn't exist
set SIGNING_KEY_GENERATED=0
if not exist "config\signing.key" (
    echo   Generating signing key...
    python -m daemon.security.daemon_integrity generate-key --output config\signing.key 2>nul
    if errorlevel 1 (
        echo !YELLOW!   Warning: Failed to generate signing key via module!RESET!
        echo   Attempting alternative key generation...
        REM Fallback: Generate key using Python directly
        python -c "import os; open('config/signing.key', 'wb').write(os.urandom(32))" 2>nul
        if errorlevel 1 (
            echo !RED!   ERROR: Failed to generate signing key!RESET!
            echo   The daemon will run in development mode without integrity verification.
        ) else (
            set SIGNING_KEY_GENERATED=1
            echo !GREEN!   Generated signing key: config\signing.key ^(fallback method^)!RESET!
        )
    ) else (
        set SIGNING_KEY_GENERATED=1
        echo !GREEN!   Generated signing key: config\signing.key!RESET!
    )
) else (
    set SIGNING_KEY_GENERATED=1
    echo   Signing key already exists: config\signing.key
)

REM Generate manifest only if signing key exists
if exist "config\signing.key" (
    echo   Generating integrity manifest...
    python -m daemon.security.daemon_integrity create --manifest config\manifest.json --key config\signing.key --root . 2>nul
    if errorlevel 1 (
        echo !YELLOW!   Warning: Failed to generate manifest via module!RESET!
        echo   Attempting alternative manifest generation...
        REM Fallback: Create a basic manifest structure
        python -c "import json, hashlib, os, datetime; files={}; [files.update({os.path.join(r,f).replace('\\','/'): {'path': os.path.join(r,f).replace('\\','/'), 'hash': hashlib.sha256(open(os.path.join(r,f),'rb').read()).hexdigest(), 'size': os.path.getsize(os.path.join(r,f)), 'mtime': os.path.getmtime(os.path.join(r,f))}} for r,d,fs in os.walk('daemon') for f in fs if f.endswith('.py')]; key=open('config/signing.key','rb').read(); import hmac; data={'version':'1.0','created_at':datetime.datetime.utcnow().isoformat()+'Z','daemon_version':'build','hash_algorithm':'sha256','files':files}; data['signature']=hmac.new(key,json.dumps({k:v for k,v in data.items() if k!='signature'},sort_keys=True,separators=(',',':')).encode(),'sha256').hexdigest(); json.dump(data,open('config/manifest.json','w'),indent=2)" 2>nul
        if errorlevel 1 (
            echo !RED!   ERROR: Failed to generate manifest!RESET!
            echo   The daemon will auto-generate a manifest on first run.
        ) else (
            echo !GREEN!   Generated manifest: config\manifest.json ^(fallback method^)!RESET!
        )
    ) else (
        echo !GREEN!   Generated manifest: config\manifest.json!RESET!
    )
) else (
    echo !YELLOW!   Skipping manifest generation - no signing key available!RESET!
    echo   The daemon will run in development mode.
)

REM Verify manifest was created
if exist "config\manifest.json" (
    echo   Verifying manifest...
    python -m daemon.security.daemon_integrity verify --manifest config\manifest.json --key config\signing.key --root . 2>nul
    if errorlevel 1 (
        echo !YELLOW!   Warning: Manifest verification returned errors ^(may be expected during build^)!RESET!
    ) else (
        echo !GREEN!   Manifest verification passed!!RESET!
    )
)

REM ============================================================================
REM Create output directories
REM ============================================================================
echo.
echo %YELLOW%[5/6] Setting up build environment...%RESET%
if not exist "dist" mkdir dist
if not exist "build" mkdir build
echo   Created output directories

REM Check for icon file
if exist "assets\icon.ico" (
    set ICON_PATH=--icon=assets\icon.ico
    echo   Found icon: assets\icon.ico
)

REM ============================================================================
REM Build the executable
REM ============================================================================
echo.
echo %YELLOW%[6/6] Building %APP_NAME%...%RESET%
echo.

REM Set build mode flag
if "%BUILD_MODE%"=="onedir" (
    set MODE_FLAG=--onedir
) else (
    set MODE_FLAG=--onefile
)

REM Set debug flag
set DEBUG_FLAG=
if %DEBUG_MODE%==1 (
    set DEBUG_FLAG=--debug=all
)

REM Build the executable
REM Note: Using explicit hidden imports instead of --collect-submodules for daemon/api
REM to avoid PyInstaller warnings about NoneType iteration errors
python -m PyInstaller ^
    --name=%APP_NAME% ^
    %MODE_FLAG% ^
    --console ^
    %ICON_PATH% ^
    %DEBUG_FLAG% ^
    --add-data "daemon;daemon" ^
    --add-data "api;api" ^
    --hidden-import=cffi ^
    --hidden-import=_cffi_backend ^
    --hidden-import=nacl ^
    --hidden-import=nacl.bindings ^
    --hidden-import=nacl.signing ^
    --hidden-import=cryptography ^
    --hidden-import=cryptography.fernet ^
    --hidden-import=cryptography.hazmat.primitives ^
    --hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2 ^
    --hidden-import=cryptography.hazmat.backends ^
    --hidden-import=yara ^
    --hidden-import=api ^
    --hidden-import=api.boundary_api ^
    --hidden-import=daemon ^
    --hidden-import=daemon.constants ^
    --hidden-import=daemon.state_monitor ^
    --hidden-import=daemon.policy_engine ^
    --hidden-import=daemon.tripwires ^
    --hidden-import=daemon.event_logger ^
    --hidden-import=daemon.signed_event_logger ^
    --hidden-import=daemon.boundary_daemon ^
    --hidden-import=daemon.memory_monitor ^
    --hidden-import=daemon.resource_monitor ^
    --hidden-import=daemon.health_monitor ^
    --hidden-import=daemon.queue_monitor ^
    --hidden-import=daemon.monitoring_report ^
    --hidden-import=daemon.privilege_manager ^
    --hidden-import=daemon.redundant_event_logger ^
    --hidden-import=daemon.integrations ^
    --hidden-import=daemon.airgap ^
    --hidden-import=daemon.airgap.data_diode ^
    --hidden-import=daemon.airgap.qr_ceremony ^
    --hidden-import=daemon.airgap.sneakernet ^
    --hidden-import=daemon.alerts ^
    --hidden-import=daemon.alerts.case_manager ^
    --hidden-import=daemon.api ^
    --hidden-import=daemon.api.health ^
    --hidden-import=daemon.auth ^
    --hidden-import=daemon.auth.api_auth ^
    --hidden-import=daemon.auth.advanced_ceremony ^
    --hidden-import=daemon.auth.biometric_verifier ^
    --hidden-import=daemon.auth.enhanced_ceremony ^
    --hidden-import=daemon.auth.persistent_rate_limiter ^
    --hidden-import=daemon.auth.secure_token_storage ^
    --hidden-import=daemon.cli ^
    --hidden-import=daemon.cli.boundaryctl ^
    --hidden-import=daemon.cli.queryctl ^
    --hidden-import=daemon.cli.sandboxctl ^
    --hidden-import=daemon.compliance ^
    --hidden-import=daemon.compliance.access_review ^
    --hidden-import=daemon.compliance.control_mapping ^
    --hidden-import=daemon.compliance.evidence_bundle ^
    --hidden-import=daemon.compliance.zk_proofs ^
    --hidden-import=daemon.config ^
    --hidden-import=daemon.config.linter ^
    --hidden-import=daemon.config.secure_config ^
    --hidden-import=daemon.containment ^
    --hidden-import=daemon.containment.agent_profiler ^
    --hidden-import=daemon.crypto ^
    --hidden-import=daemon.crypto.hsm_provider ^
    --hidden-import=daemon.crypto.post_quantum ^
    --hidden-import=daemon.detection ^
    --hidden-import=daemon.detection.event_publisher ^
    --hidden-import=daemon.detection.ioc_feeds ^
    --hidden-import=daemon.detection.mitre_attack ^
    --hidden-import=daemon.detection.sigma_engine ^
    --hidden-import=daemon.detection.yara_engine ^
    --hidden-import=daemon.distributed ^
    --hidden-import=daemon.distributed.cluster_manager ^
    --hidden-import=daemon.distributed.coordinators ^
    --hidden-import=daemon.ebpf ^
    --hidden-import=daemon.ebpf.ebpf_observer ^
    --hidden-import=daemon.ebpf.policy_integration ^
    --hidden-import=daemon.ebpf.probes ^
    --hidden-import=daemon.enforcement ^
    --hidden-import=daemon.enforcement.disk_encryption ^
    --hidden-import=daemon.enforcement.firewall_integration ^
    --hidden-import=daemon.enforcement.mac_profiles ^
    --hidden-import=daemon.enforcement.network_enforcer ^
    --hidden-import=daemon.enforcement.process_enforcer ^
    --hidden-import=daemon.enforcement.protection_persistence ^
    --hidden-import=daemon.enforcement.secure_process_termination ^
    --hidden-import=daemon.enforcement.secure_profile_manager ^
    --hidden-import=daemon.enforcement.usb_enforcer ^
    --hidden-import=daemon.enforcement.windows_firewall ^
    --hidden-import=daemon.external_integrations ^
    --hidden-import=daemon.external_integrations.siem ^
    --hidden-import=daemon.external_integrations.siem.cef_leef ^
    --hidden-import=daemon.external_integrations.siem.log_shipper ^
    --hidden-import=daemon.external_integrations.siem.sandbox_events ^
    --hidden-import=daemon.external_integrations.siem.verification_api ^
    --hidden-import=daemon.federation ^
    --hidden-import=daemon.federation.threat_mesh ^
    --hidden-import=daemon.hardware ^
    --hidden-import=daemon.hardware.tpm_manager ^
    --hidden-import=daemon.identity ^
    --hidden-import=daemon.identity.identity_manager ^
    --hidden-import=daemon.identity.ldap_mapper ^
    --hidden-import=daemon.identity.oidc_validator ^
    --hidden-import=daemon.identity.pam_integration ^
    --hidden-import=daemon.integrity ^
    --hidden-import=daemon.integrity.code_signer ^
    --hidden-import=daemon.integrity.integrity_verifier ^
    --hidden-import=daemon.intelligence ^
    --hidden-import=daemon.intelligence.mode_advisor ^
    --hidden-import=daemon.messages ^
    --hidden-import=daemon.messages.message_checker ^
    --hidden-import=daemon.pii ^
    --hidden-import=daemon.pii.bypass_resistant_detector ^
    --hidden-import=daemon.pii.detector ^
    --hidden-import=daemon.pii.filter ^
    --hidden-import=daemon.policy ^
    --hidden-import=daemon.policy.custom_policy_engine ^
    --hidden-import=daemon.sandbox ^
    --hidden-import=daemon.sandbox.cgroups ^
    --hidden-import=daemon.sandbox.mac_profiles ^
    --hidden-import=daemon.sandbox.namespace ^
    --hidden-import=daemon.sandbox.network_policy ^
    --hidden-import=daemon.sandbox.profile_config ^
    --hidden-import=daemon.sandbox.sandbox_manager ^
    --hidden-import=daemon.sandbox.seccomp_filter ^
    --hidden-import=daemon.security ^
    --hidden-import=daemon.security.agent_attestation ^
    --hidden-import=daemon.security.antivirus ^
    --hidden-import=daemon.security.antivirus_gui ^
    --hidden-import=daemon.security.arp_security ^
    --hidden-import=daemon.security.clock_monitor ^
    --hidden-import=daemon.security.code_advisor ^
    --hidden-import=daemon.security.daemon_integrity ^
    --hidden-import=daemon.security.dns_security ^
    --hidden-import=daemon.security.file_integrity ^
    --hidden-import=daemon.security.hardening ^
    --hidden-import=daemon.security.native_dns_resolver ^
    --hidden-import=daemon.security.network_attestation ^
    --hidden-import=daemon.security.process_security ^
    --hidden-import=daemon.security.prompt_injection ^
    --hidden-import=daemon.security.rag_injection ^
    --hidden-import=daemon.security.response_guardrails ^
    --hidden-import=daemon.security.secure_memory ^
    --hidden-import=daemon.security.siem_integration ^
    --hidden-import=daemon.security.threat_intel ^
    --hidden-import=daemon.security.tool_validator ^
    --hidden-import=daemon.security.traffic_anomaly ^
    --hidden-import=daemon.security.wifi_security ^
    --hidden-import=daemon.storage ^
    --hidden-import=daemon.storage.append_only ^
    --hidden-import=daemon.storage.forensic_audit ^
    --hidden-import=daemon.storage.log_hardening ^
    --hidden-import=daemon.telemetry ^
    --hidden-import=daemon.telemetry.otel_setup ^
    --hidden-import=daemon.telemetry.prometheus_metrics ^
    --hidden-import=daemon.tui ^
    --hidden-import=daemon.tui.dashboard ^
    --hidden-import=daemon.utils ^
    --hidden-import=daemon.utils.error_handling ^
    --hidden-import=daemon.watchdog ^
    --hidden-import=daemon.watchdog.hardened_watchdog ^
    --hidden-import=daemon.watchdog.log_watchdog ^
    --hidden-import=daemon.blockchain ^
    --hidden-import=daemon.blockchain.validator_protection ^
    --hidden-import=daemon.blockchain.rpc_protection ^
    --hidden-import=daemon.dreaming ^
    --hidden-import=daemon.audio ^
    --hidden-import=daemon.audio.audio_engine ^
    --hidden-import=daemon.audio.tts_engine ^
    --hidden-import=daemon.audio.stt_engine ^
    --hidden-import=pyttsx3 ^
    --hidden-import=pyttsx3.drivers ^
    --hidden-import=pyttsx3.drivers.sapi5 ^
    --hidden-import=pyttsx3.drivers.nsss ^
    --hidden-import=pyttsx3.drivers.espeak ^
    --collect-submodules=pyttsx3 ^
    --collect-submodules=nacl ^
    --collect-submodules=cffi ^
    --collect-submodules=cryptography ^
    --collect-submodules=yara ^
    --noconfirm ^
    --clean ^
    %MAIN_SCRIPT%

if errorlevel 1 goto :build_failed

REM ============================================================================
REM Post-build tasks
REM ============================================================================
echo.
echo %CYAN%Post-build tasks...%RESET%

REM Ensure dist\config directory exists
if not exist "dist\config" (
    echo   Creating dist\config directory...
    mkdir "dist\config"
)

REM Copy config files to dist
if exist "config" (
    echo   Copying configuration files...
    xcopy /E /I /Y "config" "dist\config" >nul 2>&1
    if errorlevel 1 (
        echo !YELLOW!   Warning: Some config files may not have copied correctly!RESET!
    ) else (
        echo !GREEN!   Configuration files copied to dist\config!RESET!
    )
)

REM Verify critical files exist in dist\config
echo.
echo %CYAN%Verifying integrity files...%RESET%
set INTEGRITY_OK=1

if exist "dist\config\signing.key" (
    echo !GREEN!   [OK] dist\config\signing.key!RESET!
) else (
    echo !RED!   [MISSING] dist\config\signing.key!RESET!
    set INTEGRITY_OK=0
)

if exist "dist\config\manifest.json" (
    echo !GREEN!   [OK] dist\config\manifest.json!RESET!
) else (
    echo !RED!   [MISSING] dist\config\manifest.json!RESET!
    set INTEGRITY_OK=0
)

if !INTEGRITY_OK!==0 (
    echo.
    echo !YELLOW!   Warning: Integrity files missing. The daemon will run in development mode.!RESET!
    echo !YELLOW!   To fix: Re-run build.bat or manually generate:!RESET!
    echo !YELLOW!     python -m daemon.security.daemon_integrity generate-key --output dist\config\signing.key!RESET!
    echo !YELLOW!     python -m daemon.security.daemon_integrity create --manifest dist\config\manifest.json --key dist\config\signing.key!RESET!
)

REM Create run script in dist
echo.
echo @echo off > dist\run-daemon.bat
echo echo Starting Boundary Daemon... >> dist\run-daemon.bat
echo cd /d "%%~dp0" >> dist\run-daemon.bat
echo "%APP_NAME%.exe" %%* >> dist\run-daemon.bat
echo pause >> dist\run-daemon.bat
echo   Created: dist\run-daemon.bat

REM Create a setup script for first-time initialization
echo @echo off > dist\setup-daemon.bat
echo echo ============================================= >> dist\setup-daemon.bat
echo echo  Boundary Daemon - First Time Setup >> dist\setup-daemon.bat
echo echo ============================================= >> dist\setup-daemon.bat
echo echo. >> dist\setup-daemon.bat
echo cd /d "%%~dp0" >> dist\setup-daemon.bat
echo if not exist "config" mkdir config >> dist\setup-daemon.bat
echo echo Checking for signing key... >> dist\setup-daemon.bat
echo if not exist "config\signing.key" ( >> dist\setup-daemon.bat
echo     echo Generating signing key... >> dist\setup-daemon.bat
echo     python -c "import os; open('config/signing.key', 'wb').write(os.urandom(32))" >> dist\setup-daemon.bat
echo     echo Done. >> dist\setup-daemon.bat
echo ) else ( >> dist\setup-daemon.bat
echo     echo Signing key already exists. >> dist\setup-daemon.bat
echo ) >> dist\setup-daemon.bat
echo echo. >> dist\setup-daemon.bat
echo echo Setup complete! Run the daemon with: %APP_NAME%.exe >> dist\setup-daemon.bat
echo pause >> dist\setup-daemon.bat
echo   Created: dist\setup-daemon.bat

REM Get executable size
if "%BUILD_MODE%"=="onefile" (
    if exist "dist\%APP_NAME%.exe" (
        for %%A in ("dist\%APP_NAME%.exe") do set EXE_SIZE=%%~zA
        if defined EXE_SIZE (
            set /a EXE_SIZE_MB=!EXE_SIZE! / 1048576
            echo   Executable size: !EXE_SIZE_MB! MB
        ) else (
            echo   Executable size: unknown
        )
    ) else (
        echo   !YELLOW!Warning: Executable not found at dist\!APP_NAME!.exe!RESET!
    )
)

REM Calculate build duration
set END_TIME=%TIME%

REM ============================================================================
REM Build success
REM ============================================================================
echo.
echo %GREEN%========================================%RESET%
echo %GREEN% BUILD SUCCESSFUL!%RESET%
echo %GREEN%========================================%RESET%
echo.
if "%BUILD_MODE%"=="onefile" (
    echo   Executable: dist\%APP_NAME%.exe
) else (
    echo   Directory: dist\%APP_NAME%\
)
echo.
echo   Config:     dist\config\
echo.
echo %CYAN%First time setup:%RESET%
echo   cd dist
echo   setup-daemon.bat    ^(if integrity files are missing^)
echo.
echo %CYAN%To run the daemon:%RESET%
echo   cd dist
echo   %APP_NAME%.exe
echo.
echo Or use: dist\run-daemon.bat
echo.
goto :end

REM ============================================================================
REM Build failed
REM ============================================================================
:build_failed
echo.
echo %RED%========================================%RESET%
echo %RED% BUILD FAILED!%RESET%
echo %RED%========================================%RESET%
echo.
echo Check the error messages above for details.
echo.
echo Common fixes:
echo   - Ensure Python 3.8+ is installed
echo   - Run: pip install pyinstaller
echo   - Run: pip install -r requirements.txt
echo   - Try: build.bat --clean
echo.
pause
exit /b 1

REM ============================================================================
REM Show help
REM ============================================================================
:show_help
echo.
echo Boundary Daemon Build Script
echo.
echo Usage: build.bat [options]
echo.
echo Options:
echo   --onefile     Create a single executable (default)
echo   --onedir      Create a directory with executable and dependencies
echo   --debug       Include debug symbols and console output
echo   --clean       Clean build artifacts before building
echo   --skip-deps   Skip dependency installation
echo   --help, -h    Show this help message
echo.
echo Examples:
echo   build.bat                  Build single executable
echo   build.bat --clean          Clean and build
echo   build.bat --onedir         Build as directory
echo   build.bat --debug --clean  Debug build with clean
echo.
exit /b 0

:end
endlocal
