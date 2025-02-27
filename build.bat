@echo off
echo Building JWT Token Generator executable...

REM Check if the previous executable is still running and try to close it
taskkill /f /im JWT_Token_Generator.exe >nul 2>&1
echo Waiting for resources to be released...
timeout /t 2 >nul

echo Installing required packages...
pip install PyJWT cryptography pyinstaller pillow

REM Remove the old dist directory to avoid permission issues
if exist dist (
    echo Removing old build files...
    rmdir /s /q dist
    rmdir /s /q build
    del /f /q JWT_Token_Generator.spec
)

echo Packaging the application...
pyinstaller --noconfirm --onefile --windowed --icon=NONE --add-data "config.json;." --name "JWT_Token_Generator" token_generator_app.py

echo Build completed!
if exist dist\JWT_Token_Generator.exe (
    echo The executable can be found in the dist folder: JWT_Token_Generator.exe
    echo.
    echo Would you like to run the application now? (Y/N)
    choice /c YN /n
    if errorlevel 2 goto end
    if errorlevel 1 start "" "dist\JWT_Token_Generator.exe"
) else (
    echo Build failed. Please check the error messages above.
)

:end
pause