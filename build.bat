@echo off
echo Building JWT Token Generator executable...

echo Installing required packages...
pip install PyJWT cryptography pyinstaller

echo Packaging the application...
pyinstaller --noconfirm --onefile --windowed --icon=NONE --add-data "config.json;." --name "JWT_Token_Generator" token_generator_app.py

echo Build completed!
echo The executable can be found in the dist folder: JWT_Token_Generator.exe
pause