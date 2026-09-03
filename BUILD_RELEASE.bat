@echo off
title Build JNUKECRYPT Private
echo ==========================================
echo       BUILD JNUKECRYPT PRIVATE
echo              .NET 8 / win-x64
echo ==========================================
echo.
dotnet restore
if errorlevel 1 goto :erro
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
if errorlevel 1 goto :erro
echo.
echo BUILD CONCLUIDO.
echo.
echo EXE:
echo bin\Release\net8.0\win-x64\publish\JNukeCrypt.exe
echo.
pause
exit /b 0
:erro
echo.
echo ERRO AO COMPILAR.
echo Verifique se o .NET 8 SDK esta instalado.
pause
exit /b 1
