@echo off

rem Compile the Java program
javac tajnik.java

rem Check if compilation was successful
if %errorlevel% equ 0 (
    echo Compilation successful.
) else (
    echo Compilation failed.
    exit /b 1
)

rem Initialize the database
java tajnik init passwords.txt

rem Add passwords
java tajnik put passwords.txt masterPass fer.hr ferPass
java tajnik put passwords.txt masterPass youtube.com ytPassword
java tajnik put passwords.txt masterPass adresa.hr adresaPass

rem Get passwords
echo Trying to access fer.hr with correct master password:
java tajnik get passwords.txt masterPass fer.hr
echo.

echo Trying to access youtube.com with correct master password:
java tajnik get passwords.txt masterPass youtube.com
echo.

echo Trying to access youtube.com with wrong master password:
java tajnik get passwords.txt wrongMasterPassword youtube.com
echo.

echo Trying to add password with wrong master password:
java tajnik put passwords.txt wrongMasterPassword youtube.com imposterPassword
echo.

echo Trying to access wrong address with correct master password:
java tajnik get passwords.txt masterPass wrongAddress
echo.

rem Pause 
pause