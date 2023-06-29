@echo off

rem MSITOOLS is expected to be C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x86
rem Thumbprint.txt is supposed to exist and contain the thumbprint of the signing cert
rem TODO: sign aside from the master copy of the file

cd ..
python -c "import dwex.__main__;print('.'.join(str(x) for x in dwex.__main__.version))" >ver.txt
set /p VER= <ver.txt
del ver.txt
echo Version %VER%
cd msi
powershell MSISetProp.ps1 -Path %CD%\DWEXMin.msi -Property ProductVersion -Value %VER%

set /p THU= <Thumbprint.txt
echo Signing cert %THU%
if x%THU% == x echo No signing cert thumbprint & pause & goto EOF
"%MSITOOLS%\signtool.exe" sign /fd SHA256 /sha1 %THU%  DWEXMin.msi

set D=ftp://ftp.yarxi.ru/public_html/yarxionline/temp/dwex/%VER%
powershell MakeFTPFolder -URL %D%

set D=%D%/
powershell UpFile -Src DWEXMin.msi -Dest %D%

:EOF
