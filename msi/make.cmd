@echo off

rem MSITOOLS is expected to be C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x86

cd ..
python -c "import dwex.__main__;print('.'.join(str(x) for x in dwex.__main__.version))" >ver.txt
set /p VER= <ver.txt
del ver.txt
echo Version %VER%
cd msi
powershell MSISetProp.ps1 -Path %CD%\DWEXMin-x64.msi -Property ProductVersion -Value %VER%

copy DWEXMin-x64.msi DWEXMin-x86.msi
copy DWEXMin-x64.msi DWEXMin-arm.msi
copy DWEXMin-x64.msi DWEXMin-arm64.msi
"%MSITOOLS%\msiinfo.exe" DWEXMin-x86.msi /p Intel;1033
"%MSITOOLS%\msiinfo.exe" DWEXMin-arm.msi /g 500
"%MSITOOLS%\msiinfo.exe" DWEXMin-arm.msi /p Arm;1033
"%MSITOOLS%\msiinfo.exe" DWEXMin-arm64.msi /g 500
"%MSITOOLS%\msiinfo.exe" DWEXMin-arm64.msi /p Arm64;1033

set D=ftp://ftp.yarxi.ru/public_html/yarxionline/temp/dwex/%VER%
powershell MakeFTPFolder -URL %D%

set D=%D%/
powershell UpFile -Src DWEXMin-x64.msi -Dest %D%
powershell UpFile -Src DWEXMin-x86.msi -Dest %D%
powershell UpFile -Src DWEXMin-arm.msi -Dest %D%
powershell UpFile -Src DWEXMin-arm64.msi -Dest %D%

:EOF
