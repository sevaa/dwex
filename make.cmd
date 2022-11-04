@echo off
git diff-index --quiet HEAD --
if errorlevel 1 echo Uncommitted changes! & pause & goto EOF

git log --pretty=format:%%H -n 1 >hash.txt
set /p HASH= <hash.txt
del hash.txt

python -c "import dwex.__main__;print('.'.join(str(x) for x in dwex.__main__.version))" >ver.txt
set /p VER= <ver.txt
del ver.txt

echo %HASH% %VER% >>archive\history.txt

del /q dist\*.*
echo cookie='%HASH%' >dwex\cookie.py
python setup.py sdist
echo cookie=False >dwex\cookie.py
twine upload -u sevaa dist/*
if errorlevel 1 pause 