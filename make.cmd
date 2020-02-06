@echo off
del /q dist\*.*
python setup.py sdist
twine upload -u sevaa dist/* 