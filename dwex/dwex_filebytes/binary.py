# coding=utf-8
# Copyright 2018 Sascha Schirra
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" A ND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from .ctypes_helper import *
from struct import pack_into

from ctypes import *

class Container(object):

    def __init__(self, **args):
        setattr = super(Container, self).__setattr__
        for key, value in args.items():
            setattr(key, value)


class Binary(object):
    def __init__(self, fileName, fileContent=None):
        if fileContent:
            if type(fileContent[0]) != int:
                fileContent = to_ubyte_array(fileContent)
            self._bytes = fileContent
        else:
            self._bytes = self._readFile(fileName)
        if not self.__class__.isSupportedContent(self._bytes):
            raise BinaryError('Not a suitable filetype')

        self.__fileName = fileName


    @property
    def fileName(self):
        """
        Returns the filename
        """
        return self.__fileName

    @property
    def entryPoint(self):
        return 0x0

    @property
    def imageBase(self):
        return 0x0

    @property
    def type(self):
        return 'ELF'

    def _readFile(self, fileName):
        """
        Returns the bytes of the file.
        """
        with open(fileName, 'rb') as binFile:
            b = binFile.read()
            return to_ubyte_array(b)

    def assertFileRange(self, value):
        if type(value) == c_void_p:
            value = value.value

        file_data_pointer = get_ptr(self._bytes)
        assert value >= (file_data_pointer.value) and value <= (
            file_data_pointer.value + len(self._bytes)), 'Pointer not in file range'

    @classmethod
    def isSupportedFile(cls, fileName):
        try:
            with open(fileName, 'rb') as f:
                return cls.isSupportedContent(f.read())
        except BaseException as e:
            raise BinaryError(e)

    @classmethod
    def isSupportedContent(cls, fileContent):
        return False


class BinaryError(BaseException):
    pass
