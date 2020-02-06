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


from struct import pack_into
import ctypes

def get_ptr(data, offset=None, ptr_type=ctypes.c_void_p):
    """Returns a void pointer to the data"""
    ptr = ctypes.cast(ctypes.pointer(data), ctypes.c_void_p)

    if offset:
        ptr = ctypes.c_void_p(ptr.value + offset)

    if ptr_type != ctypes.c_void_p:
        ptr = ctypes.cast(ptr, ptr_type)

    return ptr

def get_str(data, offset=None):
    return get_ptr(data, offset, ctypes.c_char_p).value.decode('ASCII')

def to_ubyte_array(barray):
    """Returns a c_ubyte_array filled with the given data of a bytearray or bytes"""
    bs = (ctypes.c_ubyte * len(barray))()
    pack_into('%ds' % len(barray), bs, 0, barray)

    return bs
