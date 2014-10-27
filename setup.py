#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Heartbeat: https://github.com/Storj/heartbeat
#
# The MIT License (MIT)
#
# Copyright (c) 2014 Paul Durivage, William T. James
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext

with open('heartbeat/version.py','r') as f:
    exec(f.read())

copt = {'mingw32': [],
        'unix': [],
        'msvc': ['/EHsc']}
lopt = {}
libs = {'mingw32': ['cryptopp'],
        'unix': ['cryptopp'],
        'msvc': ['cryptlib']}
        
class build_ext_subclass(build_ext):
    def build_extensions(self):
        c = self.compiler.compiler_type
        print("Compiling with "+c)
        if c in copt:
            for e in self.extensions:
                e.extra_compile_args = copt[c]
        if c in lopt:
            for e in self.extensions:
                e.extra_link_args = lopt[c]
        if c in libs:
            for e in self.extensions:
                e.libraries = libs[c]
        build_ext.build_extensions(self)

swizzle_sources = ['cxx/shacham_waters_private.cxx', 'cxx/Swizzle.cxx', 'cxx/base64.cxx']
pycxx_sources = ['cxx/pycxx/Src/cxxsupport.cxx',
                 'cxx/pycxx/Src/cxx_extensions.cxx',
                 'cxx/pycxx/Src/cxxextensions.c',
                 'cxx/pycxx/Src/IndirectPythonInterface.cxx']

all_sources = swizzle_sources + pycxx_sources

swizzle = Extension('heartbeat.Swizzle',
                    include_dirs=['cxx/pycxx','cxx'],
                    sources=all_sources)

setup(
    name='storj-heartbeat',
    version=__version__,
    url='https://github.com/Storj/heartbeat',
    license='The MIT License',
    author='Storj Labs',
    author_email='info@storj.io',
    description='Python library for verifying existence of a file',
    install_requires=[
        'pycrypto >= 2.6.1',
    ],
    packages=['heartbeat', 'heartbeat.Merkle', 'heartbeat.OneHash', 'heartbeat.PySwizzle'],
    ext_modules=[swizzle],
    cmdclass={'build_ext': build_ext_subclass}
)
