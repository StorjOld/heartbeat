#
# The MIT License (MIT)
#
# Copyright (c) 2014 William T. James
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

from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

copt = {'mingw32' : ['-std=c++11'],
		'unix' : ['-std=c++11'],
		'msvc' : ['/EHsc']}
lopt = {}
libs = {'mingw32' : ['cryptopp'],
		'unix' : ['cryptopp'],
		'msvc' : ['cryptlib']}

class build_ext_subclass( build_ext ):
	def build_extensions(self):
		c = self.compiler.compiler_type
		print("Compiling with "+c)
		if c in copt:
			for e in self.extensions:
				e.extra_compile_args = copt[ c ]
		if c in lopt:
			for e in self.extensions:
				e.extra_link_args = lopt[ c ]
		if c in libs:
			for e in self.extensions:
				e.libraries = libs[ c ]
		build_ext.build_extensions(self)

swpriv_sources = ['cxx/shacham_waters_private.cxx','cxx/SwPriv.cxx']
pycxx_sources = ['cxx/pycxx/Src/cxxsupport.cxx','cxx/pycxx/Src/cxx_extensions.cxx','cxx/pycxx/Src/cxxextensions.c','cxx/pycxx/Src/IndirectPythonInterface.cxx']

all_sources = swpriv_sources + pycxx_sources
	

swpriv = Extension('heartbeat.SwPriv',
                    define_macros = [('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                    include_dirs = ['cxx/pycxx'],
                    #libraries = ['cryptopp'],
                    #library_dirs = ['/usr/local/lib'],
                    sources = all_sources);
					
setup (name = 'SwPriv',
       version = '1.0',
       description = 'Private homomorphic authenticator based proof of storage.',
       author = 'William T. James',
       author_email = 'jameswt@gmail.com',
       url = '',
       long_description = '''
Implements a privately verifiable homomorphic authentication scheme from Shacham and Waters
''',
       ext_modules = [swpriv],
	   cmdclass = {'build_ext' : build_ext_subclass})

setup (name = 'Merkle',
       version = '1.0',
       description = 'Private hash tree authenticator based proof of storage.',
       author = 'William T. James',
       author_email = 'jameswt@gmail.com',
       url = '',
       long_description = '''
Implements a merkle hash tree authentication scheme.
''',
        package_dir = {'heartbeat':''},
        py_modules = ['heartbeat.Merkle','heartbeat.MerkleTree'])
	  