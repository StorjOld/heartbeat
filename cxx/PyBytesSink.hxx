/*

The MIT License (MIT)

Copyright (c) 2014 William T. James

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

#pragma once

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <Python.h>
#include <CXX/Objects.hxx>
#include "PyArray.hxx"

#include <stdexcept>


class PyBytesSink : public CryptoPP::Bufferless<CryptoPP::Sink>
{
public:
	PyBytesSink()
		: _offset(0)
	{
		_buffer = py_from_string_and_size(0,0);
	}
	
	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking)
	{
		if (length > 0)
		{
			size_t size = py_get_size(_buffer);
			if (length < _offset && _offset + length > size)
			{
				reserve(2*_offset);
			}
			append(begin,length);
		}
		return 0;
	}
	
	void reserve(size_t n = 0)
	{
		if (py_resize(&_buffer,n))
		{
			throw std::runtime_error("Unable to resize PyBytesSink");
		}
	}
	
	void append(const byte *begin,size_t n)
	{
		char *c_ptr;
		size_t size = py_get_size(_buffer);
		if (_offset + n > size)
		{
			// resize
			reserve(n);
		}
		py_as_string_and_size(_buffer,&c_ptr,0);
		memcpy(c_ptr+_offset,begin,n);
	}
	
	py_array finish()
	{
		return py_array( _buffer, true ); 
	}
private:
	PyObject *_buffer;
	size_t _offset;
};