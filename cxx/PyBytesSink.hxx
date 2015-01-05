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
#include <sstream>

class PyBytesSink : public CryptoPP::Bufferless<CryptoPP::Sink>
{
public:
	PyBytesSink()
		: _offset(0)
	{
		_buffer = py_from_string_and_size(0,4);
		if (!_buffer)
		{
			throw std::runtime_error("Unable to create python array object");
		}
		//std::cout << "Created python buffer object at: " << std::hex << (int)_buffer << " with reference count " << _buffer->ob_refcnt << std::endl;
	}
	
	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking)
	{
		//std::cout << "entered PyBytesSink::Put2()" << std::endl;
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
		//std::cout << "Attempting to resize buffer: " << std::hex << (int)_buffer << " to have length " << n << " bytes." << std::endl;
		//std::cout << "Reference count: " << _buffer->ob_refcnt << std::endl;
		if (py_resize(&_buffer,n))
		{
			std::stringstream msg;
			msg << "Unable to resize PyBytesSink.  Requested size: " << n;
			throw std::runtime_error(msg.str());
		}
		//std::cout << "Buffer resized to: " << std::hex << (int)_buffer << std::endl;
	}
	
	void append(const byte *begin,size_t n)
	{
		//std::cout << "entered PyBytesSink::append()" << std::endl;
		char *c_ptr;
		Py_ssize_t size = py_get_size(_buffer);
		if (_offset + n > (size_t)size)
		{
			// resize
			reserve(_offset + n);
		}
		if (py_as_string_and_size(_buffer,&c_ptr,&size))
		{
			throw std::runtime_error("AsStringAndSize failed in PyBytesSink::append.");
		}
		memcpy(c_ptr+_offset,begin,n);
		_offset += n;
	}
	
	py_array finish()
	{
		//std::cout << "Attempting to resize buffer: " << std::hex << (int)_buffer << " to have length " << _offset << " bytes." << std::endl;
		//std::cout << "Reference count: " << _buffer->ob_refcnt << std::endl;
		if (py_resize(&_buffer,_offset))
		{
			std::stringstream msg;
			msg << "Unable to resize PyBytesSink.  Requested size: " << _offset;
			throw std::runtime_error(msg.str());
		}
		//std::cout << "Buffer resized to: " << std::hex << (int)_buffer << std::endl;
		//std::cout << "PyBytesSink finished." << std::endl;
		return py_array( _buffer, true ); 
	}
private:
	PyObject *_buffer;
	size_t _offset;
};
