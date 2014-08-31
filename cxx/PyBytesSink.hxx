#pragma once

#include <cryptopp/cryptlib.h>
#pragma once

#include <cryptopp/filters.h>
#include <Python.h>

class PyBytesSink : public CryptoPP::Bufferless<CryptoPP::Sink>
{
public:
	PyBytesSink()
		: _offset(0)
	{
		_buffer = PyBytes_FromStringAndSize(0,0);
	}
	
	size_t Put2(const byte *begin, size_t length, int messageEnd, bool blocking)
	{
		if (length > 0)
		{
			size_t size = PyBytes_GET_SIZE(_buffer);
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
		if (_PyBytes_Resize(&_buffer,n))
		{
			throw std::runtime_error("Unable to resize PyBytesSink");
		}
	}
	
	void append(const byte *begin,size_t n)
	{
		char *c_ptr;
		size_t size = PyBytes_GET_SIZE(_buffer);
		if (_offset + n > size)
		{
			// resize
			reserve(n);
		}
		PyBytes_AsStringAndSize(_buffer,&c_ptr,0);
		memcpy(c_ptr+_offset,begin,n);
	}
	
	Py::Bytes finish()
	{
		return Py::Bytes( _buffer, true ); 
	}
private:
	PyObject *_buffer;
	size_t _offset;
};