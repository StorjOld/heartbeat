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

#include <Python.h>
#include <CXX/Objects.hxx>
#include "PyArray.hxx"
#include "simple_file.hxx"

class PythonSeekableFile : public seekable_file
{
public:
	PythonSeekableFile(Py::Object file) : _file(file) 
	{
		/*
		if (!_file.callMemberFunction("seekable").isTrue())
		{
			throw std::runtime_error("File must be seekable.");
		}
		*/
	}
	
	virtual size_t read(unsigned char *buffer,size_t sz)
	{
		//std::cout << "Reading " << sz << " bytes...";
		std::string bytes = py_array(_file.callMemberFunction("read",Py::TupleN(Py::Long((long)sz))));
		//std::cout << "done. Read " << bytes.c_str() << " bytes" << std::endl;
		memcpy(buffer,bytes.c_str(),bytes.length());
		return bytes.length();
	}
	
	virtual size_t seek(size_t i)
	{
		_file.callMemberFunction("seek",Py::TupleN(Py::Long((long)i)));
		return (long)Py::Long(_file.callMemberFunction("tell"));
	}
	
	virtual size_t bytes_remaining()
	{
		size_t start = (long)Py::Long(_file.callMemberFunction("tell"));
		_file.callMemberFunction("seek",Py::TupleN(Py::Long(0L),Py::Long(2L)));
		size_t end = (long)Py::Long(_file.callMemberFunction("tell"));
		_file.callMemberFunction("seek",Py::TupleN(Py::Long((long)start)));
		return end-start;
	}
private:
	Py::Object _file;
	Py::Callable _read;
	Py::Callable _seek;
};
