#pragma once

#include <Python.h>
#include "simple_file.hxx"

class PythonStreamFile : public simple_file
{
public:
	PythonStreamFile(Py::Object file) : _file(file) {}
	
	virtual size_t read(unsigned char *buffer,size_t sz)
	{
		//std::cout << "Reading " << sz << " bytes...";
		std::string bytes = Py::Bytes(_file.callMemberFunction("read",Py::TupleN(Py::Long((long)sz))));
		//std::cout << "done. Read " << bytes.c_str() << " bytes" << std::endl;
		memcpy(buffer,bytes.c_str(),bytes.length());
		return bytes.length();
	}
	
	virtual size_t seek(size_t i)
	{
		return (long)Py::Long(_file.callMemberFunction("seek",Py::TupleN(Py::Long((long)i))));
	}
private:
	Py::Object _file;
	Py::Callable _read;
	Py::Callable _seek;
};