//implements a basic file that can be read from

#pragma once

#include "simple_file.hxx"

#include <iostream>

class stream_file : public simple_file
{
public:
	stream_file(std::istream &in) : _in(in) 
	{}
	
	virtual size_t read(unsigned char *buffer,size_t sz)
	{
		_in.read((char*)buffer,sz);
		_in.clear();
		return _in.gcount();
	}
	
	virtual size_t seek(size_t i)
	{
		_in.seekg(i);
		return _in.tellg();
	}
private:
	std::istream &_in;
};