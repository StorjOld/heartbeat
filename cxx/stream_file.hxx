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
	
	virtual size_t bytes_remaining()
	{
		size_t start = _in.tellg();
		_in.seekg(0,_in::end);
		size_t end = _in.tellg();
		_in.seekg(start);
		return end-start;
	}
private:
	std::istream &_in;
};