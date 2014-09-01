//implements a basic file that can be read from

#pragma once

#include <cstddef>

class simple_file
{
public:
	virtual size_t read(unsigned char *buffer,size_t sz) = 0;
	
	virtual size_t seek(size_t i) = 0;
};