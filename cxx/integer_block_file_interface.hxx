#pragma once

#include <pbc/pbc.h>
#include <cryptopp/integer.h>
#include "block_file.hxx"

class integer_block_file_interface
{
public:
	integer_block_file_interface(block_file &f) : _f(f) {}

	CryptoPP::Integer get_sector(unsigned int i, unsigned int j = 0)
	{
		CryptoPP::Integer result;
		
		result.Decode(_f.get_sector(i,j),_f.get_sector_size(i,j));
		
		return result;
	}
private:
	block_file &_f;
};