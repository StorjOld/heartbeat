#pragma once

#include <pbc/pbc.h>
#include <cryptopp/integer.h>
#include "block_file.hxx"


class integer_block_file_interface
{
public:
	integer_block_file_interface(block_file &f) : _f(f) {}

	void get_sector(mpz_t e, unsigned int i, unsigned int j = 0)
	{
		mpz_import(e,_f.get_sector_size(i,j),1,sizeof(unsigned char),0,0,_f.get_sector(i,j));
	}
	
	CryptoPP::Integer get_sector(unsigned int i, unsigned int j = 0)
	{
		CryptoPP::Integer result;
		
		result.Decode(_f.get_sector(i,j),_f.get_sector_size(i,j));
		
		return result;
	}
	
private:
	block_file &_f;
};