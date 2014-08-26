#include <iostream>

#include <cryptopp/integer.h>
#include "endian_swap.h"

class heartbeat_binary_serializer
{
public:
	heartbeat_binary_serializer(CryptoPP::BufferedTransformation) : _out(o) {}
	
	void write(CryptoPP::Integer i)
	{
		// write the size as 32 bit integer in big endian format
		unsigned int n = htonl(i.MinEncodedSize());
		
		_out.write(&n,sizeof(unsigned int));
		
		// encode integer
		
	}
	
	void write(unsigned int i)
	{
	}
private:
	std::ostream &_out;
};

class heartbeat_binary_reader
{
public:
	heartbeat_binary_reader(std::istream &i) : _in(i) {}
	
	void read(CryptoPP::Integer &i)
	{
	}
	
	void read(unsigned int &i)
	{
	}
private:
	std::istream &_in;
};