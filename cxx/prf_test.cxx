#include "prf.hxx"
#include <iostream>
#include <cryptopp/osrng.h>

int main()
{
	prf f;
	CryptoPP::AutoSeededRandomPool rng;
	byte key[32];
	
	CryptoPP::Integer limit(rng,0,CryptoPP::Integer::Power2(32*8),CryptoPP::Integer::RandomNumberType::PRIME);
	
	f.set_limit(limit);
	
	rng.GenerateBlock(key,32);
	
	f.set_key(key,32);
	
	std::cout << "p    = " << std::hex << limit << std::endl;
	
	for (int j=0;j<2;j++)
	{
		for (int i=0;i<10;i++)
		{
			std::cout << "r[" << i << "] = " << std::hex << f.evaluate(i) << std::endl;
		}
	}
}