#include "private_hla.hxx"
#include "stream_block_file.hxx"

#include <config.h>

#include <iostream>
#include <fstream>

const char default_file[] = "files/test.txt";

int main(int argc,char *argv[])
{	
	const char *filename = default_file;
	if (argc > 1)
	{
		filename = argv[1];
	}
	std::ifstream ifs(filename,std::ifstream::in|std::ifstream::binary);
	
	stream_block_file sbf(ifs);

	std::string raw_tag;
	std::string raw_state;
	std::string raw_challenge;
	std::string raw_proof;
	std::string p_hla;
	std::string s_hla;
	
	{
		// client context
		private_hla s_test;
	
		private_hla::tag t;
		private_hla::state s;
	
		s_test.gen();
	
		s_test.encode(t,s,sbf);	
		ifs.seekg(0);
	
		private_hla p_test;
		s_test.get_public(p_test);
		
		t.serializep(new CryptoPP::StringSink(raw_tag));
		s.serializep(new CryptoPP::StringSink(raw_state));
		p_test.serializep(new CryptoPP::StringSink(p_hla));
		s_test.serializep(new CryptoPP::StringSink(s_hla));
	}
	
	{
		// auditor context 1
		private_hla::challenge c;
		private_hla::state s;
		
		private_hla s_test;
		
		s_test.deserializep(new CryptoPP::StringSource(s_hla,true));
		s.deserializep(new CryptoPP::StringSource(raw_state,true));
		
		s_test.gen_challenge(c,s);
		
		c.serializep(new CryptoPP::StringSink(raw_challenge));
	}
	
	{
		// server context
		private_hla::challenge c;
		private_hla::proof p;
		private_hla::tag t;
	
		private_hla p_test;
		
		p_test.deserializep(new CryptoPP::StringSource(p_hla,true));
		c.deserializep(new CryptoPP::StringSource(raw_challenge,true));
		t.deserializep(new CryptoPP::StringSource(raw_tag,true));
	
		p_test.prove(p,c,sbf,t);
		
		p.serializep(new CryptoPP::StringSink(raw_proof));
	}
	
	{
		// auditor context 2
		private_hla::challenge c;
		private_hla::state s;
		private_hla::proof p;
		
		private_hla s_test;
		
		s_test.deserializep(new CryptoPP::StringSource(s_hla,true));
		s.deserializep(new CryptoPP::StringSource(raw_state,true));
		p.deserializep(new CryptoPP::StringSource(raw_proof,true));
		
		if (s_test.verify(p,c,s))
		{
			std::cout << "Proof verified." << std::endl;
		}
		else
		{
			std::cout << "Proof failed." << std::endl;
		}
	}
	
	return 0;
}