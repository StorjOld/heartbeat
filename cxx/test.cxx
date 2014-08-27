#include "shacham_waters_private.hxx"
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
		shacham_waters_private s_test;
	
		shacham_waters_private::tag t;
		shacham_waters_private::state s;
	
		s_test.gen();
	
		s_test.encode(t,s,sbf);	
		ifs.seekg(0);
	
		shacham_waters_private p_test;
		s_test.get_public(p_test);
		
		t.serializep(new CryptoPP::StringSink(raw_tag));
		s.serializep(new CryptoPP::StringSink(raw_state));
		p_test.serializep(new CryptoPP::StringSink(p_hla));
		s_test.serializep(new CryptoPP::StringSink(s_hla));
	}
	
	{
		// auditor context 1
		shacham_waters_private::challenge c;
		shacham_waters_private::state s;
		
		shacham_waters_private s_test;
		
		s_test.deserializep(new CryptoPP::StringSource(s_hla,true));
		s.deserializep(new CryptoPP::StringSource(raw_state,true));
		
		s_test.gen_challenge(c,s);
		
		c.serializep(new CryptoPP::StringSink(raw_challenge));
	}
	
	{
		// server context
		shacham_waters_private::challenge c;
		shacham_waters_private::proof p;
		shacham_waters_private::tag t;
	
		shacham_waters_private p_test;
		
		p_test.deserializep(new CryptoPP::StringSource(p_hla,true));
		c.deserializep(new CryptoPP::StringSource(raw_challenge,true));
		t.deserializep(new CryptoPP::StringSource(raw_tag,true));
	
		p_test.prove(p,c,sbf,t);
		
		p.serializep(new CryptoPP::StringSink(raw_proof));
	}
	
	{
		// auditor context 2
		shacham_waters_private::challenge c;
		shacham_waters_private::state s;
		shacham_waters_private::proof p;
		
		shacham_waters_private s_test;
		
		s_test.deserializep(new CryptoPP::StringSource(s_hla,true));
		p.deserializep(new CryptoPP::StringSource(raw_proof,true));
		c.deserializep(new CryptoPP::StringSource(raw_challenge,true));
		s.deserializep(new CryptoPP::StringSource(raw_state,true));
		
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