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

#include "shacham_waters_private.hxx"
#include "stream_file.hxx"

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

		std::ifstream is(filename,std::ifstream::in|std::ifstream::binary);
		stream_file sf(is);
		
		s_test.encode(t,s,sf);
	
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
		shacham_waters_private::state s;
	
		shacham_waters_private p_test;
		
		p_test.deserializep(new CryptoPP::StringSource(p_hla,true));
		c.deserializep(new CryptoPP::StringSource(raw_challenge,true));
		t.deserializep(new CryptoPP::StringSource(raw_tag,true));
		s.deserializep(new CryptoPP::StringSource(raw_state,true));
	
		std::ifstream is(filename,std::ifstream::in|std::ifstream::binary);
		stream_file sf(is);
	
		p_test.prove(p,sf,c,t,s);
		
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