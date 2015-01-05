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

/*

This is an implementation of a privately verifiable HLA scheme as seen in

Shacham, Waters, "Compact Proofs of Retrievability"

*/

#pragma once

#include <stdexcept>

#include "heartbeat.hxx"
#include "seekable_file.hxx"
#include "prf.hxx"
#include "serializable.hxx"
#include "pointer.hxx"

// for encryption / decryption of state information
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>



class shacham_waters_private_data 
{
public:
	static const unsigned int key_size = 32;
	
	class safe_integer : public CryptoPP::Integer
	{
	public:
		safe_integer(CryptoPP::BufferedTransformation &bt, size_t byteCount)
		{
			if (byteCount > max_size)
			{
				throw std::runtime_error("Maximum integer size exceeded");
			}
			if (bt.MaxRetrievable() < byteCount)
			{
				throw std::runtime_error("Integer not retrievable.");
			}
			Decode(bt,byteCount);
		}
	private:
		static const unsigned int max_size = 1024;
	};

	class tag : public serializable 
	{
	public:
		std::vector<CryptoPP::Integer> &sigma() { return _sigma; }
		const std::vector<CryptoPP::Integer> &sigma() const { return _sigma; }
		
		virtual void serialize(CryptoPP::BufferedTransformation &bt) const;
		virtual void deserialize(CryptoPP::BufferedTransformation &bt);
	
	private:
		std::vector<CryptoPP::Integer> _sigma;
	};
	
	class state : public serializable 
	{
	public:
		static const unsigned int max_raw_size = 2048;
	
		state() : _n(0), _raw_sz(0), _encrypted_and_signed(false)  {}
		
		state(const state &s);
		
		void copy(const state &s);
		
		state& operator=(const state &other);
	
		unsigned int get_n() const { return _n; }
		void set_n(unsigned int n) { _n = n; }
		
		void serialize(CryptoPP::BufferedTransformation &bt) const;
		void deserialize(CryptoPP::BufferedTransformation &bt);
		
		bool encrypted() const { return _encrypted_and_signed; }
		void encrypt_and_sign(byte k_enc[shacham_waters_private_data::key_size],byte k_mac[shacham_waters_private_data::key_size],bool convergent_encryption = false);
		bool check_sig_and_decrypt(byte k_enc[shacham_waters_private_data::key_size],byte k_mac[shacham_waters_private_data::key_size]);
		void public_interpretation();
		
		CryptoPP::Integer f(unsigned int i) const;
		CryptoPP::Integer alpha(unsigned int i) const;
		
		void set_f_limit(CryptoPP::Integer limit) { _f.set_limit(limit); }
		void set_alpha_limit(CryptoPP::Integer limit) { _alpha.set_limit(limit); }
		
		void set_f_key(unsigned char* key,unsigned int key_length) { _f.set_key(key,key_length); }
		void set_alpha_key(unsigned char* key,unsigned int key_length) { _alpha.set_key(key,key_length); }
		
	private:
		unsigned int _n;
		
		prf _alpha;
		prf _f;
		
		smart_buffer _raw;
		unsigned int _raw_sz;
		bool _encrypted_and_signed;
	};
	
	class challenge : public serializable 
	{
	public:
		challenge() :  _l(0), _key_sz(0) {}
	
		unsigned int get_l() const { return _l; }
		void set_l(unsigned int l) { _l = l; }
		
		void set_v_limit(const CryptoPP::Integer &limit) { _v_max = limit; }
		const CryptoPP::Integer& get_v_limit() const { return _v_max; }
		
		void set_key(const unsigned char* key,unsigned int key_length);
		const unsigned char *get_key() const {return _key.get(); }
		unsigned int get_key_size() const { return _key_sz; }
		
		void serialize(CryptoPP::BufferedTransformation &bt) const;
		void deserialize(CryptoPP::BufferedTransformation &bt);
		
	private:
		unsigned int _l;
		CryptoPP::Integer _v_max;
		smart_buffer _key;
		unsigned int _key_sz;
	};
	
	class proof : public serializable
	{
	public:
		std::vector<CryptoPP::Integer> &mu() { return _mu; }
		const std::vector<CryptoPP::Integer> &mu() const { return _mu; }
		
		CryptoPP::Integer &sigma() { return _sigma; }
		const CryptoPP::Integer &sigma() const { return _sigma; }
		
		void serialize(CryptoPP::BufferedTransformation &bt) const;
		void deserialize(CryptoPP::BufferedTransformation &bf);
		
	private:
		std::vector<CryptoPP::Integer> _mu;
		CryptoPP::Integer _sigma;
	};
};

class shacham_waters_private : public heartbeat<shacham_waters_private_data,shacham_waters_private>, public serializable
{	
public:
	shacham_waters_private() 
		: 
		_public(false), 
		_sectors(0), 
		_sector_size(0),
		_check_fraction(1.0)
	{}
	
	void gen()
	{
		init();
	}

	void init(double check_fraction = 1.0, unsigned int sectors = 10, unsigned int prime_size_bytes = 128);
	
	void get_public(shacham_waters_private &h) const;
	
	// gets the tag and state into t and s for file f
	void encode(tag &t, state &s, simple_file &f);
	
	// gets a challenge for the beat
	void gen_challenge(challenge &c, const state &s);
	
	// generates a challenge for the beat with some specific parameters for this scheme
	// l is the number of chunks to check for, defaulting to n, and B is the basis for 
	// the challenge vector, defaulting to p
	void gen_challenge(challenge &c, unsigned int l, const CryptoPP::Integer &B);
	
	// gets a proof of storage for the file
	void prove(proof &p, seekable_file &f, const challenge &c,const tag &t);
	
	// verifies that a proof is correct
	bool verify(const proof &p,const challenge &c, const state &s);
	
	void serialize(CryptoPP::BufferedTransformation &bt) const;
	void deserialize(CryptoPP::BufferedTransformation &bt);
	
private:
	bool _public;
	byte _k_enc[shacham_waters_private_data::key_size];
	byte _k_mac[shacham_waters_private_data::key_size];

	unsigned int _sectors;
	size_t _sector_size;
	double _check_fraction;
	
	CryptoPP::Integer _p;
	
	static const byte _flag_public = 0x01;
};
