/*

This is an implementation of a privately verifiable HLA scheme as seen in

Shacham, Waters, "Compact Proofs of Retrievability"

*/

#pragma once

#include "heartbeat.hxx"
#include "block_file.hxx"
#include "integer_block_file_interface.hxx"
#include "prf.hxx"
#include "serializable.hxx"

// for encryption / decryption of state information
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

#include <rapidjson/writer.h>
#include <rapidjson/reader.h>

class shacham_waters_private_data 
{
public:
	static const unsigned int key_size = 32;

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
		state() : _encrypted_and_signed(false) {}
		
		state(const state &s);
		
		void copy(const state &s);
		
		state& operator=(const state &other);
	
		unsigned int get_n() const { return _n; }
		void set_n(unsigned int n) { _n = n; }
		
		void serialize(CryptoPP::BufferedTransformation &bt) const;
		void deserialize(CryptoPP::BufferedTransformation &bt);
		
		void encrypt_and_sign(byte k_enc[shacham_waters_private_data::key_size],byte k_mac[shacham_waters_private_data::key_size]);
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
		
		std::unique_ptr<unsigned char> _raw;
		unsigned int _raw_sz;
		bool _encrypted_and_signed;
	};
	
	class challenge : public serializable 
	{
	public:
		unsigned int get_l() const { return _l; }
		void set_l(unsigned int l) { _l = l; }
		
		CryptoPP::Integer v(unsigned int i) const;
		CryptoPP::Integer i(unsigned int i) const;
		
		void set_v_limit(const CryptoPP::Integer &limit) { _v.set_limit(limit); }
		void set_i_limit(unsigned int limit) { _i.set_limit(CryptoPP::Integer(CryptoPP::Integer::POSITIVE,(CryptoPP::lword)limit)); }
		
		void set_key(unsigned char* key,unsigned int key_length) { _v.set_key(key,key_length); _i.set_key(key,key_length); }
		const unsigned char *get_key() const {return _v.get_key(); }
		unsigned int get_key_size() const { return _v.get_key_size(); }
		
		void serialize(CryptoPP::BufferedTransformation &bt) const;
		void deserialize(CryptoPP::BufferedTransformation &bt);
		
		const prf& get_v() const { return _v; }
		const prf& get_i() const { return _i; }
		
	private:
		unsigned int _l;
		prf _v;
		prf _i;
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
	typedef block_file file;
};

class shacham_waters_private : public heartbeat<shacham_waters_private_data,shacham_waters_private>, public serializable
{	
public:
	void gen()
	{
		init();
	}

	void init(unsigned int prime_size_bytes = 128, unsigned int sectors = 10);
	
	void get_public(shacham_waters_private &h) const;
	
	// gets the tag and state into t and s for file f
	void encode(tag &t, state &s, file &f);
	
	// gets a challenge for the beat
	void gen_challenge(challenge &c, const state &s);
	
	// generates a challenge for the beat with some specific parameters for this scheme
	// l is the number of chunks to check for, defaulting to n, and B is the basis for 
	// the challenge vector, defaulting to p
	bool gen_challenge(challenge &c, const state &s, unsigned int l, const CryptoPP::Integer &B);
	
	// gets a proof of storage for the file
	void prove(proof &p,const challenge &c, file &f,const tag &t);
	
	// verifies that a proof is correct
	bool verify(const proof &p,const challenge &c, const state &s);
	
	void serialize(CryptoPP::BufferedTransformation &bt) const;
	void deserialize(CryptoPP::BufferedTransformation &bt);
	
private:
	byte _k_enc[shacham_waters_private_data::key_size];
	byte _k_mac[shacham_waters_private_data::key_size];

	unsigned int _sectors;
	size_t _sector_size;
	
	CryptoPP::Integer _p;
};