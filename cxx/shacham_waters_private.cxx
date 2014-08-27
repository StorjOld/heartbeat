#include "shacham_waters_private.hxx"
#include "endian_swap.h"

#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hex.h>

void shacham_waters_private_data::tag::serialize(CryptoPP::BufferedTransformation &bt) const
{
	unsigned int n = htonl(_sigma.size());
	
	bt.PutWord32(n);
	
	for (int i=0;i<_sigma.size();i++)
	{
		unsigned int sigma_sz = _sigma[i].MinEncodedSize();
		n = htonl(sigma_sz);
	
		bt.PutWord32(n);
		
		//std::cout << "Encoding sigma_" << i << " in " << sigma_sz << " bytes." << std::endl;
		_sigma[i].Encode(bt,sigma_sz);
	}
}

void shacham_waters_private_data::tag::deserialize(CryptoPP::BufferedTransformation &bt)
{
	unsigned int n;
	
	bt.GetWord32(n);
	
	n = ntohl(n);
	
	_sigma.clear();
	_sigma.resize(n);
	for (int i=0;i<_sigma.size();i++)
	{
		bt.GetWord32(n);
		
		n = ntohl(n);
		
		//std::cout << "Decoding sigma_" << i << " in " << n << " bytes." << std::endl;
		_sigma[i].Decode(bt,n);
	}
}

shacham_waters_private_data::state::state(const state &s)
{
	copy(s);
}

void shacham_waters_private_data::state::copy(const state &s) 
{
	_n = s._n;
	_alpha = s._alpha;
	_f = s._f;
	if (s._raw)
	{
		_raw_sz = s._raw_sz;
		_raw = std::unique_ptr<unsigned char>(new unsigned char[_raw_sz]);
		memcpy(_raw.get(),s._raw.get(),_raw_sz);
	}
	_encrypted_and_signed = s._encrypted_and_signed;
}

shacham_waters_private_data::state& shacham_waters_private_data::state::operator=(const shacham_waters_private_data::state &other)
{
	copy(other);
	return *this;
}

inline CryptoPP::Integer shacham_waters_private_data::state::f(unsigned int i) const
{
	return _f.evaluate(i);
}

inline CryptoPP::Integer shacham_waters_private_data::state::alpha(unsigned int i) const
{
	return _alpha.evaluate(i);
}

void shacham_waters_private_data::state::serialize(CryptoPP::BufferedTransformation &bt) const
{
	if (!_encrypted_and_signed)
	{
		throw std::runtime_error("in shacham_waters_private_data::serialize, state must be encrypted prior to serialization.");
	}
	
	// write the raw data size
	unsigned int n = htonl(_raw_sz);
	bt.PutWord32(n);
	
	// write the raw data
	bt.Put(_raw.get(),_raw_sz);
}

void shacham_waters_private_data::state::deserialize(CryptoPP::BufferedTransformation &bt)
{
	unsigned int n;
	
	// get the size of the raw data
	bt.GetWord32(n);
	_raw_sz = ntohl(n);
	
	_raw = std::unique_ptr<unsigned char>(new unsigned char[_raw_sz]);
	
	// get the raw data
	bt.Get(_raw.get(),_raw_sz);
	
	_encrypted_and_signed = true;
}

void shacham_waters_private_data::state::encrypt_and_sign(byte k_enc[shacham_waters_private_data::key_size],byte k_mac[shacham_waters_private_data::key_size])
{
	CryptoPP::CFB_Mode< CryptoPP::AES >::Encryption e;
	CryptoPP::HMAC< CryptoPP::SHA256 > hmac(k_mac,shacham_waters_private_data::key_size);
	CryptoPP::AutoSeededRandomPool rng;
	// generate an IV
	unsigned int iv_sz = e.DefaultIVLength();
	std::unique_ptr<unsigned char> iv(new unsigned char[iv_sz]);
	rng.GenerateBlock(iv.get(),iv_sz);
	
	e.SetKeyWithIV(k_enc,shacham_waters_private_data::key_size,iv.get(),iv_sz);
	
	// raw format:
	// [signed_size,signed_data([n,iv_size,iv,encrypted_size,encrypted_data([f_key_size,f_key,alpha_key_size,alpha_key])]),mac_size,mac]
	
	// raw size:
	// signed_size : 4 bytes
	// n : 4 bytes
	// iv_size : 4 bytes
	// iv : iv_size bytes
	// encrypted_size : 4 bytes
	// f_key_size : 4 bytes
	// f_key : key_size bytes
	// alpha_key_size : 4 bytes
	// alpha_key : alpha_size bytes
	// mac_size : 4 bytes
	// mac : mac_size bytes
	
	std::string raw_data;
	std::string sig_data;
	std::string enc_data;
	std::string mac;
	
	// encrypted data
	CryptoPP::StreamTransformationFilter ef(e,
		new CryptoPP::StringSink(enc_data));
	
	// put key size
	unsigned int n = htonl(_f.get_key_size());
	ef.PutWord32(n);
	// put key
	ef.Put(_f.get_key(),_f.get_key_size());
	
	n = htonl(_alpha.get_key_size());
	ef.PutWord32(n);
	ef.Put(_alpha.get_key(),_alpha.get_key_size());
	
	ef.MessageEnd();
	// finished encrypting
	
	// signed data
	CryptoPP::StringSink sig_sink(sig_data);
	
	// put n
	n = htonl(_n);
	sig_sink.PutWord32(n);
	
	// put iv size
	n = htonl(iv_sz);
	sig_sink.PutWord32(n);
	
	// put iv
	sig_sink.Put(iv.get(),iv_sz);
	
	// now put encrypted length into signed data	
	n = htonl(enc_data.length());
	sig_sink.PutWord32(n);
	
	// redirect encrypted data to the sink now we've put the number of bytes
	CryptoPP::StringSource(enc_data,true,
		new CryptoPP::Redirector(sig_sink));
	
	sig_sink.MessageEnd();
	
	// now encoded should have tag, we sign it
	CryptoPP::StringSource(sig_data, true,
		new CryptoPP::HashFilter(hmac,
			new CryptoPP::StringSink(mac)));
	
	// fininshed signing, now copy to raw
	
	// raw construction
	CryptoPP::StringSink raw_sink(raw_data);
	
	// put the sig length
	n = htonl(sig_data.length());
	raw_sink.PutWord32(n);
	
	// put the sig data
	CryptoPP::StringSource(sig_data, true,
		new CryptoPP::Redirector(raw_sink));
	
	// put mac length
	n = htonl(mac.length());
	raw_sink.PutWord32(n);
	
	// put mac
	CryptoPP::StringSource(mac, true,
		new CryptoPP::Redirector(raw_sink));
	
	raw_sink.MessageEnd();
	
	/*
	std::string str0,str1,str2;
	
	std::cout << "during encoding: " << std::endl;
	CryptoPP::StringSource s0(k_mac, shacham_waters_private_data::key_size, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str0),true,2,":"));
	std::cout << "key = " << str0 << std::endl;
	std::cout << "sig_data.length() = " << sig_data.length() << std::endl;
	CryptoPP::StringSource s1(sig_data, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str1),true,2,":"));
	std::cout << "sig_data = " << str1 << std::endl;
	std::cout << "mac.length() = " << mac.length() << std::endl;
	CryptoPP::StringSource s2(mac, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str2),true,2,":"));
	std::cout << "mac = " << str2 << std::endl;
	*/
	
	// now write raw
	_raw_sz = raw_data.length();
	_raw = std::unique_ptr<unsigned char>(new unsigned char[_raw_sz]);
	
	memcpy(_raw.get(),raw_data.c_str(),_raw_sz);
	
	_encrypted_and_signed = true;
}

bool shacham_waters_private_data::state::check_sig_and_decrypt(byte k_enc[shacham_waters_private_data::key_size],byte k_mac[shacham_waters_private_data::key_size])
{
	//std::cout << "Checking signature..." << std::endl;
	if (!_encrypted_and_signed)
	{
		throw std::runtime_error("in shacham_waters_private_data::state::check_sig_and_decrypt, data must be encrypted before decryption and checking signature.");
	}
	
	CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption d;
	CryptoPP::HMAC< CryptoPP::SHA256 > hmac(k_mac,shacham_waters_private_data::key_size);

	CryptoPP::StringSource raw_source(_raw.get(),_raw_sz,true);
	
	std::string sig_data;
	std::string mac_data;
	std::string enc_data;
	
	unsigned int n;
	
	// get signed data size
	raw_source.GetWord32(n);
	unsigned int sig_data_size = ntohl(n);
	
	// get signed data
	CryptoPP::StringSink sig_sink(sig_data);
	raw_source.TransferTo(sig_sink,(CryptoPP::lword)sig_data_size);
	
	// get mac size
	raw_source.GetWord32(n);
	unsigned int mac_size = ntohl(n);
	
	if (mac_size != hmac.DigestSize())
	{
		// mismatched mac sizes
		return false;
	}
	
	// get mac
	CryptoPP::StringSink mac_sink(mac_data);
	raw_source.TransferTo(mac_sink,(CryptoPP::lword)mac_size);
	
	/*
	std::string str0,str1,str2;
	
	std::cout << "during decoding: " << std::endl;
	CryptoPP::StringSource s0(k_mac, shacham_waters_private_data::key_size, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str0),true,2,":"));
	std::cout << "key = " << str0 << std::endl;
	std::cout << "sig_data.length() = " << sig_data.length() << std::endl;
	CryptoPP::StringSource s1(sig_data, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str1),true,2,":"));
	std::cout << "sig_data = " << str1 << std::endl;
	std::cout << "mac_data.length() = " << mac_data.length() << std::endl;
	CryptoPP::StringSource s2(mac_data, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str2),true,2,":"));
	std::cout << "mac_data = " << str2 << std::endl;
	*/
	
	// check signed data
	CryptoPP::HashVerificationFilter hf(hmac, NULL, CryptoPP::HashVerificationFilter::PUT_RESULT|CryptoPP::HashVerificationFilter::HASH_AT_END);
	
	CryptoPP::StringSource(sig_data+mac_data, true,
		new CryptoPP::Redirector(hf));
	
	if (!hf.GetLastResult())
	{
		// authentication failed
		return false;
	}
	
	
	// parse signed data
	CryptoPP::StringSource sig_source(sig_data,true);
	
	// get n
	sig_source.GetWord32(n);
	_n = ntohl(n);
	
	// get iv size
	sig_source.GetWord32(n);
	unsigned int iv_sz = ntohl(n);
	std::unique_ptr<unsigned char> iv(new unsigned char[iv_sz]);
	
	// get iv
	sig_source.Get(iv.get(),iv_sz);
	
	// set up decryption
	d.SetKeyWithIV(k_enc,shacham_waters_private_data::key_size,iv.get(),iv_sz);
	
	// get encrypted data size
	sig_source.GetWord32(n);
	unsigned int enc_sz = ntohl(n);
	
	CryptoPP::StreamTransformationFilter df(d);
	
	sig_source.TransferTo(df,(CryptoPP::lword)enc_sz);
	
	// get f_key size
	df.GetWord32(n);
	n = ntohl(n);
	std::unique_ptr<unsigned char> key(new unsigned char[n]);
	
	df.Get(key.get(),n);
	
	set_f_key(key.get(),n);
	
	df.GetWord32(n);
	n = ntohl(n);
	key = std::unique_ptr<unsigned char>(new unsigned char[n]);
	
	df.Get(key.get(),n);
	
	set_alpha_key(key.get(),n);
	
	return true;
}

void shacham_waters_private_data::state::public_interpretation()
{
	if (!_encrypted_and_signed)
	{
		throw std::runtime_error("in shacham_waters_private_data::state::check_sig_and_decrypt, data must be encrypted before decryption and checking signature.");
	}
	
	// simply gets n out of the stream
	CryptoPP::StringSource raw_source(_raw.get(),_raw_sz,true);
	
	// skip sig size
	raw_source.Skip(sizeof(unsigned int));
	
	// get n
	unsigned int n;
	raw_source.GetWord32(n);
	_n = ntohl(n);
}

inline CryptoPP::Integer shacham_waters_private_data::challenge::v(unsigned int i) const
{
	return _v.evaluate(i);
}

inline CryptoPP::Integer shacham_waters_private_data::challenge::i(unsigned int i) const
{
	return _i.evaluate(i);
}

void shacham_waters_private_data::challenge::serialize(CryptoPP::BufferedTransformation &bt) const
{
	// write l
	unsigned int n = htonl(_l);
	bt.PutWord32(n);

	// write key size
	n = htonl(get_key_size());
	bt.PutWord32(n);
	
	// write key
	bt.Put(get_key(),get_key_size());
	
	// write B size
	CryptoPP::Integer B = _v.get_limit();
	
	unsigned int B_sz = B.MinEncodedSize();
	n = htonl(B_sz);
	
	bt.PutWord32(n);
	
	// write B
	//std::cout << "Encoding B in " << B_sz << " bytes." << std::endl;
	B.Encode(bt,B_sz);
}

void shacham_waters_private_data::challenge::deserialize(CryptoPP::BufferedTransformation &bt)
{
	unsigned int n;
	
	// get l
	bt.GetWord32(n);
	_l = ntohl(n);
	
	std::unique_ptr<unsigned char> key;
	// get key size
	bt.GetWord32(n);
	n = ntohl(n);
	key = std::unique_ptr<unsigned char>(new unsigned char[n]);
	
	bt.Get(key.get(),n);
	
	set_key(key.get(),n);
	
	// read B size
	bt.GetWord32(n);
	n = ntohl(n);
	
	CryptoPP::Integer B;
	
	// read B
	//std::cout << "Dencoding B in " << n << " bytes." << std::endl;
	B.Decode(bt,n);
	
	// set B
	_v.set_limit(B);
}

void shacham_waters_private_data::proof::serialize(CryptoPP::BufferedTransformation &bt) const
{
	unsigned int n = htonl(_mu.size());
	
	bt.PutWord32(n);
	
	for (int i=0;i<_mu.size();i++)
	{
		unsigned int mu_sz = _mu[i].MinEncodedSize();
		n = htonl(mu_sz);
	
		bt.PutWord32(n);
		
		//std::cout << "Encoding mu_" << i << " in " << mu_sz << " bytes." << std::endl;
		_mu[i].Encode(bt,mu_sz);
	}
	
	unsigned int sigma_sz = _sigma.MinEncodedSize();
	n = htonl(sigma_sz);
	
	bt.PutWord32(n);
	//std::cout << "Encoding sigma  in " << sigma_sz << " bytes." << std::endl;
	_sigma.Encode(bt,sigma_sz);
}

void shacham_waters_private::proof::deserialize(CryptoPP::BufferedTransformation &bt)
{
	unsigned int n;
	
	bt.GetWord32(n);
	
	n = ntohl(n);
	
	_mu.clear();
	_mu.resize(n);
	for (int i=0;i<_mu.size();i++)
	{
		bt.GetWord32(n);
		
		n = ntohl(n);
		
		//std::cout << "Dencoding mu_" << i << " in " << n << " bytes." << std::endl;
		_mu[i].Decode(bt,n);
	}
	
	bt.GetWord32(n);
	n = ntohl(n);
	//std::cout << "Dencoding sigma in " << n << " bytes." << std::endl;
	_sigma.Decode(bt,n);
}

void shacham_waters_private::init(unsigned int prime_size_bytes, unsigned int sectors)
{
	CryptoPP::AutoSeededRandomPool rng;
	
	rng.GenerateBlock(_k_enc,shacham_waters_private_data::key_size);
	rng.GenerateBlock(_k_mac,shacham_waters_private_data::key_size);
	
	_sectors = sectors;
	
	_p = CryptoPP::Integer(rng,0,CryptoPP::Integer::Power2(prime_size_bytes*8),CryptoPP::Integer::RandomNumberType::PRIME);
	
	// sector should be no larger than the prime
	// otherwise sector reduction can be performed by a malicious
	// server to save space
	_sector_size = _p.BitCount()/8;
}

void shacham_waters_private::get_public(shacham_waters_private &h) const
{
	h._p = _p;
	h._sectors = _sectors;
	h._sector_size = _sector_size;
}

void shacham_waters_private::encode(tag &t, state &s, file &f)
{
	//std::cout << "Encoding... " << std::endl;
	CryptoPP::AutoSeededRandomPool rng;
	
	integer_block_file_interface ibf(f);
	
	// split file into sector sized chunks
	f.redefine_chunks(_sector_size,_sectors);
	
	s.set_n(f.get_chunk_count());
	
	byte k_prf[shacham_waters_private_data::key_size];
	rng.GenerateBlock(k_prf,shacham_waters_private_data::key_size);
	s.set_f_key(k_prf,shacham_waters_private_data::key_size);
	s.set_f_limit(_p);
	
	byte k_alpha[shacham_waters_private_data::key_size];
	rng.GenerateBlock(k_alpha,shacham_waters_private_data::key_size);
	s.set_alpha_key(k_alpha,shacham_waters_private_data::key_size);
	s.set_alpha_limit(_p);
	
	t.sigma().clear();
	t.sigma().resize(f.get_chunk_count());
	//std::cout << "Chunks: " << f.get_chunk_count() << std::endl;
	//std::cout << "Sectors per chunk: " << f.get_sectors_per_chunk() << std::endl;
	for (int i=0;i<f.get_chunk_count();i++)
	{
		t.sigma().at(i) = s.f(i);
		for (int j=0;j<_sectors;j++)
		{
			t.sigma().at(i) += s.alpha(j) * ibf.get_sector(i,j);
			t.sigma().at(i) %= _p;
		}
		//std::cout << "sigma_" << i << " = " << t.sigma().at(i) << std::endl;
	}
	
	s.encrypt_and_sign(_k_enc,_k_mac);
}

void shacham_waters_private::gen_challenge(challenge &c, const state &s)
{
	if (!gen_challenge(c,s,s.get_n(),_p))
	{
		throw std::runtime_error("Signature check on state failed.");
	}
}

bool shacham_waters_private::gen_challenge(challenge &c, const state &s_enc, unsigned int l, const CryptoPP::Integer &B)
{
	//std::cout << "Generating challenge..." << std::endl;
	
	state s = s_enc;
	
	// decrypt and check sig of state
	if (!s.check_sig_and_decrypt(_k_enc,_k_mac))
	{
		std::cout << "Signature check or decryption failed..." << std::endl;
		return false;
	}
	
	CryptoPP::AutoSeededRandomPool rng;
	
	c.set_l(l);

	byte k[shacham_waters_private_data::key_size];
	rng.GenerateBlock(k,shacham_waters_private_data::key_size);
	
	c.set_key(k,shacham_waters_private_data::key_size);
	c.set_v_limit(B);
	c.set_i_limit(s.get_n());
	
	return true;
}

void shacham_waters_private::prove(proof &p,const challenge &c, file &f,const tag &t)
{
	//std::cout << "Proving existence..." << std::endl;
	integer_block_file_interface ibf(f);
	
	f.redefine_chunks(_sector_size,_sectors);
	
	// serializer cannot get indexer limits, so we manually set here
	prf indexer = c.get_i();
	indexer.set_limit(f.get_chunk_count());
	
	p.mu().clear();
	p.mu().resize(_sectors);
	//std::cout << "Sectors: " << _sectors << std::endl;
	for (int j=0;j<_sectors;j++)
	{
		//p.mu().at(j) = CryptoPP::Integer(); // this is called implicitly
		for (int i=0;i<c.get_l();i++)
		{
			p.mu().at(j) += c.v(i) * ibf.get_sector(indexer.evaluate(i).ConvertToLong(),j);
			p.mu().at(j) %= _p;
		}
		//std::cout << "mu_" << j << " = " << p.mu().at(j) << std::endl;
	}
	
	//p.sigma() = CryptoPP::Integer();
	//std::cout << "Calculating sigma... t.sigma().size() = " << t.sigma().size() << std::endl;
	for (int i=0;i<c.get_l();i++)
	{
		//std::cout << "sigma += v_" << i << " * sigma_" << indexer.evaluate(i) << std::endl;
		p.sigma() += c.v(i) * t.sigma().at(indexer.evaluate(i).ConvertToLong());
		p.sigma() %= _p;
	}
	
	//std::cout << "sigma = " << p.sigma() << std::endl;
}

bool shacham_waters_private::verify(const proof &p, const challenge &c, const state &s_enc)
{
	//std::cout << "Verifying proof..." << std::endl;
	CryptoPP::Integer rhs;
	
	state s = s_enc;
	
	// decrypt and check sig of state
	if (!s.check_sig_and_decrypt(_k_enc,_k_mac))
	{
		std::cout << "Signature check or decryption failed..." << std::endl;
		return false;
	}
	
	// serializer will not get manual limits, ensure they are set here
	prf indexer = c.get_i();
	indexer.set_limit(s.get_n());
	
	s.set_f_limit(_p);
	s.set_alpha_limit(_p);
	
	for (int i=0;i<c.get_l();i++)
	{
		rhs += c.v(i) * s.f(indexer.evaluate(i).ConvertToLong());
		rhs %= _p;
	}
	
	for (int j=0;j<_sectors;j++)
	{
		rhs += s.alpha(j) * p.mu().at(j);
		rhs %= _p;
	}
	
	//std::cout << "sigma: " << p.sigma() << std::endl;
	//std::cout << "rhs: " << rhs << std::endl;
	
	return p.sigma() == rhs;
}

void shacham_waters_private::serialize(CryptoPP::BufferedTransformation &bt) const
{
	unsigned int n;
	
	// write key size
	n = htonl(shacham_waters_private_data::key_size);
	bt.PutWord32(n);
	
	// write encryption key
	bt.Put(_k_enc,shacham_waters_private_data::key_size);
	
	// write key size
	bt.PutWord32(n);
	
	// write key
	bt.Put(_k_mac,shacham_waters_private_data::key_size);
	
	// write sectors
	n = htonl(_sectors);
	bt.PutWord32(n);
	
	// write sector size
	n = htonl(_sector_size);
	bt.PutWord32(n);
	
	// write p size
	unsigned int p_sz = _p.MinEncodedSize();
	n = htonl(p_sz);
	bt.PutWord32(n);
	
	// write p
	//std::cout << "Encoding p in " << p_sz << " bytes." << std::endl;
	_p.Encode(bt,p_sz);
}

void shacham_waters_private::deserialize(CryptoPP::BufferedTransformation &bt)
{
	unsigned int n;
	// read key size
	bt.GetWord32(n);
	n = ntohl(n);
	
	// check key size
	if (n != shacham_waters_private_data::key_size)
	{
		throw std::runtime_error("Incompatible key sizes.");
	}
	
	// get key
	bt.Get(_k_enc,n);
	
	// read key size
	bt.GetWord32(n);
	n = ntohl(n);
	
	// check key size
	if (n != shacham_waters_private_data::key_size)
	{
		throw std::runtime_error("Incompatible key sizes.");
	}
	
	// get key
	bt.Get(_k_mac,n);
	
	// read sectors
	bt.GetWord32(n);
	_sectors = ntohl(n);

	// read sector size
	bt.GetWord32(n);
	_sector_size = ntohl(n);

	// read p size
	bt.GetWord32(n);
	n = ntohl(n);
	
	// read p
	//std::cout << "Dencoding p in " << n << " bytes." << std::endl;
	_p.Decode(bt,n);
}