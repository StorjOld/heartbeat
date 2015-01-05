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

#pragma once 

#include <cryptopp/integer.h>
#include <cryptopp/randpool.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include "clz.h"
#include "pointer.hxx"

class prf
{
public:
	prf()
	{
		init();
	}
	
	prf(const prf &p)
	{
		init();
		copy(p);
	}
	
	 prf& operator= (const prf &other)
    {
		init();
        copy(other);
        return *this;
    }
	
	void init()
	{
		_iv_sz = _aes.DefaultIVLength();
		_iv = smart_buffer(new unsigned char[_iv_sz]);
		memset(_iv.get(),0,_iv_sz);
		_buffer_sz = 0;
		_key_sz = 0;
	}
	
	void copy(const prf &p)
	{
		_limit = p._limit;
		_limit_sz = p._limit_sz;
		
		if (p._buffer.get()!=0)
		{
			_buffer_sz = p._buffer_sz;
			_buffer = smart_buffer(new unsigned char[_buffer_sz]);
			memcpy(_buffer.get(),p._buffer.get(),_buffer_sz);
		}
			
		if (p._key.get()!=0)
		{
			set_key(p._key.get(),p._key_sz);
		}
		_msb_mask = p._msb_mask;
	}
	
	void set_key(const unsigned char *key,unsigned int key_length)
	{
		_key_sz = key_length;
		_key = smart_buffer(new unsigned char[_key_sz]);
		memcpy(_key.get(),key,_key_sz);
		
		_aes.SetKeyWithIV(_key.get(),_key_sz,_iv.get(),_iv_sz);
	}
	
	void set_limit(const CryptoPP::Integer &limit)
	{
		_limit = limit;
		
		_limit_sz = limit.ByteCount();
		
		byte b = limit.GetByte(_limit_sz-1);
		
		int lz = count_leading_zeros(b);
		
		_msb_mask = 0x00;
		for (int i=0;i<(32-lz);i++)
		{
			_msb_mask |= 1 << i;
		}
		
		unsigned int digest_sz = _sha.DigestSize();
		
		_buffer_sz = _limit_sz > digest_sz ? _limit_sz : digest_sz;
		_buffer = smart_buffer(new unsigned char[_buffer_sz]);
	}
	
	const CryptoPP::Integer& get_limit() const
	{
		return _limit;
	}

	// gets a random number into e
	CryptoPP::Integer evaluate(unsigned int i) const
	{
		/*
		std::string str0;
		CryptoPP::StringSource s0(_iv.get(), _iv_sz, true,new CryptoPP::HexEncoder(new CryptoPP::StringSink(str0),true,2,":"));
		std::cout << "iv = " << str0 << std::endl;
		*/
		_aes.Resynchronize(_iv.get(),_iv_sz);
		CryptoPP::Integer a;
		unsigned int count = 0;
		do
		{
			rand_buf(i);
			
			a.Decode(_buffer.get(),_limit_sz);
			
			a.SetByte(_limit_sz-1,a.GetByte(_limit_sz-1) & _msb_mask);
		} while (a >= _limit && count++ < max_iterations);
		
		return a;
	}
	
	unsigned int get_key_size() const { return _key_sz; }
	const unsigned char* get_key() const { return _key.get(); }
	
private:
	mutable CryptoPP::CFB_Mode< CryptoPP::AES >::Encryption _aes;
	mutable CryptoPP::SHA256 _sha;
	
	CryptoPP::Integer _limit;
	unsigned int _limit_sz;
	
	smart_buffer _buffer;
	unsigned int _buffer_sz;
	
	smart_buffer _iv;
	unsigned int _iv_sz;

	smart_buffer _key;
	unsigned int _key_sz;
	
	byte _msb_mask;
	
	static const unsigned int max_iterations = 80;
	
	void rand_buf(unsigned int i) const
	{
		memset(_buffer.get(),0,_limit_sz);
		_sha.CalculateDigest(_buffer.get(),(unsigned char*)&i,sizeof(unsigned int));
		
		_aes.ProcessData(_buffer.get(),_buffer.get(),_limit_sz);
	}
};
