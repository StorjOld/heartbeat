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

C++ interface to the heartbeat, for fast implementation

*/

#pragma once
#include "seekable_file.hxx"

template <typename Tdata,typename T>
class heartbeat
{
public:
	typedef typename Tdata::tag tag;
	typedef typename Tdata::state state;
	typedef typename Tdata::challenge challenge;
	typedef typename Tdata::proof proof;
	
	// generates the public and private keys for the scheme
	virtual void gen() = 0;
	
	// gets the public version of this object into heartbeat h
	virtual void get_public(T &h) const = 0;
	
	// gets the tag and state into t and s for file f
	virtual void encode(tag &t,state &s, simple_file &f) = 0;
	
	// gets a challenge for the beat
	virtual void gen_challenge(challenge &c, const state &s) = 0;
	
	// gets a proof of storage for the file
	virtual void prove(proof &p, seekable_file &f, const challenge &c, const tag &t) = 0;
	
	// verifies that a proof is correct
	virtual bool verify(const proof &p,const challenge &c,const state &s) = 0;
};
