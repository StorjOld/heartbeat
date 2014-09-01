/*

C++ interface to the heartbeat, for fast implementation

*/

#pragma once

template <typename Tdata,typename T>
class heartbeat
{
public:
	typedef typename Tdata::tag tag;
	typedef typename Tdata::state state;
	typedef typename Tdata::challenge challenge;
	typedef typename Tdata::proof proof;
	typedef typename Tdata::file file;
	
	// generates the public and private keys for the scheme
	virtual void gen() = 0;
	
	// gets the public version of this object into heartbeat h
	virtual void get_public(T &h) const = 0;
	
	// gets the tag and state into t and s for file f
	virtual void encode(tag &t,state &s, file &f) = 0;
	
	// gets a challenge for the beat
	virtual void gen_challenge(challenge &c, const state &s) = 0;
	
	// gets a proof of storage for the file
	virtual void prove(proof &p,const challenge &c, file &f,const tag &t,const state &s) = 0;
	
	// verifies that a proof is correct
	virtual bool verify(const proof &p,const challenge &c,const state &s) = 0;
};