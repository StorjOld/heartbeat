/*

C++ interface to the heartbeat, for fast implementation

*/

#include <iostream>
#include "../config.h"

class heartbeat
{
public:
	// encapsulates a file tag after encoding
	class tag 
	{
	};
	
	// encapsulates state information after encoding
	class state
	{
	};
	
	// encapsulates a file within this scheme
	class file
	{
	};
	
	// encapsulates a challenge
	class challenge
	{
	};
	
	// encapsulates the proof of the challenge
	class proof
	{
	};

	// generates the public and private keys for the scheme
	virtual void gen() = 0;
	
	// gets the public version of this object into heartbeat h
	virtual void get_public(heartbeat &h) = 0;
	
	// gets the tag and state into t and s for file f
	virtual void encode(tag &t, state &s, file &f) = 0;
	
	// gets a challenge for the beat
	virtual void gen_challenge(challenge &c) = 0;
	
	// gets a proof of storage for the file
	virtual void prove(proof &p,const challenge &c, file &f,const tag &t) = 0;
	
	// verifies that a proof is correct
	virtual bool verify(const proof&p,const challenge &c,const state &s) = 0;
};