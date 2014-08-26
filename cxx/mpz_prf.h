#include <pbc/pbc.h>
#include <randpool.h>
#include "clz.h"

class mpz_prf
{
public:

	prf()
	{
		_initialized = false;
	}
	
	~prf()
	{
		cleanup();
	}

	void init(mpz_t limit)
	{
		mpz_init(_n);
		
		mpz_init_set(_p,limit);
		
		// count leading zeros of p
		size_t n = mpz_size(_p);
		mp_limb_t msb_p = mpz_getlimbn(_p,n-1);
		unsigned int lz_p = count_leading_zeros(msb_p);
		
		unsigned int to_p = sizeof(mp_limb_t)-lz_p;
		
		msb_mask = 0;
		
		// form a mask from the leading zeros
		for (int i=0;i<to_p;i++)
		{
			msb_mask |= 1 << i;
		}
		
		_initialized = true;
	}
	
	void cleanup()
	{
		if (_initialized)
		{
			delete[] _buffer;
		}
	}
	
	// initialize the psueodrandom function with data
	void seed(unsigned char *data,size_t sz)
	{
		rng.IncorporateEntropy(data,sz);
	}

	// gets a random number into e
	void get(mpz_t e)
	{
		size_t n = mpz_size(_p);
		
		mp_limb_t *xp = mpz_limbs_write(_n,n);
		mpz_limbs_finish(xp,n);
		do
		{
			rng.GenerateBlock(xp,n * sizeof(mp_limb_t));
			
			// mask the most significant byte
			xp[n-1] &= msb_mask;
			
			// compare to prime to ensure it is less
			int cmp = mpz_cmp(_n,_p);
		} while (cmp > 0) // while n is greater than p, we continue searching for numbers in the correct range
		
		mpz_set(e,_n);
	}
	
private:
	RandPool rng;
	
	byte *_buffer;
	size_t _buf_sz;
	
	mpz_t _p;
	mp_limb_t msb_mask;
	mpz_t _n;
	
	bool _initialized;
	
	const int max_iterations = 80;
};