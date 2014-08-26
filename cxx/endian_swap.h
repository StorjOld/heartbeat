
inline void swap(uint32_t *i)
{
	char buf;
	char *r = (char*)i;
	buf = r[0];
	r[0] = r[3];
	r[3] = buf;
	buf = r[1];
	r[1] = r[2];
	r[2] = buf;
}

inline uint32_t htonl(uint32_t hostint)
{
#ifndef __BIG_ENDIAN__
	swap(&hostint);
#else
#ifndef __LITTLE_ENDIAN__
#error "__BIG_ENDIAN__ or __LITTLE_ENDIAN__ must be define."
#endif
#endif
	return hostint;
}

inline uint32_t ntohl(uint32_t netint)
{
#ifndef __BIG_ENDIAN__
	swap(&netint);
#else
#ifndef __LITTLE_ENDIAN__
#error "__BIG_ENDIAN__ or __LITTLE_ENDIAN__ must be define."
#endif
#endif
	return netint;
}