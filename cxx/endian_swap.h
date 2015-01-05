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

#include <stdint.h>

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

#ifndef htonl

inline uint32_t htonl(uint32_t hostint)
{
#ifndef __BIG_ENDIAN__
	swap(&hostint);
#else
#ifndef __LITTLE_ENDIAN__
#error "__BIG_ENDIAN__ or __LITTLE_ENDIAN__ must be defined."
#endif
#endif
	return hostint;
}

#endif

#ifndef ntohl

inline uint32_t ntohl(uint32_t netint)
{
#ifndef __BIG_ENDIAN__
	swap(&netint);
#else
#ifndef __LITTLE_ENDIAN__
#error "__BIG_ENDIAN__ or __LITTLE_ENDIAN__ must be defined."
#endif
#endif
	return netint;
}

#endif
