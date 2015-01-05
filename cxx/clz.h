/*

The MIT License (MIT)

Copied from from ACMer on Coding for Speed DOT COM
Additional preprocessing by William T. James, Storj Labs

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

#ifdef HAVE_GNU_CLZ
#define count_leading_zeros __builtin_clz
#elsif HAVE_VS_LZCNT
#define count_leading_zeros __lzcnt
#else

#define count_leading_zeros clz

inline unsigned clz(int x)
{
    unsigned n = 0;
    if (x == 0) return sizeof(x) * 8;
    while (1) {
        if (x < 0) break;
        n ++;
        x <<= 1;
    }
    return n;
}

#endif
