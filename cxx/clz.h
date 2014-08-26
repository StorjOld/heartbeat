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