#pragma once
#include <memory>

#if (__cplusplus < 201103L)
typedef std::auto_ptr<unsigned char> smart_buffer;
#else
typedef std::unique_ptr<unsigned char> smart_buffer;
#endif
