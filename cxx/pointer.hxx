#pragma once
#include <memory>

#if (__cplusplus < 201103L)
typedef std::auto_ptr std::unique_ptr;
#endif