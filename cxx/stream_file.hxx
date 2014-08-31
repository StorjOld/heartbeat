#implements a basic file that can be read from

#include <cstddef>

class stream_file
{
public:
	virtual size_t read(unsigned char *buffer,size_t sz);
};