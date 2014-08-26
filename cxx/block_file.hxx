// implements a file as a block accessible object

#pragma once

#include <cstddef>

class block_file
{
public:
	// redefines the chunks of the file.
	// each chunk has s sectors
	// each sector will have size size
	virtual unsigned int redefine_chunks(size_t size,unsigned int s = 1) = 0;

	// gets a chunk i into data buffer data with size sz.  
	// throws an exception if there isn't enough space
	// returns the size of the chunk
	virtual unsigned int get_sector(unsigned char *data,size_t sz,unsigned int i, unsigned int j = 0) = 0;
	
	// returns a pointer to requested chunk in contiguous memory.
	// is guaranteed to remain valid until get_chunk(unsigned int) is called again, 
	// or until this object is destroyed
	virtual unsigned char *get_sector(unsigned int i, unsigned int j = 0) = 0;

	// gets the size of chunk i in bytes
	virtual size_t get_sector_size(unsigned int i, unsigned int j = 0) = 0;
	
	// gets the number of chunks
	virtual unsigned int get_chunk_count() = 0;
	
	// returns the number of sectors per chunk
	virtual unsigned int get_sectors_per_chunk() = 0;
};