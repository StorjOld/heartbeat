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

// implements a block file from a stream

#pragma once

#include "block_file.hxx"

#include <iostream>


class stream_block_file : public block_file
{
public:
	// create a file from a stream
	stream_block_file(std::istream &in,size_t size = 0) : _in(in), _file_size(size) {}

	
	// redefines the chunks of the file.
	// each chunk has s sectors
	// each sector will have size size
	unsigned int redefine_chunks(size_t size,unsigned int s = 1)
	{
		_sector_size = size;
		_sectors_per_chunk = s;
	
		if (_file_size == 0)
		{
			// get file size
			_in.seekg(0,std::ios_base::end);
			_file_size = _in.tellg();
			_in.seekg(0,std::ios_base::beg);
		}
		
		
		// chunk size in bytes
		_chunk_size = _sector_size * _sectors_per_chunk;
		
		_chunks = (_file_size + _chunk_size - 1) / _chunk_size;
		
		//std::cout << "File is " << _file_size << " bytes in length," << std::endl;
		//std::cout << " split into " << _chunks << " chunks" << std::endl;
		//std::cout << " of " << _sectors_per_chunk << " sectors, each " << _sector_size << " bytes in length." << std::endl;
		
		//std::cout << "There should be " << _chunk_size*_chunks-_file_size << " bytes of padding." << std::endl;
		
		_buffer = std::unique_ptr<unsigned char>(new unsigned char[_sector_size]);
	}

	// gets a chunk i into data buffer data with size sz.  
	// throws an exception if there isn't enough space
	// returns the size of the chunk
	unsigned int get_sector(unsigned char *data,size_t sz,unsigned int i,unsigned int j = 0)
	{
		if (sz < _sector_size)
		{
			throw new std::runtime_error("Buffer too small to fit chunk.");
		}
		unsigned int start = i*_chunk_size + j*_sector_size;
		unsigned int end = start + _sector_size;
		if (start > _file_size)
		{
			//std::cout << "(" << i << "," << j << ") is a full padding sector (start = " << start << ", end = " << end << ")" << std::endl;
			// this whole chunk is padding
			memset(data,0,_sector_size);
		} 
		else if (end > _file_size)
		{
			//std::cout << "(" << i << "," << j << ") is a partial padding sector. (start = " << start << ", end = " << end << ", padding = " << end-_file_size << ")" << std::endl;
			// only some of this chunk is padding
			memset(data+(_file_size-start),0,end-_file_size);
			_in.seekg(start);
			_in.read((char*)data,_file_size-start);
		} 
		else
		{
			// read the whole chunk
			_in.seekg(start);
			_in.read((char*)data,_sector_size);
		}
		return _sector_size;
	}
	
	// returns a pointer to requested chunk in contiguous memory.
	// is guaranteed to remain valid until get_chunk(unsigned int) is called again, 
	// or until this object is destroyed
	unsigned char *get_sector(unsigned int i, unsigned int j = 0)
	{
		get_sector(_buffer.get(),_sector_size,i,j);
		return _buffer.get();
	}

	// gets the size of chunk i in bytes
	size_t get_sector_size(unsigned int i, unsigned int j = 0)
	{
		return _sector_size;
	}
	
	// gets the number of chunks
	unsigned int get_chunk_count()
	{
		return _chunks;
	}
	
	// returns the number of sectors per chunk
	unsigned int get_sectors_per_chunk()
	{
		return _sectors_per_chunk;
	}
	
private:
	std::istream &_in;
	
	unsigned int _chunks;
	unsigned int _sectors_per_chunk;
	size_t _chunk_size;
	size_t _sector_size;
	size_t _file_size;
	
	std::unique_ptr<unsigned char> _buffer;
};