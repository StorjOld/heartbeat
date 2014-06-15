heartbeat
=========

Python library for verifying existence of a file. Works with other Storj libraries and wrappers to allow to allow for Node A to trustlessly verify that Node B has a file by comparing hashes.

Yes, we should be using Merkle trees for the challege verification. 

#### Functions

Get the hash of some data. Defaults to the SHA256 hashing algorithm. 

    data_hash(data, algorithm)
    
Get the hash of a file plus some arbitrary data appended. If there is no data specified, just get the hash of the file.

    full_hash(file_path, data)
    
The file is split up into chunks of chunk_size (from 0 to N where N=filesize/chunk_size). If the file is below the chunk size we use the whole file. We use the seed to deterministically generate a series of chunks to access up to num_chunks. We return the data from the chunks.

    get_stripes(file_path, seed, chunk_size, num_chunks)
    
Gets the hash of data returned from get_stripes() plus the seed.
    hash_challenge(data, seed)
    
Generates a list of random seeds. Returns a list of 2-tuples containing the seed, and its corresponding hash_challenge. 
    gen_challenges(file_path, num)
