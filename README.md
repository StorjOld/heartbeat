heartbeat
=========

Python library for verifying existence of a file. Works with other Storj libraries and wrappers to allow to allow for Node A to trustlessly verify that Node B has a file by comparing hashes. This should be expanded to use Merkle trees, and data striping to optimize I/O. 

#### Functions

Get the the SHA256 hash of a file plus some seed data.

	hash_challenge(file_path, seed = "")

Deterministically generate list of seeds from a root seed. 

	gen_seeds(num, root_seed)

Generate the specified number of hash challenges.

	gen_challenges(file_path, num, root_seed)
	