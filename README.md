heartbeat
=========

Python library for verifying existence of a file. Works with other Storj libraries and wrappers to allow to allow for Node A to trustlessly verify that Node B has a file by comparing hashes. This should be expanded to use Merkle trees, and data striping to optimize I/O. 

#### Functions

Get the the SHA256 hash of a file plus some seed data.

	hash_challenge(seed)

Deterministically generate list of seeds from a root seed. 

	gen_seeds(num, root_seed)

Generate the specified number of hash challenges.

	gen_challenges(num, root_seed)

Check if the returned hash is in our challenges list. 

	check_challenge(hash_answer)

Get a random challenge.

	get_challenge()

Get bytes size of our challenges.
 
 	challenges_size()

Delete challenge from our list of challenges.

	delete_challenge(hash_answer)

 #### Usage

 	# Config vars
	file_path = "test.txt"
	file_path2 = "test2.txt"
	root_seed = "myroot"

	# Create challenges from file
	file1 = HeartBeat(file_path)
	file1.gen_challenges(1000, root_seed)
	seed, hash_response = file1.get_challenge()

	# Create hash_response from seed and duplicate file
	file2 = HeartBeat(file_path2)
	hash_answer = file2.hash_challenge(seed)

	# Check to see if they match
	print(file1.check_challenge(hash_answer))