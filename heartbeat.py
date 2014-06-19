import base64
import random
import hashlib # For SHA-256 Encoding


def hash_challenge(file_path, seed = ""):
	"""
	Get the the sha256 hash of a file plus some seed data.

 	Arguments:
    file_path -- Path to the file we want to generate hashes for.
    seed -- Extra data appended to the file. By using a seed
    and file we can generate unique hashes to verify that we hold
    a particular file.  
	"""

	with open(file_path, "r", encoding='utf-8') as f:
		m = hashlib.sha256()
		# File + Seed
		m.update(f.read().encode('utf-8') + str(seed).encode('utf-8'))
		sha = m.digest()
		res = base64.b64encode(sha)
	return res


def gen_seeds(num, root_seed):
	"""
	Deterministically generate list of seeds from a root seed. 

	Arguments:
	num -- Numbers of seeds to generate.
	root_seed -- Seed to start off with. 
	"""
	# Generate a starting seed from the root
	seeds = []
	random.seed(root_seed)
	tmp_seed = random.random()

	# Deterministically generate the rest of the seeds
	for x in range(num):
		seeds.append(tmp_seed)
		random.seed(tmp_seed)
		tmp_seed = random.random()

	return seeds


def gen_challenges(file_path, num, root_seed):
	"""
	Generate the specified number of hash challenges.

	Arguments:
	file_path -- Path to the file we want to generate hashes for.
	num -- The number of hash challenges we want to generate.
	root_seed -- Some value that we use to generate our seeds from.
	"""

	# Generate a series of seeds
	seeds = gen_seeds(num, root_seed)

	# List of 2-tuples (seed, hash)
	challenges = []

	# Generate the corresponding hash for each seed
	for a_seed in seeds:
		result_hash = hash_challenge(file_path, a_seed)
		challenges.append((a_seed, result_hash))

	return challenges


file_path = "test.txt"
file_path2 = "test2.txt"
root_seed = "myroot"


cha1 = gen_challenges(file_path, 1, root_seed)
print("Node A - Genereate Root Seed: "  + root_seed)
print("Node A - Find 1st Seed: "  + str(cha1[0][0]))
print("Node A - Find 1st Seed's Hash: "  + str(cha1[0][1]))
print("Node B - Pass File to Node B")
print("Node A - Ask Node B for the Hash to 1st Seed: " + str(cha1[0][0]))
cha2 = hash_challenge(file_path2, str(cha1[0][0]))
print("Node B - Find Seed's Hash: " + str(cha2))
print("Node B - Reply with Hash: " + str(cha2))
print("Node A - Check to see if Hash Matches: " + str( cha1[0][1] == cha2 ))