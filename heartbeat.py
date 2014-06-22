import base64
import random
import hashlib # For SHA-256 Encoding
import os.path

class HeartBeat:
	"""
	A small library used to create and verify hash challenges so 
	Node A can verify that Node B has a specified file.
	"""

	def __init__(self, file_path):
		# Check if the file exists
		if os.path.isfile(file_path):
			self.file_path = file_path
		else:
			raise IOError("File Not Found.")

		# Challenges is a list of 2-tuples (seed, hash_response)
		self.challenges = []

	def gen_challenges(self, num, root_seed):
		"""
		Generate the specified number of hash challenges.

		Arguments:
		num -- The number of hash challenges we want to generate.
		root_seed -- Some value that we use to generate our seeds from.
		"""

		# Generate a series of seeds
		seeds = self.gen_seeds(num, root_seed)

		# List of 2-tuples (seed, hash_response)
		challenges = []

		# Generate the corresponding hash for each seed
		for a_seed in seeds:
			result_hash = self.hash_challenge(a_seed)
			challenges.append((a_seed, result_hash))

		# Save challenges
		self.challenges = challenges

	def hash_challenge(self, seed = ""):
		"""
		Get the the SHA256 hash of a file plus some seed data.

	 	Arguments:
	    seed -- Extra data appended to the file. By using a seed
	    and file we can generate unique hashes to verify that we hold
	    a particular file.  
		"""

		with open(self.file_path, "r", encoding='utf-8') as f:
			m = hashlib.sha256()
			# File + Seed
			m.update(f.read().encode('utf-8') + str(seed).encode('utf-8'))
			sha = m.digest()
			res = base64.b64encode(sha)
		return res


	def gen_seeds(self, num, root_seed):
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

	def check_challenge(self, hash_response):
		"""
		Check if the returned hash is in our challenges list. 

		Arguments:
		challenges -- 2-tuples(seed, hash) list from gen_challenges()
		hash_response -- a hash that we compare to our list of challenges.
		"""
		for a_challenge in self.challenges:
			if a_challenge[1] == hash_response:
				return True
		return False

	def get_challenge(self):
		"""Accessor for the challenge list"""
		return random.choice(self.challenges)

if __name__ == "__main__":
	# Config vars
	file_path = "test.txt"
	file_path2 = "test2.txt"
	root_seed = "myroot"

	# Create challenges from file
	file1 = HeartBeat(file_path)
	file1.gen_challenges(10, root_seed)
	seed, hash_response = file1.get_challenge()

	# Create hash_response from seed and duplicate file
	file2 = HeartBeat(file_path2)
	hash_answer = file2.hash_challenge(seed)

	# Check to see if they match
	print(file1.check_challenge(hash_answer))