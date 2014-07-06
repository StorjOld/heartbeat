import sys
import base64
import random
import hashlib # For SHA-256 Encoding
import os.path


class HeartBeat:
	"""
	A small library used to create and verify hash challenges
	so Node A can verify that Node B has a specified file.
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

	def hash_challenge(self, seed):
		"""
		Get the the SHA256 hash of a file plus some seed data.

	 	Arguments:
		seed -- Extra data appended to the file. By using a seed
		and file we can generate unique hashes to verify that we hold
		a particular file.  
		"""

		h = hashlib.sha256()
		CHUNK_SIZE = 8 * 1024
		seed = bytes(str(seed), 'utf-8')

		with open(self.file_path, "rb") as f:
			for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
				h.update(chunk+seed)

		return h.hexdigest()


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

	def check_challenge(self, hash_answer):
		"""
		Check if the returned hash is in our challenges list. 

		Arguments:
		hash_answer -- a hash that we compare to our list of challenges.
		"""
		for a_challenge in self.challenges:
			if a_challenge[1] == hash_answer:
				# If we don't disgard a used challenge then a node
				# could fake having the file because it already 
				# knows the proper response
				#self.delete_challenge(hash_answer)
				return True
		return False

	def delete_challenge(self, hash_answer):
		"""Delete challenge from our list of challenges."""
		for a_challenge in self.challenges:
			if a_challenge[1] == hash_answer:
				self.challenges.remove(a_challenge)
				return True
		return False

	def get_challenge(self):
		"""Get a random challenge."""
		return random.choice(self.challenges)

	def challenges_size(self):
		"""Get bytes size of our challenges."""
		return sys.getsizeof(self.challenges)
