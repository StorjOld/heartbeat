import sys
import time
sys.path.append("..")
from heartbeat import OneHash


class Chunk:
	def __init__(self, file_path, num_challenges, root_seed):
		self.target_file = OneHash(file_path)
		self.target_file.gen_challenges(num_challenges, root_seed)
	def challenge(self):
		return self.target_file.get_challenge()
	def response(self, answer):
		return self.target_file.check_answer(answer)


class Client:
	def __init__(self, file_path):
		self.target_file = OneHash(file_path)
	def answer(self, challenge):
		return self.target_file.meet_challenge(challenge)