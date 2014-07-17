import sys
import time
from heartbeat import HeartBeat

class Server:
	def __init__(self, file_path, num_challenges, root_seed):
		self.file1 = HeartBeat(file_path)
		self.file1.gen_challenges(num_challenges, root_seed)
	def challenge(self):
		return self.file1.get_challenge()
	def response(self, answer):
		return self.file1.check_answer(answer)

class Client:
	def __init__(self, file_path):
		self.file1 = HeartBeat(file_path)
	def answer(self, hash):
		return self.file1.meet_challenge(challenge)



if __name__ == "__main__":
	# Config 
	num_challenges = 100000
	root_seed = "testing"

	# Start
	server = Server("C:\\Users\\super3\\Code\\heartbeat\\test4.txt", num_challenges, root_seed)
	client = Client("C:\\Users\\super3\\Code\\heartbeat\\test4.txt")

	for i in range(num_challenges):
		challenge = server.challenge()
		print("Server: c - " + str(challenge.seed))
		try: 
			response = client.answer(challenge)
		except ValueError:
			response = "IO"
		print("Client: a - " +  str(response))
		correct = server.response(response)
		print("Server: " +  str(correct) + "\n")

		if not correct:
			break
		