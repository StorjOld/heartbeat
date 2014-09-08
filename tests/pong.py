import sys
import time
sys.path.append("..")
from model import Chunk
from model import Client


# Config
num_challenges = 10000
root_seed = "testing"

# Start
chunk = Chunk("../files/test4.txt", num_challenges, root_seed)
client = Client("../files/test4.txt")

for i in range(num_challenges):
    challenge = chunk.challenge()
    print("Node: c - " + str(challenge.seed))
    try:
        response = client.answer(challenge)
    except ValueError:
        response = "IO"
    print("Client: a - " + str(response))
    correct = chunk.response(response)
    print("Node: " + str(correct) + "\n")

    if not correct:
        break
    time.sleep(0.25)
