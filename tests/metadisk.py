import sys
import time
sys.path.append("..")
from model import Chunk
from heartbeat import HeartBeat


class Contract:
    def __init__(self, file_path, redudancy, num_challenges, root_seed):
        self.chunk_list = []
        for i in range(redudancy):
            self.chunk_list.append(Chunk(file_path, num_challenges, root_seed + str(i)))

    def send_contract(self):
        pass

    def run(self):
        for chunk in self.chunk_list:
            print(chunk.challenge())

if __name__ == "__main__":
    contract = Contract("../files/test4.txt", 3, 100, "testing")
    contract.run()
