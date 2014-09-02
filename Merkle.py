# This implements a merkle tree based proof of storage
from heartbeat.MerkleTree import MerkleTree
import hashlib
import hmac
import os

#debugging
import base64

# challenge is a the seed and index
class Challenge(object):
    def __init__(self,seed,index):
        self.seed = seed
        self.index = index

    def get_index(self):
        return self.index

    def get_seed(self):
        return self.seed

# tag is the stripped merkle tree
class Tag(object):
    def __init__(self,tree):
        self.tree = tree

    def get_tree(self):
        return self.tree

# state unused, since we don't have any secret data that needs to be stored on the server

# proof is the leaf and branch
class Proof(object):
    def __init__(self,leaf,branch):
        self.leaf = leaf
        self.branch = branch

    def get_leaf(self):
        return self.leaf

    def get_branch(self):
        return self.branch

# this is the heartbeat object
class Merkle(object):
    @staticmethod
    def get_next_seed(key,seed):
        return hmac.new(key,seed,hashlib.sha256).digest()

    @staticmethod
    def get_file_hash(file,seed,bufsz=65536):
        #print("getting file with seed = "+str(base64.b64encode(seed)))
        h = hmac.new(seed,None,hashlib.sha256)
        while (True):
            buffer = file.read(bufsz)
            tmp = hashlib.sha256(buffer).digest()
            #print("Read "+str(len(buffer))+" bytes, hash: "+str(base64.b64encode(tmp)))
            h.update(buffer)
            if (len(buffer)!=bufsz):
                break
        fh = h.digest()
        #print("returning file hash : "+str(base64.b64encode(fh)))
        return fh


    def __init__(self,key=None,seed=None,root=None,i=0,n=256):
        self.key = key
        self.seed = seed
        self.root = root
        self.i = i
        self.n = n

    def gen(self):
        self.key = os.urandom(32)
        self.seed = os.urandom(32)
        return None

    def get_public(self):
        return Merkle(None,self.seed,self.i,self.n)

    def encode(self,file):
        mt = MerkleTree()
        seed = self.seed
        for i in range(0,self.n):
            #print("Encoding seed "+str(i)+" = "+str(base64.b64encode(seed)))
            file.seek(0)
            leaf = Merkle.get_file_hash(file,seed)
            #print("Adding leaf = "+str(base64.b64encode(leaf)))
            mt.add_leaf(leaf)
            seed = Merkle.get_next_seed(self.key,seed)
        mt.build()
        self.root = mt.get_root()
        mt.strip_leaves()
        tag = Tag(mt)
        return (tag,None)

    def gen_challenge(self,state=None):
        if (self.i>self.n):
            raise Exception("Out of challenges.")
        chal = Challenge(self.seed,self.i)
        #print("Challenge seed = "+str(base64.b64encode(self.seed))+", index = "+str(self.i))
        self.seed = Merkle.get_next_seed(self.key,self.seed)
        self.i+=1
        return chal

    def prove(self,file,challenge,tag):
        #print("Proving seed = "+str(base64.b64encode(challenge.get_seed()))+", index = "+str(challenge.get_index()))
        leaf = Merkle.get_file_hash(file,challenge.get_seed())
       # print("  with leaf = "+str(base64.b64encode(leaf)))
        proof = Proof(leaf,tag.get_tree().get_branch(challenge.get_index()))
        return proof

    def verify(self,proof,challenge,state):
        #print("Merkle.verify()")
        verified = MerkleTree.verify_branch(proof.get_leaf(),proof.get_branch(),self.root)
        return verified
