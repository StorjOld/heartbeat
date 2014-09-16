#
# The MIT License (MIT)
#
# Copyright (c) 2014 William T. James
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This implements a merkle tree based proof of storage
import hashlib
import hmac
import os
import random

from .MerkleTree import MerkleTree
from ..exc import HeartbeatError


# challenge is a the seed and index
class Challenge(object):
    def __init__(self, seed, index):
        self.seed = seed
        self.index = index

    def get_index(self):
        return self.index

    def get_seed(self):
        return self.seed


# tag is the stripped merkle tree
class Tag(object):
    def __init__(self, tree):
        self.tree = tree

    def get_tree(self):
        return self.tree

# state is unused, since we don't have any secret data
# that needs to be stored on the server


# proof is the leaf and branch
class Proof(object):
    def __init__(self, leaf, branch):
        self.leaf = leaf
        self.branch = branch

    def get_leaf(self):
        return self.leaf

    def get_branch(self):
        return self.branch


# this is the heartbeat object
class Merkle(object):
    @staticmethod
    def get_next_seed(key, seed):
        # we use an HMAC function to ensure authenticity of the seeds
        return hmac.new(key, seed, hashlib.sha256).digest()

    @staticmethod
    def get_file_hash(file, seed, bufsz=65536):
        # we use an HMCA to ensure authenticity of the file hash
        h = hmac.new(seed, None, hashlib.sha256)
        while (True):
            buffer = file.read(bufsz)
            h.update(buffer)
            if (len(buffer) != bufsz):
                break
        return h.digest()

    @staticmethod
    def get_chunk_hash(file, seed, chunksz=8192, bufsz=65536):
        filesz = file.seek(0, 2)
        random.seed(seed)
        i = random.randint(0, filesz-chunksz)
        file.seek(i)
        read = 0
        if (chunksz < bufsz):
            bufsz = chunksz
        h = hmac.new(seed, None, hashlib.sha256)
        while (True):
            buffer = file.read(bufsz)
            h.update(buffer)
            read += len(buffer)
            if (read >= chunksz):
                break
        return h.digest()

    def __init__(self,
                 i=0,
                 n=256,
                 chunksz=8192,
                 key=None,
                 seed=None,
                 root=None):
        self.n = n
        self.i = i
        self.chunksz = chunksz
        if (key is None):
            self.key = os.urandom(32)
        else:
            self.key = key
        if (seed is None):
            self.seed = os.urandom(32)
        else:
            self.seed = seed
        self.root = root

    def get_public(self):
        return Merkle(self.i, self.n, self.chunksz)

    def encode(self, file):
        # generates a merkle tree with the leaves as seed file hashes,
        # the seed for each leaf being a deterministic seed
        # generated from a key does not generate state as no
        # state data needs to be stored on the server
        mt = MerkleTree()
        seed = Merkle.get_next_seed(self.key, self.seed)
        for i in range(0, self.n):
            file.seek(0)
            # leaf = Merkle.get_file_hash(file,seed)
            leaf = Merkle.get_chunk_hash(file, seed, self.chunksz)
            mt.add_leaf(leaf)
            seed = Merkle.get_next_seed(self.key, seed)
        mt.build()
        self.root = mt.get_root()
        mt.strip_leaves()
        tag = Tag(mt)
        return (tag, None)

    def gen_challenge(self, state=None):
        # returns the next challenge and increments the seed and index
        if (self.i >= self.n):
            raise HeartbeatError("Out of challenges.")
        self.seed = Merkle.get_next_seed(self.key, self.seed)
        chal = Challenge(self.seed, self.i)
        self.i += 1
        return chal

    def prove(self, file, challenge, tag):
        # leaf = Merkle.get_file_hash(file,challenge.get_seed())
        leaf = Merkle.get_chunk_hash(file, challenge.get_seed(), self.chunksz)
        return Proof(leaf, tag.get_tree().get_branch(challenge.get_index()))

    def verify(self, proof, challenge, state=None):
        return MerkleTree.verify_branch(proof.get_leaf(),
                                        proof.get_branch(),
                                        self.root)
