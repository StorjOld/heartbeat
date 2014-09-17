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

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

from .MerkleTree import MerkleTree
from ..exc import HeartbeatError


# challenge is a the seed and index
class Challenge(object):
    """The Challenge class represents a challenge one node can pose to
    another when requesting verification that they have a complete version
    of a specific file.
    """
    def __init__(self, seed, index):
        """Initialization method

        :param seed: this is the seed for this challenge, representing the
        seed to use when calculating the HMAC of the specified block
        :param index: this is challenge index, the index of the
        particular branch of the merkle tree
        """
        self.seed = seed
        self.index = index


# tag is the stripped merkle tree
class Tag(object):
    """The Tag class represents the file tag that is a stripped merkle
    tree, that is a merkle tree without the leaves, which are the seeded
    hashes of each chunk."""

    def __init__(self, tree):
        """Initialization method

        :param tree: this is the stripped merkle tree
        """
        self.tree = tree

# state is unused, since we don't have any secret data
# that needs to be stored on the server


class State(object):
    """The State class represents the state of a file, which can be encrypted
    and stored on the server, or held plaintext by the client.  It is mutable,
    i.e. it will change every time a challenge is issued, since it holds the
    current seed and the merkle branch index for the last challenge.  If it
    is stored on the server it should be signed
    """
    def __init__(self, index, seed):
        self.index = index
        self.seed = seed
        self.hmac = None

    def sign(self, key):
        # sign
        h = HMAC.new(key, None, SHA256)
        h.update(self.index)
        h.update(self.seed)
        self.hmac = h.digest()

    def checksig(self, key):
        # check sig
        h = HMAC.new(key, None, SHA256)
        h.update(self.index)
        h.update(self.seed)
        if (h.digest() != self.hmac):
            raise HeartbeatError("Signature invalid on state.")


# proof is the leaf and branch
class Proof(object):
    """The proof class encpasulates proof that a file exists"""
    def __init__(self, leaf, branch):
        """Initialization method

        :param leaf: this is leaf of the merkle tree branch, i.e. the seeded
        HMAC of the file chunk that was specified in the challenge.
        :param branch: this is the merkle tree branch without the leaf
        """
        self.leaf = leaf
        self.branch = branch


# this is the heartbeat object
class Merkle(object):
    """This class represents a heartbeat based on a merkle tree hash.  The client
    generates a key, which is used for the generation of challenges.  Then the
    client generates a number of challenges based on this key.
    """
    def __init__(self,
                 n=256,
                 chunksz=8192,
                 key=None,
                 root=None):
        self.n = n
        self.chunksz = chunksz
        if (key is None):
            self.key = os.urandom(32)
        else:
            self.key = key
        self.root = root

    def get_public(self):
        return Merkle(self.n, self.chunksz)

    def encode(self, file):
        """ this function generates a merkle tree with the leaves as seed file
        hashes, the seed for each leaf being a deterministic seed generated
        from a key.
        """
        mt = MerkleTree()
        state = State(0, os.urandom(32))
        seed = MerkleHelper.get_next_seed(self.key, state.get_seed())
        for i in range(0, self.n):
            file.seek(0)
            leaf = MerkleHelper.get_chunk_hash(file, seed, self.chunksz)
            mt.add_leaf(leaf)
            seed = MerkleHelper.get_next_seed(self.key, seed)
        mt.build()
        self.root = mt.get_root()
        mt.strip_leaves()
        tag = Tag(mt)
        state.sign(self.key)
        return (tag, state)

    def gen_challenge(self, state):
        # returns the next challenge and increments the seed and index
        # in the state
        state.checksig(self.key)
        if (state.index >= self.n):
            raise HeartbeatError("Out of challenges.")
        state.seed = MerkleHelper.get_next_seed(self.key, state.seed)
        chal = Challenge(self.seed, state.index)
        state.index += 1
        state.sign(self.key)
        return chal

    def prove(self, file, challenge, tag):
        leaf = MerkleHelper.get_chunk_hash(file, challenge.seed, self.chunksz)
        return Proof(leaf, tag.tree.get_branch(challenge.index))

    def verify(self, proof, challenge, state=None):
        return MerkleTree.verify_branch(proof.leaf,
                                        proof.branch,
                                        self.root)


def MerkleHelper(object):
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
