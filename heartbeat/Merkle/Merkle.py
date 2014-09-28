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
import time


from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

from .MerkleTree import MerkleTree, MerkleBranch
from ..exc import HeartbeatError
from ..util import hb_encode, hb_decode


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

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {'seed': hb_encode(self.seed),
                'index': self.index}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new Challenge
        object from the dictionary.

        :param dict: the dictionary to convert
        """
        seed = hb_decode(dict['seed'])
        index = dict['index']
        return Challenge(seed, index)


# tag is the stripped merkle tree
class Tag(object):
    """The Tag class represents the file tag that is a stripped merkle
    tree, that is a merkle tree without the leaves, which are the seeded
    hashes of each chunk.  it also includes the chunk size used for breaking
    up the file
    """

    def __init__(self, tree, chunksz):
        """Initialization method

        :param tree: this is the stripped merkle tree
        :param chunksz: this is the chunk size used for dividing up the file
        """
        self.tree = tree
        self.chunksz = chunksz

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {'tree': self.tree.todict(),
                'chunksz': self.chunksz}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new Tag object
        from the dictionary.

        :param dict: the dictionary to convert
        """
        tree = MerkleTree.fromdict(dict['tree'])
        chunksz = dict['chunksz']
        return Tag(tree, chunksz)


class State(object):
    """The State class represents the state of a file, which can be encrypted
    and stored on the server, or held plaintext by the client.  It is mutable,
    i.e. it will change every time a challenge is issued, since it holds the
    current seed and the merkle branch index for the last challenge.  If it
    is stored on the server it should be signed.  A timestamp is included so
    that the client can verify that this is the most recent state being sent
    back from the server.  The client should ensure that the timestamp is not
    older than the last challenge time.  For instance, if the challenge
    frequency is 1 per hour, the timestamp should be no older than 1 hour at
    any time it is received from the server, or else the server is using an
    old state.  If the server does send back an old state, the index and seed
    can be incremented multiple times in order to reach the present state.
    """
    def __init__(self,
                 index,
                 seed,
                 n,
                 root=None,
                 hmac=None,
                 timestamp=time.time()):
        """Initialization method

        :param index: this is the index of the most recently issued challenge
        :param seed: this is the seed of the most recently issued challenge,
        and is used to calculate the next seed.
        :param n: this is the maximum number of challenges that can be issued
        :param root: this is the merkle root of the tree
        :param hmac: this is the hmac of the signed data
        :param timestamp: this is the timestamp of when the state was generated
        """
        self.index = index
        self.seed = seed
        self.n = n
        self.root = root
        self.hmac = hmac
        self.timestamp = timestamp

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {'index': self.index,
                'seed': hb_encode(self.seed),
                'n': self.n,
                'root': hb_encode(self.root),
                'hmac': hb_encode(self.hmac),
                'timestamp': self.timestamp}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new State object
        from the dictionary.

        :param dict: the dictionary to convert
        """
        index = dict['index']
        seed = hb_decode(dict['seed'])
        n = dict['n']
        root = hb_decode(dict['root'])
        hmac = hb_decode(dict['hmac'])
        timestamp = dict['timestamp']
        self = State(index, seed, n, root, hmac, timestamp)
        return self

    def get_hmac(self, key):
        """Returns the keyed HMAC for authentication of this state data.

        :param key: the key for the keyed hash function
        """
        h = HMAC.new(key, None, SHA256)
        h.update(str(self.index).encode())
        h.update(self.seed)
        h.update(str(self.n).encode())
        h.update(self.root)
        h.update(str(self.timestamp).encode())
        return h.digest()

    def sign(self, key):
        """This function signs the state with a key to prevent modification.
        This should not need to be explicitly used since the encode function
        outputs a signed state.

        :param key: the key to use for signing
        """

        self.hmac = self.get_hmac(key)

    def checksig(self, key):
        """This function checks the state signature.  It raises a
        HeartbeatError in the event of a signature failure.  This should not
        need to be explicitly used since the gen_challenge and verify methods
        check the signature of the state.

        :param key: the key to use for checking the signature
        """
        if (self.get_hmac(key) != self.hmac):
            raise HeartbeatError("Signature invalid on state.")


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

    def todict(self):
        return {'leaf': hb_encode(self.leaf),
                'branch': self.branch.todict()}

    @staticmethod
    def fromdict(dict):
        leaf = hb_decode(dict['leaf'])
        branch = MerkleBranch.fromdict(dict['branch'])
        return Proof(leaf, branch)


class Merkle(object):
    """This class represents a heartbeat based on a merkle tree hash.  The
    client generates a key, which is used for the generation of challenges.
    Then the client generates a number of challenges based on this key.
    """
    def __init__(self, key=None):
        """Initialization method

        :param key: the key for signing the state and generating seeds
        """
        if (key is None):
            self.key = os.urandom(32)
        else:
            self.key = key

    def todict(self):
        """Returns a dictionary fully representing the state of this object
        """
        return {'key': hb_encode(self.key)}

    @staticmethod
    def fromdict(dict):
        """Takes a dictionary as an argument and returns a new Proof object
        from the dictionary.

        :param dict: the dictionary to convert
        """
        key = hb_decode(dict['key'])
        return Merkle(key)

    def get_public(self):
        """This function returns a Merkle object that has it's key
        stripped."""
        return Merkle()

    def encode(self, file, n=256, chunksz=8192):
        """This function generates a merkle tree with the leaves as seed file
        hashes, the seed for each leaf being a deterministic seed generated
        from a key.

        :param file: a file like object that supports the `read()`, `seek()`
        and `tell()` methods
        :param n: the number of challenges to generate
        :param chunksz: the chunk size for breaking up the file.
        """
        mt = MerkleTree()
        state = State(0, os.urandom(32), n)
        seed = MerkleHelper.get_next_seed(self.key, state.seed)
        for i in range(0, n):
            file.seek(0)
            leaf = MerkleHelper.get_chunk_hash(file, seed, chunksz)
            mt.add_leaf(leaf)
            seed = MerkleHelper.get_next_seed(self.key, seed)
        mt.build()
        state.root = mt.get_root()
        mt.strip_leaves()
        tag = Tag(mt, chunksz)
        state.sign(self.key)
        return (tag, state)

    def gen_challenge(self, state):
        """returns the next challenge and increments the seed and index
        in the state.

        :param state: the state to use for generating the challenge.  will
        verify the integrity of the state object before using it to generate
        a challenge.  it will then modify the state by incrementing the seed
        and index and resign the state for passing back to the server for
        storage
        """
        state.checksig(self.key)
        if (state.index >= state.n):
            raise HeartbeatError("Out of challenges.")
        state.seed = MerkleHelper.get_next_seed(self.key, state.seed)
        chal = Challenge(state.seed, state.index)
        state.index += 1
        state.sign(self.key)
        return chal

    def prove(self, file, challenge, tag):
        """Returns a proof of ownership of the given file based on the
        challenge.  The proof consists of a hash of the specified file chunk
        and the complete merkle branch.

        :param file: a file that supports `read()`, `seek()` and `tell()`
        :param challenge: the challenge to use for generating this proof
        :param tag: the file tag as provided from the client
        """
        leaf = MerkleHelper.get_chunk_hash(file, challenge.seed, tag.chunksz)
        return Proof(leaf, tag.tree.get_branch(challenge.index))

    def verify(self, proof, challenge, state):
        """returns true if the proof matches the challenge.  verifies that the
        server possesses the encoded file.

        :param proof: the proof that was returned from the server
        :param challenge: the challenge provided to the server
        :param state: the state of the file, which includes the merkle root of
        of the merkle tree, for verification.
        """
        state.checksig(self.key)
        return MerkleTree.verify_branch(proof.leaf,
                                        proof.branch,
                                        state.root)

    @staticmethod
    def tag_type():
        """Returns the type of the tag object associated with this heartbeat
        """
        return Tag

    @staticmethod
    def state_type():
        """Returns the type of the state object associated with this heartbeat
        """
        return State

    @staticmethod
    def challenge_type():
        """Returns the type of the challenge object associated with this
        heartbeat"""
        return Challenge

    @staticmethod
    def proof_type():
        """Returns the type of the proof object associated with this heartbeat
        """
        return Proof


class MerkleHelper(object):
    """This object provides several helper functions for the Merkle class"""
    @staticmethod
    def get_next_seed(key, seed):
        """This takes a seed and generates the next seed in the sequence.
        it simply calculates the hmac of the seed with the key.  It returns
        the next seed

        :param key: the key to use for the HMAC
        :param seed: the seed to permutate
        """
        return hmac.new(key, seed, hashlib.sha256).digest()

    @staticmethod
    def get_file_hash(file, seed, bufsz=65536):
        """This method generates a secure has of the given file.  Returns the
        hash

        :param file: a file like object to get a hash of.  should support
        `read()`
        :param seed: the seed to use for key of the HMAC function
        :param bufsz: an optional buffer size to use for reading the file
        """
        h = hmac.new(seed, None, hashlib.sha256)
        while (True):
            buffer = file.read(bufsz)
            h.update(buffer)
            if (len(buffer) != bufsz):
                break
        return h.digest()

    @staticmethod
    def get_chunk_hash(file, seed, chunksz=8192, bufsz=65536):
        """returns a hash of a chunk of the file provided.  the position of
        the chunk is determined by the seed.  additionally, the hmac of the
        chunk is calculated from the seed.

        :param file: a file like object to get the chunk hash from.  should
        support `read()`, `seek()` and `tell()`.
        :param seed: the seed to use for calculating the chunk position and
        chunk hash
        :param chunksz: the size of the chunk to check
        :param bufsz: an optional buffer size to use for reading the file.
        """
        file.seek(0, 2)
        filesz = file.tell()
        if (filesz < chunksz):
            chunksz = filesz//10
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
