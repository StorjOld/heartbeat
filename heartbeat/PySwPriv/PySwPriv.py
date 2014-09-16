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

from ..exc import HeartbeatError
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Util import number


class KeyedPRF(object):
    # keyed prf is a psuedo random function
    # it hashes the input, pads it to the correct output
    # length, and then encrypts it with AES
    # finally it checks that the result is within the desired range
    # if it is it returns the value as a long integer
    @staticmethod
    def pad(data, length):
        if (len(data) > length):
            return data[0:length]
        else:
            return data + b"\0"*(length-len(data))

    def __init__(self, key, range):
        self.key = key
        self.range = range
        # we need a mask because the number we'll generate will be of a
        # certain byte size but we want to restrict it to within a
        # certain bit size because we're trying to find numbers within
        # a certain range this will speed it up
        self.mask = (1 << number.size(self.range))-1

    def eval(self, x):
        aes = AES.new(self.key, AES.MODE_CFB, "\0"*AES.block_size)
        while True:
            nonce = 0
            data = KeyedPRF.pad(SHA256.new(str(x+nonce).encode()).digest(),
                                (number.size(self.range)+7)//8)
            num = self.mask & number.bytes_to_long(aes.encrypt(data))
            if (num < self.range):
                return num
            nonce += 1


class Challenge(object):
    # chunks : number of chunks to challenge
    # v_max : largest coefficient value
    # key : the key for this challenge
    def __init__(self, chunks, v_max, key):
        self.chunks = chunks
        self.v_max = v_max
        self.key = key


class Tag(object):
    def __init__(self):
        self.sigma = list()


class State(object):
    def __init__(self, f_key, alpha_key, chunks=0,
                 encrypted=False, iv=None, hmac=None):
        self.f_key = f_key
        self.alpha_key = alpha_key
        self.chunks = chunks
        self.encrypted = encrypted
        self.iv = iv
        self.hmac = hmac

    def encrypt(self, key):
        if (self.encrypted):
            return
        # encrypt
        self.iv = Random.new().read(AES.block_size)
        aes = AES.new(key, AES.MODE_CFB, self.iv)
        self.f_key = aes.encrypt(self.f_key)
        self.alpha_key = aes.encrypt(self.alpha_key)
        # sign
        h = HMAC.new(key, None, SHA256)
        h.update(self.iv)
        h.update(str(self.chunks).encode())
        h.update(self.f_key)
        h.update(self.alpha_key)
        self.hmac = h.digest()
        self.encrypted = True

    def decrypt(self, key):
        if (not self.encrypted):
            return
        # check signature
        h = HMAC.new(key, None, SHA256)
        h.update(self.iv)
        h.update(str(self.chunks).encode())
        h.update(self.f_key)
        h.update(self.alpha_key)
        if (h.digest() != self.hmac):
            raise HeartbeatError("Signature invalid on state.")
        # decrypt
        aes = AES.new(key, AES.MODE_CFB, self.iv)
        self.f_key = aes.decrypt(self.f_key)
        self.alpha_key = aes.decrypt(self.alpha_key)
        self.encrypted = False


class Proof(object):
    def __init__(self):
        self.mu = list()
        self.sigma = None


class PySwPriv(object):
    def __init__(self, sectors=10, key=None, prime=None, primebits=1024):
        if (key == None):
            self.key = Random.new().read(32)
        else:
            self.key = key
        if (prime == None):
            self.prime = number.getPrime(self.primebits)
        else:
            self.prime = prime
        self.sectors = sectors
        self.sectorsize = primebits//8
        self.primebits = primebits

    def get_public(self):
        return PySwPriv(self.sectors, None, self.prime)

    def encode(self, file):
        tag = Tag()
        tag.sigma = list()

        state = State(Random.new().read(32), Random.new().read(32))

        f = KeyedPRF(state.f_key, self.prime)
        alpha = KeyedPRF(state.alpha_key, self.prime)

        done = False
        chunk_id = 0

        while (not done):
            sigma = f.eval(chunk_id)
            for j in range(0, self.sectors):
                buffer = file.read(self.sectorsize)

                if (len(buffer) > 0):
                    sigma += alpha.eval(j) * number.bytes_to_long(buffer)

                if (len(buffer) != self.sectorsize):
                    done = True
                    break
            sigma %= self.prime
            tag.sigma.append(sigma)
            chunk_id += 1

        state.chunks = chunk_id
        state.encrypt(self.key)

        return (tag, state)

    def gen_challenge(self, state):
        state.decrypt(self.key)

        chal = Challenge(state.chunks, self.prime, Random.new().read(32))

        return chal

    def prove(self, file, chal, tag):

        chunk_size = self.sectors*self.sectorsize

        index = KeyedPRF(chal.key, len(tag.sigma))
        v = KeyedPRF(chal.key, chal.v_max)

        proof = Proof()
        proof.mu = [0]*self.sectors
        proof.sigma = 0

        for j in range(0, self.sectors):
            for i in range(0, chal.chunks):
                pos = index.eval(i) * chunk_size + j * self.sectorsize
                if (file.seek(pos) == pos):
                    buffer = file.read(self.sectorsize)
                    proof.mu[j] += v.eval(i) * number.bytes_to_long(buffer)
                else:
                    break
            proof.mu[j] %= self.prime

        for i in range(0, chal.chunks):
            proof.sigma += v.eval(i) * tag.sigma[index.eval(i)]

        proof.sigma %= self.prime

        return proof

    def verify(self, proof, chal, state):
        state.decrypt(self.key)

        index = KeyedPRF(chal.key, state.chunks)
        v = KeyedPRF(chal.key, chal.v_max)
        f = KeyedPRF(state.f_key, self.prime)
        alpha = KeyedPRF(state.alpha_key, self.prime)

        rhs = 0

        for i in range(0, chal.chunks):
            rhs += v.eval(i) * f.eval(index.eval(i))

        for j in range(0, self.sectors):
            rhs += alpha.eval(j) * proof.mu[j]

        rhs %= self.prime
        return proof.sigma == rhs
