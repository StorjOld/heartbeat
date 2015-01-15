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

import base64
from Crypto.Util import number
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def hb_encode(obj):
    if (type(obj) is list):
        return list(map(lambda x: hb_encode(x), obj))
    else:
        return base64.b64encode(obj).decode('utf-8')


def hb_decode(obj):
    if (type(obj) is list):
        return list(map(lambda x: hb_decode(x), obj))
    else:
        return base64.b64decode(obj.encode('utf-8'))


class KeyedPRF(object):

    """KeyedPRF is a psuedo random function. It hashes the input, pads it to
    the correct output length, and then encrypts it with AES. Finally it
    checks that the result is within the desired range. If it is it returns
    the value as a long integer, if it isn't, it increments a nonce in the
    input and recalculates until it finds an integer in the given range
    """
    @staticmethod
    def pad(data, length):
        """This function returns a padded version of the input data to the
        given length.  this function will shorten the given data to the length
        specified if necessary.  post-condition: len(data) = length

        :param data: the data byte array to pad
        :param length: the length to pad the array to
        """
        if (len(data) > length):
            return data[0:length]
        else:
            return data + b"\0" * (length - len(data))

    def __init__(self, key, range):
        """Initialization method

        :param key: the key to use for the PRF.  this key is the only source
        of randomness for the output of this function. should be a hashable
        object, preferably a byte array or string
        :param range: the output range as a long of the function. the output
        of the function will be in [0:range)
        """
        self.key = key
        self.range = range
        # we need a mask because the number we'll generate will be of a
        # certain byte size but we want to restrict it to within a
        # certain bit size because we're trying to find numbers within
        # a certain range this will speed it up
        self.mask = (1 << number.size(self.range)) - 1

    def eval(self, x):
        """This method returns the evaluation of the function with input x

        :param x: this is the input as a Long
        """
        aes = AES.new(self.key, AES.MODE_CFB, "\0" * AES.block_size)
        while True:
            nonce = 0
            data = KeyedPRF.pad(SHA256.new(str(x + nonce).encode()).digest(),
                                (number.size(self.range) + 7) // 8)
            num = self.mask & number.bytes_to_long(aes.encrypt(data))
            if (num < self.range):
                return num
            nonce += 1
