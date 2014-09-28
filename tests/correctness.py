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

from heartbeat import SwPriv,Merkle

tests = {"Merkle": Merkle.Merkle,
         "SwPriv": SwPriv.SwPriv }


def test_heartbeat(heartbeat, n=10):

    beat = heartbeat()

    beat.gen()

    public_beat = beat.get_public()

    with open("tests/files/test7.txt", "rb") as f:
        (tag, state) = beat.encode(f)

    for i in range(n):
        challenge = beat.gen_challenge(state)

        with open("tests/files/test7.txt", "rb") as f:
            proof = public_beat.prove(f, challenge, tag)

        if (beat.verify(proof, challenge, state)):
            print("passed test "+str(i))
        else:
            print("failed test "+str(i))
            return False

    return True


for b in tests:
    if (test_heartbeat(tests[b])):
        print(b+" seems correct.")
    else:
        print(b+" is incorrect.")
