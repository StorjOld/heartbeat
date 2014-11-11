import RandomIO
import heartbeat
import timeit
import os

print('This tests the three libraries for speed.  Please note,\n'
      'the Merkle library is only encoding and checking a fraction\n'
      'of the file, and so the speed number has been adjusted to\n'
      'compensate for this fact.\n')

size = 1e6
n=10

class TestCase(object):
    def __init__(self, beat, encode_fraction):
        self.beat = beat
        self.fraction = encode_fraction


beats = [TestCase(heartbeat.Swizzle.Swizzle,1.0),
         TestCase(heartbeat.Merkle.Merkle,heartbeat.Merkle.DEFAULT_CHUNK_SIZE/size)]

for case in beats:
    print('======= Speed testing {0} ======'.format(case.beat.__name__))

    beat = case.beat()
    
    path = RandomIO.RandomIO().genfile(int(size))

    with open(path,'rb') as f:
        (tag,state) = beat.encode(f)
        print('encode: {0} MB/s'.format(case.fraction*size*n/1e6/timeit.timeit('f.seek(0);beat.encode(f)',setup='from __main__ import beat,f',number=n)))
        
    chal = beat.gen_challenge(state)
    print('gen_challenge: {0} MB/s'.format(size*n/1e6/timeit.timeit('beat.gen_challenge(state)',setup='from __main__ import beat,state',number=n)))

    with open(path,'rb') as f:
        proof = beat.prove(f,chal,tag)
        print('prove: {0} MB/s'.format(case.fraction*size*n/1e6/timeit.timeit('f.seek(0);beat.prove(f,chal,tag)',setup='from __main__ import beat,f,chal,tag',number=n)))

    valid = beat.verify(proof,chal,state)
    print('verify: {0} MB/s'.format(size*n/1e6/timeit.timeit('beat.verify(proof,chal,state)',setup='from __main__ import beat,proof,chal,state',number=n)))

    if (not valid):
        raise RuntimeError('Proof invalid')
    
    os.remove(path)
    
    print('\n')