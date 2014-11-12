import RandomIO
import heartbeat
import timeit
import os
import pickle

n=10

class TestCase(object):
    def __init__(self, beat, encode_fraction, size, min_chals):
        self.beat = beat
        self.fraction = encode_fraction
        self.size = size
        self.min_chals = min_chals

sizes = [1e3,1e4,1e5,1e6,1e7,1e8]
chals = [int(1e2),int(1e3),int(1e4),int(1e5)]

cf = 0.01

tests = list(map(lambda x: TestCase(heartbeat.Swizzle.Swizzle,cf,x,100), sizes))+\
            list(map(lambda x: TestCase(heartbeat.Merkle.Merkle,cf,x,100), sizes))+\
            list(map(lambda x: TestCase(heartbeat.Merkle.Merkle,cf,1e4,x), chals))

column_width = 14
print('{:<{width}}{:<{width}}{:<{width}}{:<{width}}{:<{width}}{:<{width}}{:<{width}}{:<{width}}'.format('type','file sz (MB)','chals','encode (MB/s)','chal (MB/s)','prove (MB/s)','verify (MB/s)','tag sz (MB)',width=column_width))

results = []
          
for case in tests:
    beat = case.beat(case.fraction)
    
    path = RandomIO.RandomIO().genfile(int(case.size))

    result = []
    
    with open(path,'rb') as f:
        if (case.beat is heartbeat.Merkle.Merkle):
            chals = case.min_chals
            (tag,state) = beat.encode(f, chals)
            result.append(case.size*n/1e6/timeit.timeit('f.seek(0);beat.encode(f,chals)',setup='from __main__ import beat,f,chals',number=n))            
        else:
            (tag,state) = beat.encode(f)
            chals = 'N/A'
            result.append(case.size*n/1e6/timeit.timeit('f.seek(0);beat.encode(f)',setup='from __main__ import beat,f,chals',number=n))            

    tag_size = len(pickle.dumps(tag))
    
    chal = beat.gen_challenge(state)
    result.append(case.size*n/1e6/timeit.timeit('beat.gen_challenge(state)',setup='from __main__ import beat,state',number=n))

    with open(path,'rb') as f:
        proof = beat.prove(f,chal,tag)
        result.append(case.size*n/1e6/timeit.timeit('f.seek(0);beat.prove(f,chal,tag)',setup='from __main__ import beat,f,chal,tag',number=n))

    valid = beat.verify(proof,chal,state)
    result.append(case.size*n/1e6/timeit.timeit('beat.verify(proof,chal,state)',setup='from __main__ import beat,proof,chal,state',number=n))

    if (not valid):
        raise RuntimeError('Proof invalid')
    
    os.remove(path)
    
    print('{:<{width}}{:<{width}.2}{:<{width}}{:<{width}.4}{:<{width}.4}{:<{width}.4}{:<{width}.4}{:<{width}}'.format(case.beat.__name__,case.size/1e6,chals,result[0],result[1],result[2],result[3],tag_size/1e6,width=column_width))
    results.append(result)    
