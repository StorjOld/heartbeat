# detection of random byte change

import random
from heartbeat import Swizzle
import RandomIO

modify = True

# create a 100MB file
file_size = int(1e8)
filename = RandomIO.RandomIO(b'seed').genfile(file_size)

hb = Swizzle.Swizzle()

#encode the file
with open(filename, 'rb') as f:
    (tag, state) = hb.encode(f)
    
# generate a challenge
chal = hb.gen_challenge(state)

if (modify):
    # modify a random bit
    byte_offset = random.randrange(0,file_size)
    bit_offset = random.randrange(0,8)

    with open(filename, 'r+b') as f:
        f.seek(byte_offset)        
        byte = f.read(1)[0]
        byte = byte ^ (1 << bit_offset)
        f.seek(byte_offset)
        f.write(bytes([byte]))
    
# generate a proof
with open(filename, 'rb') as f:
    proof = hb.prove(f, chal, tag)
    
# verify proof
if (hb.verify(proof, chal, state)):
    print('Proof valid')
else:
    print('Proof invalid')