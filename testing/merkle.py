from heartbeat import Merkle

m = Merkle.Merkle()

m.gen()

public_m = m.get_public()

with open("files/test7.txt","rb") as f:
    (tag,state) = m.encode(f)

challenge = m.gen_challenge(state)

with open("files/test7.txt","rb") as f:
    proof = public_m.prove(f,challenge,tag)

if (m.verify(proof,challenge,state)):
	print('proof valid')
else:
	print('proof invalid')

