import heartbeat.SwPriv

hla = heartbeat.SwPriv.SwPriv()

hla.gen()

public_hla = hla.get_public()

f = open("files/test7.txt","rb")

(tag,state) = hla.encode(f)

f.close()

challenge = hla.gen_challenge(state)

f = open("files/test7.txt","rb")

proof = public_hla.prove(f,challenge,tag,state)

if (hla.verify(proof,challenge,state)):
	print('proof valid')
else:
	print('proof invalid')