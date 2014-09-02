from heartbeat import SwPriv,Merkle

tests = {"Merkle" : Merkle.Merkle,
         "SwPriv" : SwPriv.SwPriv}

def test_heartbeat(heartbeat,n=10):

    beat = heartbeat()

    beat.gen()

    public_beat = beat.get_public()

    with open("files/test7.txt","rb") as f:
        (tag,state) = beat.encode(f)

    for i in range(n):
        challenge = beat.gen_challenge(state)

        with open("files/test7.txt","rb") as f:
            proof = public_beat.prove(f,challenge,tag)

        if (beat.verify(proof,challenge,state)):
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