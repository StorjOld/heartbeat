import pickle

class GenericCorrectnessTests(object):
    @staticmethod
    def generic_correctness_test(hb):
        priv = hb()
        pub = priv.get_public()
        file = open('files/test.txt','rb')
        (tag,state) = priv.encode(file)
        file.close()
        chal = priv.gen_challenge(state)
        file = open('files/test.txt','rb')
        proof = pub.prove(file,chal,tag)
        file.close()
        self.assertTrue(priv.verify(proof,chal,state))
        
        file = open('files/test3.txt','rb')
        proof = pub.prove(file,chal,tag)
        file.close()
        self.assertFalse(priv.verify(proof,chal,state))
        
    @staticmethod
    def generic_scheme_test(hb):
        # set up client
        client = hb()
        
        # send public heart beat to server
        pub = client.get_public()
        message = pickle.dumps(pub)
        
        del pub
        
        # set up server
        server = pickler.loads(message)
        
        # encode the file
        file = open('files/test.txt','rb')
        (tag,state) = client.encode(file)
        file.close()
        
        message = pickle.dumps((tag,state))
        # file would also be sent
        
        # delete client side information
        del state,tag
        
        # store server side information
        (serv_tag,serv_state) = pickle.loads(message)
        
        # client now wants to challenge server
        # client requests state from server
        
        # server sends back state
        message = pickle.dumps(serv_state)
        
        # client interprets state from server
        state = pickle.loads(message)
        
        # client generates challenge
        chal = client.gen_challenge(state)
        
        # client sends challenge to server
        message = pickle.dumps(chal)
        
        # server interprets challenge from client
        serv_chal = pickle.loads(message)
        
        # server generates proof
        file = open('files/test.txt','rb')
        serv_proof = server.prove(file,serv_chal,serv_tag)
        file.close()
        
        # send proof back to client
        message = pickle.dumps(serv_proof)
        
        # client interprets proof from server
        proof = pickle.loads(message)
        
        # client checks proof
        self.assertTrue(client.verify(proof,chal,state))
        