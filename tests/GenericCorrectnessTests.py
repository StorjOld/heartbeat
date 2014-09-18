import pickle

class GenericCorrectnessTests(object):
    @staticmethod
    def generic_correctness_test(test,hb):
        priv = hb()
        pub = priv.get_public()
        with open('files/test.txt','rb') as file:
            (tag,state) = priv.encode(file)
        chal = priv.gen_challenge(state)
        with open('files/test.txt','rb') as file:
            proof = pub.prove(file,chal,tag)
        test.assertTrue(priv.verify(proof,chal,state))
        
        with open('files/test3.txt','rb') as file:
            proof = pub.prove(file,chal,tag)
        test.assertFalse(priv.verify(proof,chal,state))
        
    @staticmethod
    def generic_scheme_test(test,hb):
        # set up client
        client = hb()
        
        # send public heart beat to server
        pub = client.get_public()
        message = pickle.dumps(pub,2)
        
        del pub
        
        # set up server
        server = pickle.loads(message)
        
        # encode the file
        with open('files/test.txt','rb') as file:
            (tag,state) = client.encode(file)
        
        message = pickle.dumps((tag,state),2)
        # file would also be sent
        
        # delete client side information
        del state,tag
        
        # store server side information
        (serv_tag,serv_state) = pickle.loads(message)
        
        # client now wants to challenge server
        # client requests state from server
        
        # server sends back state
        message = pickle.dumps(serv_state,2)
        
        # client interprets state from server
        state = pickle.loads(message)
        
        # client generates challenge
        chal = client.gen_challenge(state)
        
        # client sends challenge to server
        message = pickle.dumps(chal,2)
        
        # server interprets challenge from client
        serv_chal = pickle.loads(message)
        
        # server generates proof
        with open('files/test.txt','rb') as file:
            serv_proof = server.prove(file,serv_chal,serv_tag)
        
        # send proof back to client
        message = pickle.dumps(serv_proof,2)
        
        # client interprets proof from server
        proof = pickle.loads(message)
        
        # client checks proof
        test.assertTrue(client.verify(proof,chal,state))
        