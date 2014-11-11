import json

class GenericCorrectnessTests(object):
    @staticmethod
    def generic_correctness_test(test,hb,fn1='files/test.txt',fn2='files/test3.txt'):
        priv = hb()
        pub = priv.get_public()
        with open(fn1,'rb') as file:
            (tag,state) = priv.encode(file)
        chal = priv.gen_challenge(state)
        with open(fn1,'rb') as file:
            proof = pub.prove(file,chal,tag)
        test.assertTrue(priv.verify(proof,chal,state))
        
        with open(fn2,'rb') as file:
            proof = pub.prove(file,chal,tag)
        test.assertFalse(priv.verify(proof,chal,state))
    
    @staticmethod
    def generic_test_repeated_challenge(test,hb,fn1='files/test.txt'):
        priv = hb()
        pub = priv.get_public()
        with open(fn1,'rb') as f:
            (tag, state) = priv.encode(f)
        chal1 = priv.gen_challenge(state)
        with open(fn1,'rb') as f:
            proof1 = pub.prove(f,chal1,tag)
        test.assertTrue(priv.verify(proof1,chal1,state))
        # now we generate a new challenge and verify that the old challenge does not work
        chal2 = priv.gen_challenge(state)
        test.assertFalse(priv.verify(proof1,chal2,state))
    
    @staticmethod
    def generic_scheme_test(test,hb,n=20,fn='files/test.txt'):
        # set up client
        print('set up client')
        client = hb()
        
        # send public heart beat to server
        print('send public heart beat to server')
        pub = client.get_public()
        message = json.dumps(pub.todict())
        print('message: {0}'.format(message))
        
        del pub
        
        # set up server
        print('set up server')
        dict = json.loads(message)
        server = hb.fromdict(dict)
        
        # encode the file
        print('encode the file')
        with open(fn,'rb') as file:
            (tag,state) = client.encode(file)
        
        message = json.dumps({'tag': tag.todict(),'state': state.todict()})
        print('message: {0}'.format(message))
        # file would also be sent
        
        # delete client side information
        del state,tag
        
        # store server side information
        print('store server side information')
        obj = json.loads(message)
        serv_tag = hb.tag_type().fromdict(obj['tag'])
        serv_state = hb.state_type().fromdict(obj['state'])
        
        for i in range(0,n):
            # client now wants to challenge server
            # client requests state from server
            
            # server sends back state
            print('server sends back state')
            message = json.dumps(serv_state.todict())
            print('message: {0}'.format(message))
            
            # client interprets state from server
            print('client interprets state from server')
            dict = json.loads(message)
            state = hb.state_type().fromdict(dict)
            
            # client generates challenge
            print('client generates challenge')
            chal = client.gen_challenge(state)
            
            # client sends challenge and new state to server
            print('client sends challenge and new state to server')
            message = json.dumps({'challenge':chal.todict(),'state':state.todict()})
            print('message: {0}'.format(message))
            
            # server interprets challenge from client
            print('server interprets challenge from client')
            obj = json.loads(message)
            serv_chal = hb.challenge_type().fromdict(obj['challenge'])
            serv_state = hb.state_type().fromdict(obj['state'])
            
            # server generates proof
            print('server generates proof')
            with open(fn,'rb') as file:
                serv_proof = server.prove(file,serv_chal,serv_tag)
            
            # send proof back to client
            print('send proof back to client')
            message = json.dumps(serv_proof.todict())
            print('message: {0}'.format(message))
            
            # client interprets proof from server
            print('client interprets proof from server')
            dict = json.loads(message)
            proof = hb.proof_type().fromdict(dict)
            
            # client checks proof
            print('client checks proof')
            test.assertTrue(client.verify(proof,chal,state))
        