import math
import hashlib
import hmac
import base64
import heartbeat

# numbering scheme:
# branches                               0
#                         1                               2
#                 3               4               5         
#             7      8        9      10      11
#          15  16  17  18  19  20  21  22  23

# leaves:   0 - 1 - 2 - 3 - 4 - 5 - 6 - 7 - 8 - 0 - 0 - 0 - 0 - 0 - 0 - 0

class MerkleTree(object):
    def __init__(self,order=0):
        self.branches = list()
        self.order = 0
        self.leaves = list()

    @staticmethod
    def get_parent(i):
        return (i+1)//2-1

    @staticmethod
    def get_partner(i):
        if MerkleTree.is_left(i):
            return i+1
        else:
            return i-1

    @staticmethod
    def is_left(i):
        return i%2 != 0

    @staticmethod
    def get_left_child(i):
        return (i+1)*2-1

    @staticmethod
    def get_right_child(i):
        return (i+1)*2
    
    @staticmethod
    def get_order(n):
        return math.ceil(math.log2(n))

    def add_leaf(self,leaf):
        self.leaves.append(leaf)

    def build(self):
        self.order = MerkleTree.get_order(len(self.leaves))
        n = 2**self.order
        self.branches = [None]*2*n

        # populate lowest branches with leaf hashes
        for j in range(0,n):
            if (j < len(self.leaves)):
                h = hashlib.sha256()
                h.update(self.leaves[j])
                self.branches[j+n-1] = h.digest()
            else:
                break

        # now populate the entire tree
        for i in range(1,self.order+1):
            p = 2**(self.order-i)
            for j in range(0,p):
                k = p+j-1
                h = hashlib.sha256()
                l = self.branches[MerkleTree.get_left_child(k)]
                if (l):
                    h.update(l)
                r = self.branches[MerkleTree.get_right_child(k)]
                if (r):
                    h.update(self.branches[MerkleTree.get_right_child(k)])
                self.branches[k] = h.digest()

    # gets the branch of leaf i
    def get_branch(self,i):
        branch = [None]*(self.order)
        #print("Compiling branch "+str(i))
        j = i + 2**self.order - 1

        for k in range(0,self.order):
            if (self.is_left(j)):
                #print("("+str(j)+","+str(j+1)+")")
                branch[k] = (self.branches[j],self.branches[j+1])
            else:
                #print("("+str(j-1)+","+str(j)+")")
                branch[k] = (self.branches[j-1],self.branches[j])
            j = MerkleTree.get_parent(j)

        return branch

    @staticmethod
    def verify_branch(leaf,branch,root):
        #print("MerkleTree.verify_branch()")
        # just check the hashes are correct
        lh = hashlib.sha256(leaf).digest()
        for i in range(0,len(branch)):
            #print("Child hash = "+str(base64.b64encode(lh)))
            #if (branch[i][0]):
            #    print("Left hash = "+str(base64.b64encode(branch[i][0])))
            #if (branch[i][1]):
            #    print("Right hash = "+str(base64.b64encode(branch[i][1])))
            if (branch[i][0] != lh and branch[i][1] != lh):
                #print("Branch hash failed")
                return False;
            h = hashlib.sha256()
            if (branch[i][0]):
                h.update(branch[i][0])
            if (branch[i][1]):
                h.update(branch[i][1])
            lh = h.digest()
        if (root != lh):
            #print("Root hash failed")
            return False
        #print("Branch verified")
        return True

    # gets the merkle root
    def get_root(self):
        return self.branches[0]

    def strip_leaves(self):
        self.leaves = list()