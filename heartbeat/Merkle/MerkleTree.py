#
# The MIT License (MIT)
#
# Copyright (c) 2014 William T. James
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import math
import hashlib

from ..util import hb_encode, hb_decode

# numbering scheme:
# nodes                                   0
#                         1                               2
#                 3               4               5
#             7      8        9      10      11
#          15  16  17  18  19  20  21  22  23

# leaves:   0 - 1 - 2 - 3 - 4 - 5 - 6 - 7 - 8 - 0 - 0 - 0 - 0 - 0 - 0 - 0


class MerkleLeaf(object):

    def __init__(self, index, blob):
        self.index = index
        self.blob = blob

    def __eq__(self, other):
        return (isinstance(other, MerkleLeaf)
                and self.index == other.index
                and self.blob == other.blob)

    def get_hash(self):
        h = hashlib.sha256(self.blob)
        h.update(str(self.index).encode())
        return h.digest()

    def todict(self):
        return {'index': self.index,
                'blob': hb_encode(self.blob)}

    @staticmethod
    def fromdict(dict):
        return MerkleLeaf(dict['index'], hb_decode(dict['blob']))


class MerkleBranch(object):

    def __init__(self, order):
        self.rows = [(b'', b'')] * order

    def __eq__(self, other):
        return isinstance(other, MerkleBranch) and self.rows == other.rows

    def get_left(self, i):
        return self.rows[i][0]

    def get_right(self, i):
        return self.rows[i][1]

    def set_row(self, i, value):
        self.rows[i] = value

    def get_order(self):
        return len(self.rows)

    def todict(self):
        return {'rows': list(map(lambda x: (hb_encode(x[0]),
                                            hb_encode(x[1])), self.rows))}

    @staticmethod
    def fromdict(dict):
        self = MerkleBranch(len(dict['rows']))
        self.rows = list(map(lambda x: (hb_decode(x[0]),
                                        hb_decode(x[1])), dict['rows']))
        return self


class MerkleTree(object):

    """This provides a simple MerkleTree implementation for use in the Merkle
    proof of storage scheme.  A leaf refers to the bottom level of the tree,
    while a branch is a list of pairs between the leaf and the root, not
    including the leaf or root.

    Generally, this is designed to be a static tree, in that you add the
    leaves using the `add_leaf()` method, and then construct the tree using
    the `build()` method.
    """

    def __init__(self):
        """Initialization method

        Creates an empty tree
        """
        self.nodes = list()
        self.order = 0
        self.leaves = list()

    def __eq__(self, other):
        return (isinstance(other, MerkleTree) and
                self.nodes == other.nodes and
                self.order == other.order and
                self.leaves == other.leaves)

    def todict(self):
        return {'nodes': hb_encode(self.nodes),
                'order': self.order,
                'leaves': list(map(lambda x: x.todict(), self.leaves))}

    @staticmethod
    def fromdict(dict):
        self = MerkleTree()
        self.nodes = hb_decode(dict['nodes'])
        self.order = dict['order']
        self.leaves = list(
            map(lambda x: MerkleLeaf.fromdict(x), dict['leaves']))
        return self

    def add_leaf(self, leaf_blob):
        """Adds a leaf to the list of leaves.  Does not build the tree so call
        `build()` to construct the rest of the tree from the added leaves.

        :param leaf_blob: the leaf payload to add.  should be a hashable object
        """
        self.leaves.append(MerkleLeaf(len(self.leaves), leaf_blob))

    def build(self):
        """Builds the tree from the leaves that have been added.

        This function populates the tree from the leaves down non-recursively
        """
        self.order = MerkleTree.get_order(len(self.leaves))
        n = 2 ** self.order
        self.nodes = [b''] * 2 * n

        # populate lowest nodes with leaf hashes
        for j in range(0, n):
            if (j < len(self.leaves)):
                self.nodes[j + n - 1] = self.leaves[j].get_hash()
            else:
                break

        # now populate the entire tree
        for i in range(1, self.order + 1):
            p = 2 ** (self.order - i)
            for j in range(0, p):
                k = p + j - 1
                h = hashlib.sha256()
                l = self.nodes[MerkleTree.get_left_child(k)]
                if (len(l) > 0):
                    h.update(l)
                r = self.nodes[MerkleTree.get_right_child(k)]
                if (len(r) > 0):
                    h.update(r)
                self.nodes[k] = h.digest()

    def get_branch(self, i):
        """Gets a branch associated with leaf i.  This will trace the tree
        from the leaves down to the root, constructing a list of tuples that
        represent the pairs of nodes all the way from leaf i to the root.

        :param i: the leaf identifying the branch to retrieve
        """
        branch = MerkleBranch(self.order)
        j = i + 2 ** self.order - 1

        for k in range(0, self.order):
            if (self.is_left(j)):
                branch.set_row(k, (self.nodes[j], self.nodes[j + 1]))
            else:
                branch.set_row(k, (self.nodes[j - 1], self.nodes[j]))
            j = MerkleTree.get_parent(j)

        return branch

    def get_root(self):
        """Returns the merkle root of the tree"""
        return self.nodes[0]

    def strip_leaves(self):
        """strips the leaves off the tree"""
        self.leaves = list()

    @staticmethod
    def get_parent(i):
        """This method returns the node id of the parent of the given node

        :param i: the node id specifying the node to get the parent of
        """
        return (i + 1) // 2 - 1

    @staticmethod
    def get_partner(i):
        """Returns the partner node of the given node id

        :param i: the node id to get the partner of
        """
        if MerkleTree.is_left(i):
            return i + 1
        else:
            return i - 1

    @staticmethod
    def is_left(i):
        """Returns True if the given node is a left node

        :param i: the node id to check
        """
        return i % 2 != 0

    @staticmethod
    def get_left_child(i):
        """Returns the node id of the left child of the given node

        :param i: the node id to get the left child of
        """
        return (i + 1) * 2 - 1

    @staticmethod
    def get_right_child(i):
        """Returns the right chid of the given node

        :param i: the node id to get the right child of
        """
        return (i + 1) * 2

    @staticmethod
    def get_order(n):
        """Returns the order of the tree with n leaves.  This is the required
        number of levels of the tree given that there will be n leaves.

        :param n: the number of leaves of the tree to obtain the order of
        """
        return int(math.ceil(math.log(n, 2)))

    @staticmethod
    def verify_branch(leaf, branch, root):
        """This will verify that the given branch fits the given leaf and root
        It calculates the hash of the leaf, and then verifies that one of the
        bottom level nodes in the branch matches the leaf hash.  Then it
        calculates the hash of the two nodes on the next level and checks that
        one of the nodes on the level above matches.  It continues this until
        it reaches the top level of the tree where it asserts that the root is
        equal to the hash of the nodes below

        :param leaf: the leaf to check
        :param branch: a list of tuples (pairs) of the nodes in the branch,
        ordered from leaf to root.
        :param root: the root node
        """
        # just check the hashes are correct
        try:
            lh = leaf.get_hash()
        except:
            return False
        for i in range(0, branch.get_order()):
            if (branch.get_left(i) != lh and branch.get_right(i) != lh):
                return False
            h = hashlib.sha256()
            if (len(branch.get_left(i)) > 0):
                h.update(branch.get_left(i))
            if (len(branch.get_right(i)) > 0):
                h.update(branch.get_right(i))
            lh = h.digest()
        if (root != lh):
            return False
        return True
