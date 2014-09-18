heartbeat
=========

This is the API for heartbeat which is for proving the existance of a file on a remote server without downloading the entire file.  In theory there are both publicly and privately verifiable schemes.  Publicly verifiable schemes work even when the data auditor does not have access to any more information than the person storing the data.  Privately verifiable schemes work only when the auditor has access to secrets that the storer does not have.

Right now there are three working implementations of this scheme.  Merkle, SwPriv, and PySwPriv.  See Implementations below for more information.

#### Overview

In practice, the client and server will run an implementation of this software.  Before uploading, the client `tag`s the target `file` and some `state` information is generated.  Then the `tag`, `state` and `file` are stored on the remote server.  When the client wants to verify that the server is storing the data, he retrieves the `state` information, generates a `challenge`, and sends that `challenge` to the server.  The server then sends back a `proof` that is calculated from the `challenge`, the `tag`, and the `file`.  The client can then verify from the `proof` that the server is storing the `file`.

The `file` is a binary readable object that implements methods `read`, `seek`, and `tell`.

The `tag` is a potentially large set of information that matches the particular file that is stored.

The `state` is a possibly encrypted and signed set of data that represents some of the information about how the tags were generated, and allows verification of the file by the client.  In a publicly verificable scheme, the state information would not be encrypted, and might not be necessary.

The `challenge` is a set of data that informs the server how to calculate a proof.  It is not predictable by the server and therefore the response cannot be predetermined.

The `proof` is a set of data that represents proof that the server has read access to the complete file contents.

For transferring of data between client and server the `tag`, `state`, `challenge`, and `proof` objects can be pickled since they should provide at the very least `__getstate__()` and `__setstate__()` methods.

#### Usage

The API for a heartbeat module is given below.  The specific implementation of each heartbeat type should be subclasses of the heartbeat class as used below.

```python
beat = heartbeat()
```

Beat represents a proof of storage scheme.  Data internal to the beat is essential for all functions.  This generates public and private keys for the scheme.

```python
public_beat = beat.get_public()
```

Retrieves the public beat, which contains public parameters and set up parameters for sending to the server or auditors.  This strips any private keys but maintains public information.

```python
(tag,state) = beat.encode(file)
```

The tag encapsulates data about the file which will be used by a server to verify that it has stored the file.  The file, tag and state information are sent to server (tag may or may not be quite large).  The state information will be signed and/or encrypted.  The state information is information that can be outsourced but is necessary for verification.  State and tag are sent to the server for storage.  These are separate because in some cases the state information needs to be transmitted apart from the tag.  The client should maintain the heartbeat because it contains the private keys for generation and verification of challenges.

After a time has passed, when an auditor wants to verify the challenge, if necessary he should request the state back from the server.  Then, he can generate a challenge:

```python
challenge = beat.gen_challenge(state)
```

This should generate a challenge key which is unique.  This step may or may not be necessary, since in some schemes the challenge information could be drawn by the server from another source (for instance, last hash of bitcoin blockchain header).  In the publically verifiable case it should be possible to call `public_beat.gen_challenge()` and in many cases it is possible to call the static message `heartbeat.gen_challenge()`.  Then, the challenge, and possibly the public_beat if not already sent, are sent to the server who proves the file existance by running:

```python
proof = public_beat.prove(file,challenge,tag)
```

This calculates a proof which shows that the file exists.  Then the proof is sent back to the auditor who verifies the challenge.

```python
if (beat.verify(proof,challenge,state)):
	print('file is stored by the server')
else:
	print('file may not be stored')
```

Verifies in a private verification scheme that the file exists.

```python
if (public_beat.verify(proof,challenge,state)):
	print('file is stored by the server')
else:
	print('file may not be stored')
```

Verifies in a public verification scheme that the file exists.

#### Implementations

##### Merkle

This is a merkle tree hash proof of storage scheme.  It works by pre-generating a large number of deterministic hash challenges from a secret seed and file chunks.  Then it forms a merkle tree from these challenges and uploads the file and the merkle tree (with leaves stripped) to the server.  To verify presence of the file, a new seed is deterministically generated and sent to the server.  Then the appropriate branch of the merkle tree is sent back along with the leaf.  The client can verify that the merkle tree branch is valid, thereby verifying existance of the file.

The current implementation uses a random chunk of the file for each challenge, so any one challenge cannot verify the presence of the entire file.

##### SwPriv

This is a homomorphic linear authentication scheme based on work by Shacham and Waters, see Shacham, Waters "Compact proofs of Retrievability".  Please see that paper or look at the code for details of the implementation.  From the paper:

The user authenticates each block as follows. She chooses a random alpha in `Zp` and PRF key `k` for
function `f`. These values serve as her secret key. She calculates an authentication value for each
block `i` as

```
sigma_i = f_k(i) + alpha*m_i
```

where `m_i` is a small chunk of the file in `Zp` (a prime, by default 1024 bits long).

The blocks `m_i` and authenticators `sigma_i` are stored on the server. The proof of retrievability
protocol is as follows. The verifier chooses a random challenge set `I` of `l` indices along with `l` random
coefficients in `Zp`.  Let `Q` be the set `{(i,v_i)}` of challenge index-coefficient pairs. The verifier sends
`Q` to the prover. The prover then calculates the response, a pair `(sigma,mu)`, as

```
sigma = sum(v_i * sigma_i)
```

and

```
mu = sum(v_i * m_i)
```

Now verifier can check that the response was correctly formed by checking that

```
sigma ?= alpha * mu + sum(v_i * f_k(i))
```

Please see the paper or the code for more details.  This scheme as described above obviously requires 2x storage on the server since the file tags are the same size as the file.  However, it is possible to reduce the storage requirement significantly at the cost of increasing the communication by a small amount, which the implementation currently does.  By default it reduces the extra storage requirement by 10 times, so that the storage requirement is 1.1x.

##### PySwPriv

This is the same as SwPriv but written in pure python.  It is significantly slower (understandably) but provides the same functionality.

#### Installation

To build the heartbeat modules, including C++ SwPriv python extension module which is a privately verifiable Homomorphic Linear Authentication scheme, use pip.  You must have Crypto++ installed.

```
pip install .
```

Also note that setup.py is configured to compile against the static Crypto++ library, not the DLL, and so on windows it defaults to searching for cryptlib, not cryptopp.  Make sure cryptlib is located in the library search directory.

