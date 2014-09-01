heartbeat
=========

This is the API for heartbeat, of which there can be many different types.  There are at least two distinct structures: public and private verifiable schemes.  For publically verifiable schemes, the auditor must only have a public beat (generated from a private beat with `beat.public()` ).  

#### Overview

```python
beat = heartbeat()
```

Beat represents a proof of storage scheme.

```python
beat.gen()
```

Generates public and private keys for the scheme.

```python
public_beat = beat.get_public()
```

Retrieves the public beat, which contains public parameters and set up parameters for sending to the server or auditors.

```python
(tag,state) = beat.encode(file)
```

The tag encapsulates data about the file which will be used by a server to verify that it has stored the file.  The file, tag and state information are sent to server (tag may or may not be quite large).  The state information will be signed and/or encrypted.

```python
challenge = beat.gen_challenge(state)
```

This should generate a challenge key which is unique.  This step may or may not be necessary, since the challenge information could be drawn by the server from another source (for instance, last hash of bitcoin blockchain header).  In the publically verifiable case it should be possible to call `public_beat.gen_challenge()` and in many cases it is possible to call `heartbeat.gen_challenge()` .

```python
proof = public_beat.prove(file,challenge,tag,state)
```

This calculates a proof which shows that the file exists.

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

#### Hash challenge scheme

The old hash challenge scheme fits within the above as a privately verifiable scheme.

#### Installation

To build the SwPriv python extension module which is a privately verifiable Homomorphic Linear Authentication scheme, use setup.py.  You must have Crypto++ installed.

To build and install heartbeat.SwPriv on a linux system:

```
python3 setup.py build
sudo python3 setup.py install
```

Your C++ compiler must support C++11, although really only for support of std::unique_ptr, which isn't included in the standard library before C++11.

Also note that setup.py is configured to compile against the static Crypto++ library, not the DLL, and so on windows it defaults to searching for cryptlib, not cryptopp.





