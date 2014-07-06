heartbeat
=========

Python library for verifying existence of a file. Works with other Storj libraries and wrappers to allow to allow for Node A to trustlessly verify that Node B has a file by comparing hashes. This should be expanded to use Merkle trees, and data striping to optimize I/O. 

#### Functions

Create a heartbeat using a filepath.

````
beat = HeartBeat(file_path)
````

A beat represents a file. To see if another file matches this file (in practice,
if another node has the file), generate challenges. Only nodes with the same file
in full will be likely to match the file's beat.

````
beat.gen_challenges()
a_challenge = beat.get_challenge()
````

Once there is a challenge, it can be posed to other beats who can meet the
challenge.

````
another_beat = HeartBeat(another_file_path)
answer = another_beat.meet_challenge(a_challenge)
````

The original beat can verify the other beat's answer.

````
if beat.check_answer(answer):
	print('The beat matches.')
else:
	print('The beat does not match.')
````

The byte size of all a beat's challenges can be found using

```` 
beat.challenges_size()
````

Refer to ````testing.py```` for simple and up to date code examples.
