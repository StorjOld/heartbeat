heartbeat
=========

[![Build Status](https://drone.io/github.com/Storj/heartbeat/status.png)](https://drone.io/github.com/Storj/heartbeat/latest)

Python library for verifying existence of a file. Works with other Storj libraries and wrappers to allow to allow for Node A to trustlessly verify that Node B has a file by comparing hashes. This should be expanded to use Merkle trees, and data striping to optimize I/O. 

#### Functions

Create a heartbeat using a filepath.

````
heartbeat = Heartbeat('/file/path')
````

A heartbeat represents a file. To see if another file matches this file (in practice,
if another node has the file), generate challenges. Only nodes with the same file
in full will be likely to match the file's beat.

````
heartbeat.generate_challenges()
one_challenge = heartbeat.random_challenge()
````

Once there is a challenge, it can be posed to other heartbeats who can meet the
challenge.

````
another_heartbeat = Heartbeat('/path/to/file')
answer = another_heartbeat.meet_challenge(one_challenge)
````

The original heartbeat can verify the other heartbeat's answer.

````
if heartbeat.check_answer(answer):
	print('The heartbeat matches.')
else:
	print('The heartbeat does not match.')
````

The byte size of all a beat's challenges can be found using

```` 
heartbeat.challenges_size()
````

