# heartbeat Changelog

### 0.1.10

* [BUGFIX] Fixed type error where comparison of two different types resulted in type error instead of False.  Now it just returns True on not equal and False for all other comparisons if the types are different.

### 0.1.9

* [BUGFIX] Fixed buffering error in Merkle
* [ENHANCEMENT] Added filesz parameter for prove and encode methods incase file size is known in advance for optimization.

### 0.1.8

* [BUGFIX] Fixed equality calculation to check for proofs.

### 0.1.7

* [BUGFIX] Fixed merkle bug where different python versions would provide different proofs due to inconsistency of the random package across python versions.

### 0.1.6

* [OPTIMIZATION] Improved get_public() method for Swizzle to prevent unncessary initialization
* [BUGFIX] Fixed merkle bug that allowed repeating proofs with different challenges (#28)

### 0.1.5

* [ENHANCEMENT] Added CHANGELOG.md for moving to changelog model of releases.
* [ENHANCEMENT] SwPriv renamed to Swizzle