# heartbeat Changelog

### Master

* [BUGFIX] Fixed merkle bug where different python versions would provide different proofs due to inconsistency of the random package across python versions.
* [OPTIMIZATION] Improved get_public() method for Swizzle to prevent unncessary initialization
* [BUGFIX] Fixed merkle bug that allowed repeating proofs with different challenges (#28)

### 0.1.5

* [ENHANCEMENT] Added CHANGELOG.md for moving to changelog model of releases.
* [ENHANCEMENT] SwPriv renamed to Swizzle