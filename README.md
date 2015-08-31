verify-hash
=====================================

A simple tool to verify that the hash of a downloaded file matches the expected value.
It computes the hash of a file and compares it to the expected value provided on
the command line.

**Usage**

	verify-hash.py  [-h]
					[--algorithm ]
					FILE HASH
	
	Verify hash of a file
	
	positional arguments:
	FILE                  file to compute hash
	HASH                  Expected hash value (in hex)
	
	optional arguments:
	-h, --help            show this help message and exit
	--algorithm {RIPEMD160,md5,MD4,sha,ripemd160,sha224,
	             sha384,sha1,dsaEncryption,SHA256,
				 ecdsa-with-SHA1,DSA-SHA,DSA,SHA224,MD5,
				 SHA,sha512,whirlpool,SHA384,md4,SHA1,
				 sha256,dsaWithSHA,SHA512}
						  algorithm used to compute hash

**Command Line Example**

Verification failure

	> verify-hash.py --algorithm=sha1 .gitignore C0BBC8F5931193D649C9D0AF3E02921B2C043900
	FAIL: .gitignore
	COMPUTED: 9E12A4DA8B38FE993CE11AEA37804E83A29CD357
	EXPECTED: C0BBC8F5931193D649C9D0AF3E02921B2C043900
	Hash does not match expected value.

Verification success
	
	> verify-hash.py --algorithm=sha1 .gitattributes C0BBC8F5931193D649C9D0AF3E02921B2C043900
	Hash matches expected value.
	
**Python Example**

    >>> verify_hash = __import__("verify-hash")
    >>> verify_hash.compare_hash(".gitattributes", algorithm="sha1", expected="1")
    FAIL: .gitattributes
    COMPUTED: C0BBC8F5931193D649C9D0AF3E02921B2C043900
    EXPECTED: 1
    False
	
	>>> verify_hash.compare_hash(".gitattributes", algorithm="sha1", expected="C0BBC8F5931193D649C9D0AF3E02921B2C043900")
	True

**Run Tests**

	> py -m doctest README.md