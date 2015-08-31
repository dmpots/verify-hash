#! /usr/bin/env python3
import hashlib
import sys

def get_hash(input_file, algorithm):
	READ_SIZE=1024
	h = hashlib.new(algorithm)
	with open(input_file, "rb") as f:
		data = f.read(READ_SIZE)
		while data:
			h.update(data)
			data = f.read(READ_SIZE)
	return h.hexdigest()

def parse_args():
	import argparse
	
	parser = argparse.ArgumentParser(description='Verify hash of a file')
	parser.add_argument('input_file', metavar='FILE',
						help='file to compute hash')
	parser.add_argument("expected_hash", metavar="HASH",
						help="Expected hash value (in hex)")
	parser.add_argument('--algorithm',
				        choices=hashlib.algorithms_available,
						default="sha1",
						help='algorithm used to compute hash')
	
	args = parser.parse_args()
	return args

def compare_hash(file_name, algorithm, expected):
	computed_hash = get_hash(file_name, algorithm)
	computed = computed_hash.upper()
	expected = expected.upper()
	
	if computed != expected:
		print("FAIL: {}\nCOMPUTED: {}\nEXPECTED: {}".format(file_name, computed, expected))
		return False
	
	return True


def main():
	options = parse_args()
	
	expected_hash = options.expected_hash
	hashes_match  = compare_hash(options.input_file, options.algorithm, expected_hash)
	
	if hashes_match:
		print("Hash matches expected value.")
		sys.exit(0)
	else:
		print("Hash does not match expected value.")
		sys.exit(1)
	
if __name__ == "__main__":
	main()
