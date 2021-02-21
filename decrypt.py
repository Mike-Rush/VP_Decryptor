# -*- coding: utf-8 -*-
import sys, os
import argparse as AP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
import P1735Parser

def parse_args(args):
	argParser = AP.ArgumentParser(description = "Decrypt P1735 encrypted modules")
	argParser.add_argument("-keyname",
						   nargs=1,
						   type=str,
						   required=False,
						   help="RSA private key name (equals key filename if not specified)",
						   metavar = "KEYNAME",
						   dest = 'keyname')
	argParser.add_argument("-key",
						   nargs=1,
						   type=AP.FileType("r"),
						   required=True,
						   help="RSA private key",
						   metavar = "IN.pem",
						   dest = 'keyfile')
	argParser.add_argument("-in",
						   nargs=1,
						   type=AP.FileType("r"),
						   required=True,
						   help="File to decrypt",
						   metavar = "IN.vp",
						   dest = 'infile')
	argParser.add_argument("-out",
						   nargs=1,
						   type=AP.FileType("w"),
						   required=False,
						   help="Destination of dectyption (stdout if not specified)",
						   metavar = "OUT.vp",
						   dest = 'outfile')
	return argParser.parse_args(args)

def parse_encrypted_file(fd):
	parser = P1735Parser.P1735Parser()
	#line_all=""
	for line in fd.readlines():
		#line_all=line_all+line.strip('\n')
		#print(line)
		parser.feed(line)
	#print(line_all)
	#parser.feed(line_all)
	return parser

def rsa_decrypt(fd, data):
	#print(fd.read())
	rsakey = RSA.importKey(fd.read())
	cipher = PKCS1_v1_5.new(rsakey)
	return cipher.decrypt(data, None)

def aes128_cbc_decrypt(key, data):
	unpad = lambda s : s[:-ord(s[len(s)-1:])]
	iv = data[:16]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	return unpad(cipher.decrypt(data[16:]))

if __name__ == "__main__":
	args = parse_args(sys.argv[1:])
	if args.keyname == None:
		get_keyname = lambda f: os.path.basename(f).split('.')[0]
		keyname = get_keyname(args.keyfile[0].name)
	else:
		keyname = args.keyname[0]
	edata = parse_encrypted_file(args.infile[0])
	try:
		esession_key = edata.session_keys[keyname]
	except KeyError:
		print("No such key: %s" % keyname)
		print("Need any one of these:")
		for kn in edata.session_keys.keys():
			print("    %s" % kn)
		sys.exit(1)

	session_key = rsa_decrypt(args.keyfile[0], esession_key)
	#print(session_key)
	session_key_pos=session_key.find(b'session_keyx')+13
	#print(session_key_pos)
	session_key_true=session_key[session_key_pos:session_key_pos+32]
	#print(session_key_true)
	str_tmp=bytes.decode(session_key_true)
	#print(str_tmp)
	session_key_bytes=bytes.fromhex(str_tmp)
	decrypted_data = aes128_cbc_decrypt(session_key_bytes, edata.encrypted_data)
	if args.outfile:
		outfile = args.outfile[0]
	else:
		outfile = sys.stdout
	#print(decrypted_data)
	outfile.write(bytes.decode(decrypted_data))