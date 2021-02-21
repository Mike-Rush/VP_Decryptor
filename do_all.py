import sys, os
import argparse as AP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5
import P1735Parser

def parse_args(args):
	argParser = AP.ArgumentParser(description = "Decrypt SubDIR VP Files")
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
	argParser.add_argument("-indir",
							nargs=1,
							type=str,
							required=True,
							help="Input Files DIR",
							metavar =  "./",
							dest='indir'
							)
	argParser.add_argument("-outdir",
							nargs=1,
							type=str,
							required=True,
							help="Output Files DIR",
							metavar =  "./",
							dest='outdir'
							)
	return argParser.parse_args(args)

def parse_encrypted_file(fd):
	parser = P1735Parser.P1735Parser()
	for line in fd.readlines():
		parser.feed(line)
	return parser

def rsa_decrypt(fd, data):
	#print(fd.read())
	fd.seek(0,0)
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
	#edata = parse_encrypted_file(args.infile[0])
	#try:
	#	esession_key = edata.session_keys[keyname]
	#except KeyError:
	#	print("No such key: %s" % keyname)
	#	print("Need any one of these:")
	#	for kn in edata.session_keys.keys():
	#		print("    %s" % kn)
	#	sys.exit(1)
	#print(args.indir[0])
	cnt=0
	for root, dirs, files in os.walk(args.indir[0], topdown=True):
		for name in dirs:
			#print(os.path.join(root, name).replace(args.indir[0],args.outdir[0]))
			#print(name.replace(args.indir[0],args.outdir[0]))
			os.mkdir(os.path.join(root, name).replace(args.indir[0],args.outdir[0]))		
		for name in files:
			if (os.path.splitext(name)[1] == '.vp'):
				cnt=cnt+1
				infile_name=os.path.join(root, name)
				print("Processing "+infile_name)
				fdin=open(infile_name,"r")
				try:
					edata = parse_encrypted_file(fdin)
				except:
					print('Parse File Error')
					continue
				try:
					esession_key = edata.session_keys[keyname]
				except KeyError:
					print("No such key: %s" % keyname)
					print("Need any one of these:")
					for kn in edata.session_keys.keys():
						print("    %s" % kn)
					continue
					#sys.exit(1)
				print(args.keyfile[0])
				session_key = rsa_decrypt(args.keyfile[0], esession_key)
				session_key_pos=session_key.find(b'session_keyx')+13
				session_key_true=session_key[session_key_pos:session_key_pos+32]
				str_tmp=bytes.decode(session_key_true)
				session_key_bytes=bytes.fromhex(str_tmp)
				decrypted_data = aes128_cbc_decrypt(session_key_bytes, edata.encrypted_data)
				fdout=open(infile_name.replace(args.indir[0],args.outdir[0]),"wb")
				#fdout.write(bytes.decode(decrypted_data))
				fd


