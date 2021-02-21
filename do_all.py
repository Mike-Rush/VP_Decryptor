import sys,os
import argparse as AP
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
	for root, dirs, files in os.walk(args.indir[0], topdown=True):
		for name in dirs:
			#print(os.path.join(root, name).replace(args.indir[0],args.outdir[0]))
			#print(name.replace(args.indir[0],args.outdir[0]))
			os.mkdir(os.path.join(root, name).replace(args.indir[0],args.outdir[0]))		
		for name in files:
			if (os.path.splitext(name)[1] == '.vp'):
				print(os.path.join(root, name))

