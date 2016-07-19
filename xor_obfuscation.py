import argparse
import random
import string
import os
import subprocess
from tempfile import mkstemp
 
def main():
	#argparse values
	parser = argparse.ArgumentParser(description='Password based XOR obfuscator.')
	parser.add_argument("-i","--input-file", help="Input file to be XOR'd", type=str, dest="input_file")
	parser.add_argument("-p","--password", help="Password used to obfuscate input_file. Password provided with -p takes priority over -c usage", type=str, default="", dest="password")
	parser.add_argument("-o","--output-file", help="Output file to be written after input_file is XOR'd with password", type=str, default="out.file", dest="output_file")
	parser.add_argument("-v","--verbose", help="Display all information while running", action="store_true")
	parser.add_argument("-c","--create-password", help="Create random password for XOR obfuscation", type=int, default=-1, dest="ran_pass_len")
	parser.add_argument("-r","--run", help="Run the executable after decrypting. Note: XOR is a symmetric operation so it cannot determine if this is an encryption or decryption process. This will attempt to run the result of the XOR operation. This could lead to undesirable results and the author takes no blame for anything that happens as a result of using this command.", action="store_true")
	args = parser.parse_args()

	#conditions to check before running program
	if args.input_file=="":
		print "No input file, please see -h options."
		quit(1)
	if args.password=="":
		if args.ran_pass_len > 0:
			print "No password provided, creating random password of length "+str(args.ran_pass_len)+"\n"
			args.password = ''.join(random.choice(string.ascii_uppercase+string.ascii_lowercase+string.digits) for _ in range(args.ran_pass_len)) #special thanks to Ignacio Vazquez-Abrams on stackoverflow
			print "Random password: "+args.password+"\n"
		else:
			print "No password provided, continuing with default 'password'."
			args.password = "password"
	if args.output_file=="":
		print "No output file specified. Using default.\n"

	#actual main function
	i=0
	password_len = len(args.password)
	if args.verbose:
		print "The length of the password is "+str(password_len)+"\n"
	f = open(args.input_file, "rb")#open input file
	if args.verbose:
		print "The input file has been opened.\n"
	f2 = open(args.output_file, "wb")#open output file
	if args.verbose:
		print "The output file has been opened.\n"
	try:
		j=1
		code = ""
		fd = None
		path = ""
		byte = f.read(1)#read first byte
		if args.verbose:
			print "Bytes are being read...\n"
		if args.run:
			fd, path = mkstemp()
			if args.verbose:
				print "Creating temp file for execution...\n"
				print "Tempfile is located at: "+str(path)+"\n"
		while byte != "": #read bytes until there are none left
			pass_byte = args.password[i:i+1]#take one byte from password
			new_byte = chr(ord(byte) ^ ord(pass_byte)) #XOR YAY
			if args.run:
				code +=new_byte
			else:
				f2.write(new_byte)#write to output file
			if args.verbose:
				print str(j)+" bytes have been written.\n"
			#loop parameter updates			
			i = (i+1) % password_len
			byte = f.read(1)
			j=j+1 #j is used to measure how many bytes have been written
	finally:
		if args.run:
			f = os.fdopen(fd,"w")
			f.write(code)
			os.chmod(path,0700)
			f.close()
			if args.verbose:
				print "Finished writing and modifying temp file for execution\n"
			try:
				result = subprocess.call(path)
				if args.verbose:
					print "Result of execution: "+str(result)+"\n"
			finally:
				os.remove(path)
				if args.verbose:
					print "Removed temporary file!\n"
		if args.verbose:
			print "All done!"
		f.close()
		f2.close()

if __name__=="__main__":
	main()
			
