#!/usr/bin/env python
import argparse
import serial
import sys
import time

# define serial connection
ser = serial.Serial(
	port='/dev/ttyACM0',
	baudrate=9600,
	parity=serial.PARITY_NONE,
	stopbits=serial.STOPBITS_ONE,
	bytesize=serial.EIGHTBITS
)

# sends a set of instructions to the connected device
# @param instruction_set : an array of commands to send to the PLC in hex
# @param printstring     : runtime message for the user
def send_instruction(instruction_set, printstring):
	# clear out any leftover data
	if ser.inWaiting() > 0:
		ser.flushInput()

	print "[*] sending %s instruction ..." % printstring

    # perform the write
	for instruction in instruction_set:
		ser.write(instruction)
		time.sleep(0.1)

		# handle printout for any read requests
		if "read" in printstring:
			cur_reg = instruction[-1:].encode('hex')
			response = ""
			while ser.inWaiting() > 0:
				response += "\\x%s" % ser.read().encode('hex')
			time.sleep(0.1)

			response = response.replace("\\x", "").strip()
			ascii_response = ""
			for letter in response.decode('hex'):
				charcode = ord(letter)
				if ((charcode < 123 and charcode > 64) or (charcode > 47 and charcode < 58)):
					ascii_response += letter
				else:
					ascii_response += "_"
			output_header = "\\x%s:\t" % cur_reg
			output_footer = "\t%s" % ascii_response

			print "%s%s%s" % (output_header, response, output_footer)
		elif "enumerate_tags" in printstring:
			process_enumerate_tags_response(ser)
		else:
			print "[*] instruction sent"

def read_response(serialPort):
	response = []
	while serialPort.inWaiting() > 0:
		response.append(ord(serialPort.read()))

	return response

def toString(byteArray):
	return ''.join(map(lambda x: chr(x), byteArray))

def decode_tag_response(response):
	assert (5 <= len(response)), "Incomplete response packet"
	assert ([0x56, 0xff, 0xff, 0x00] == response[0:4]), "Packet preamble missing"
	assert (response[4] == len(response)), "Packet length mismatch"

	tagNumber = response[8]
	tagName = toString(response[9:25])
	return (tagNumber, tagName)

def request_tag(serialPort, tagNumber):
	assert ((tagNumber > 0) and (tagNumber < 256)), "tagNumber is a 1 index, byte representation"
	request = [0x56, 0xFF, 0xFF, 0x00, 0x08, 0x0A, 0x00, tagNumber]
	serialPort.flushInput()
	serialPort.write(toString(request))
	time.sleep(0.1)

def process_enumerate_tags_response(serialPort):
	# change in style from rest of code to process serial using bytes
	response = read_response(serialPort)
	# sanity check response
	assert (5 <= len(response)), "Incomplete response packet"
	assert ([0x56, 0xff, 0xff, 0x00] == response[0:4]), "Packet preamble missing"
	assert (response[4] == len(response)), "Packet length mismatch"

	# last byte is the number of tags (TODO determine if multi byte and endian)
	tagCount = response[-1];

	for tagNumber in range(1, tagCount):
		request_tag(serialPort, tagNumber)
		response = read_response(serialPort)
		print decode_tag_response(response)


commands = {}
commands['press_play'] = ["\x56\xff\xff\x00\x07\xf1\x01"]
commands['press_pause'] =      ["\x56\xff\xff\x00\x07\xf1\x02"]
commands['press_reset'] =      ["\x56\xff\xff\x00\x07\xf1\x06"]
commands['step_into'] =        ["\x56\xff\xff\x00\x07\xf1\x03"]
commands['step_out'] =         ["\x56\xff\xff\x00\x07\xf1\x04"]
commands['step_over'] =        ["\x56\xff\xff\x00\x07\xf1\x05"]
commands['enter_debug'] =      ["\x56\xff\xff\x00\x07\xf0\x02"]
commands['exit_debug'] =       ["\x56\xff\xff\x00\x07\xf0\x01"]
commands['set_output_1_off'] = ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x01\x00\x00\x00"]
commands['set_output_2_off'] = ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x02\x00\x00\x00"]
commands['set_output_3_off'] = ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x04\x00\x00\x00"]
commands['set_output_4_off'] = ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x08\x00\x00\x00"]
commands['set_output_5_off'] = ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x10\x00\x00\x00"]
commands['set_output_6_off'] = ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x20\x00\x00\x00"]
commands['set_output_1_on'] =  ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x01\x00\x00\x01"]
commands['set_output_2_on'] =  ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x02\x00\x00\x01"]
commands['set_output_3_on'] =  ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x04\x00\x00\x01"]
commands['set_output_4_on'] =  ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x08\x00\x00\x01"]
commands['set_output_5_on'] =  ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x10\x00\x00\x01"]
commands['set_output_6_on'] =  ["\x56\xff\xff\x00\x15\x11\x01\x00\x01\x00\x00\x09\x01\x00\x00\x01\x00\x20\x00\x00\x01"]

# read instructions
commands['read_input_bits'] = [
	"\x56\xff\xff\x00\x08\x0a\x00\x01",
	"\x56\xff\xff\x00\x08\x0a\x00\x02",
	"\x56\xff\xff\x00\x08\x0a\x00\x03",
	"\x56\xff\xff\x00\x08\x0a\x00\x04",
	"\x56\xff\xff\x00\x08\x0a\x00\x05",
	"\x56\xff\xff\x00\x08\x0a\x00\x06"
	]

commands['read_output_bits'] = [
	"\x56\xff\xff\x00\x08\x0a\x00\x07",
	"\x56\xff\xff\x00\x08\x0a\x00\x08",
	"\x56\xff\xff\x00\x08\x0a\x00\x09",
	"\x56\xff\xff\x00\x08\x0a\x00\x0a",
	"\x56\xff\xff\x00\x08\x0a\x00\x0b",
	"\x56\xff\xff\x00\x08\x0a\x00\x0c"
	]

# this command receive a response informing number of enumerate_tags
# and then we need to query tag by tag
commands['enumerate_tags'] = ["\x56\xFF\xFF\x00\x06\xAC"]

def validateCommandFactory(commandList):
	def validateCommand(command):
		if (command in commandList):
			return command
		else:
			raise Exception('Unsupported command: ' + command)

	return validateCommand

def main():
	parser = argparse.ArgumentParser(description="Tool for interacting with Velocio Ace PLC")
	parser.add_argument("command", type=validateCommandFactory(commands), help="Command can be one of the following: " + str(commands.keys()))
	args = parser.parse_args()
	# initiate the connection
	ser.isOpen()
	send_instruction(commands[args.command], args.command)
	ser.close()

try:
	main()
except Exception as e:
	print "[!] ERROR"
	print "[!] MSG: %s" % e
	exit(1)
