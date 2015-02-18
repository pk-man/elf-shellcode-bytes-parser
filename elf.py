#!/usr/bin/python
import sys

from elftools.elf.elffile import ELFFile

if __name__ == '__main__':
	with open(sys.argv[1], 'rb') as stream:
		elffile = ELFFile(stream)
		section = elffile.get_section_by_name(b'.text')
		print 'Size of shellcode: [ %s ]' % section['sh_size']
		raw = section.data().encode('hex')
		shellcode = ''
		bytes = [ raw[i:i+2] for i in range(0, len(raw), 2) ]
		for x in bytes:
			shellcode += r'\x' + x
		
		print 'Shellcode: %s' % shellcode
