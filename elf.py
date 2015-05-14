#!/usr/bin/python
import sys 

from elftools.elf.elffile import ELFFile

if __name__ == '__main__':
    
    if len(sys.argv) > 2 or len(sys.argv) == 1:
        print 'Usage: %s <file>' % sys.argv[0]
    
    with open(sys.argv[1], 'rb') as stream:
        elffile = ELFFile(stream)
        section = elffile.get_section_by_name(b'.text')
        print 'Size of shellcode: [ %s ]' % section['sh_size']
        raw = section.data().encode('hex')
        bytes = [ r'\x' + raw[i:i+2] for i in range(0, len(raw), 2) ]
        print 'Shellcode: %s' % ''.join(bytes)
