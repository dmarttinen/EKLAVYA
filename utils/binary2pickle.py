#!/usr/bin/env python

# https://anee.me/reversing-an-elf-from-the-ground-up-4fe1ec31db4a

import pickle
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import binascii
import numpy as np

fname = 'binary/x86/clang-32-O0-binutils-addr2line'
pname = 'pickles/x86/clang-32-O0-binutils-addr2line.pkl'


def section_info_highlevel(stream):
    print 'High level API...'
    elffile = ELFFile(stream)

    # Just use the public methods of ELFFile to get what we need
    # Note that section names are strings.
    print '  %s sections' % elffile.num_sections()
    section = elffile.get_section_by_name('.symtab')

    if not section:
        print '  No symbol table found. Perhaps this ELF has been stripped?'
        return

    testit = []
    for i in range(section.num_symbols()):
        testit.append(section.get_symbol(i).name)

    # can find names of functions
    x = np.array(testit)
    testit = np.unique(x)
    nlist = []
    elist = []
    for i in testit:
        if '@' not in i:
            nlist.append(i)  # function names
        else:
            elist.append(i)  # extern_functions

    # A section type is in its header, but the name was decoded and placed in
    # a public attribute.
    print '  Section name: %s, type: %s' %(
        section.name, section['sh_type'])

    # But there's more... If this section is a symbol table section (which is
    # the case in the sample ELF file that comes with the examples), we can
    # get some more information about it.
    if isinstance(section, SymbolTableSection):
        num_symbols = section.num_symbols()
        print "  It's a symbol section with %s symbols" % num_symbols
        print "  The name of the last symbol in the section is: %s" % (
            section.get_symbol(num_symbols - 1).name)


with open(pname, 'rb') as f:
    data = pickle.load(f)

f.close()

with open(fname, 'rb') as f:
    elffile = ELFFile(f)
    # find text_addr
    for section in elffile.iter_sections():
        if section.name == ".text":
            text_addr = hex(section['sh_addr'])
    # find binary_filename
    binary_filename = fname.split('/')[-1]
    # find arch
    if elffile.has_dwarf_info():
        dfile = elffile.get_dwarf_info()
        if elffile.get_machine_arch() == 'x86':
            arch = 'i386'
        else:
            arch = 'amd64'
    # find functions
    f.seek(0)
    section_info_highlevel(f)
    f.seek(0)
    # find structures
    # find binRowBytes
    binRawBytes = f.read()
    binRowBytes = binascii.hexlify(f.read())
    # find function_calls


f.close()

# checks
print "is text_addr the same?"
print data['text_addr'] == text_addr

print "is arch the same?"
print data['arch'] == arch

print "is binary_filename the same?"
print data['binary_filename'] == binary_filename

