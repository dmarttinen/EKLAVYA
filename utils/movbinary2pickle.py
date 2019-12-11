#!/usr/bin/env python

# https://anee.me/reversing-an-elf-from-the-ground-up-4fe1ec31db4a
# This works for mov files only

import re
import pickle
from elftools.elf.elffile import ELFFile
import os
import sys

# dirpath = '/home/bbaker/CSCI5271/Project/EKLAVYA/test_binary/'

for filename in os.listdir(sys.argv[1]):
# for filename in os.listdir(dirpath):
    filepath = sys.argv[1] + "/" + filename
#    filepath = dirpath + "/" + filename
    cmd = "readelf -wi " + filepath + " > elftemp"
    os.system(cmd)
    cmd = "objdump -d " + filepath + " > bintemp"
    os.system(cmd)

    # nfile = 'addr2line.txt'  # created with: readelf -wi clang-32-O0-binutils-addr2line > addr2line.txt
    # nfile = 'test.txt'

    nfile = 'elftemp'

    statinfo = os.stat(nfile)
    if statinfo.st_size:
        # open elf file
        f = open(nfile, 'r')

        # Create search patterns
        tag_pattern = re.compile('TAG')
        function_pattern = re.compile('DW_TAG_subprogram')
        name_pattern = re.compile('DW_AT_name')
        low_pattern = re.compile('DW_AT_low_pc')
        high_pattern = re.compile('DW_AT_high_pc')
        parameter_pattern = re.compile('DW_TAG_formal_parameter')

        # Create the counter variables
        line_cnt = 0
        func_cnt = 0
        flag = ''
        func_lst = []
        full_dict = {}
        ret_val = ''
        arg_lst = []
        bytes_lst = []
        low = 0
        high = 0
        bounds = ()
        arg_cnt = 0
        str_lst = []
        key_name = ''

        # Loop through each line
        for line in f.readlines():
            line_cnt = line_cnt + 1  # count lines read
            if tag_pattern.search(line):  # new tag header, now find type of section
                if function_pattern.search(line):  # is it a function?
                    flag = 'function'  # set function flag
                    if len(func_lst) > 0 and key_name != '':
                        key_name = func_lst[func_cnt - 1]
                        # Save everything so far
                        full_dict[key_name] = {'ret_type': ret_val,
                                               'args_type': arg_lst,
                                               'inst_bytes': bytes_lst,
                                               'boundaries': bounds,
                                               'num_args': arg_cnt,
                                               'inst_strings': str_lst}
                    # Reset function counters
                    low = 0
                    high = 0
                    bounds = ()
                    arg_cnt = 0
                    arg_lst = []
                    key_name = ''
                elif parameter_pattern.search(line):  # is it a parameter to a function?
                    flag = 'parameter'
                else:  # something else
                    flag = 'other'
            if flag == 'function' and low_pattern.search(line):  # find the lower bound of the addresses
                m = re.match(r"[ <0-9a-f>]+DW_AT_low_pc[ ]+: ([0-9xa-f]+)", line)
                low = int(m.group(1), 16)
            if flag == 'function' and high_pattern.search(line) and low:  # find the upper bound of the addresses
                m = re.match(r"[ <0-9a-f>]+DW_AT_high_pc[ ]+: ([0-9xa-f]+)", line)
                high = int(m.group(1), 16) + low
                bounds = (low, high)
            if flag == 'function' and name_pattern.search(line) and high:  # find the function name
                m = re.match(r"[ <0-9a-f>]+DW_AT_name[ ]+:[ (a-z,]+:[ 0-9xa-f)]+: ([\w@]+)", line)
                key_name = m.group(1)
                func_lst.append(key_name)
                func_cnt = func_cnt + 1
            if flag == 'parameter' and name_pattern.search(line):  # if it is a parameter with a name count it
                arg_cnt = arg_cnt + 1

        # Save the last items to the function table
        full_dict[key_name] = {'ret_type': ret_val,
                               'args_type': arg_lst,
                               'inst_bytes': bytes_lst,
                               'boundaries': bounds,
                               'num_args': arg_cnt,
                               'inst_strings': str_lst}

        # close file
        f.close()
    else:
        cmd = "objdump -g " + filepath + " > elftemp"
        os.system(cmd)
        # open elf file
        f = open(nfile, 'r')

        # Create the counter variables
        line_cnt = 0
        func_cnt = 0
        flag = ''
        func_lst = []
        full_dict = {}
        ret_val = ''
        arg_lst = []
        bytes_lst = []
        low = 0
        high = 0
        bounds = ()
        arg_cnt = 0
        str_lst = []
        key_name = ''

        for line in f.readlines():
            line_cnt = line_cnt + 1
            m = re.match(r"[a-z]+ ([\S]+) \(([\S ]*)\)", line)
            if m is not None:
                if len(m.groups()) == 2:
                    func_cnt = func_cnt + 1
                    key_name = m.group(1)
                    func_lst.append(key_name)
                    if m.group(2) == '':
                        arg_cnt = 0
                    else:
                        arg_cnt = len(m.group(2).split(','))
                    # Save everything so far
                    full_dict[key_name] = {'ret_type': ret_val,
                                           'args_type': arg_lst,
                                           'inst_bytes': bytes_lst,
                                           'boundaries': bounds,
                                           'num_args': arg_cnt,
                                           'inst_strings': str_lst}

    # loop though all the functions and pull binary data
    for func in full_dict.keys():
        # Create objdump command to show one function only
        cmd = 'objdump -M intel -d ' + filepath + "| sed '/<" + func + ">:/,/^$/!d' > bintemp"
        os.system(cmd)

        nfile = 'bintemp'
        f = open(nfile, 'r')
        bin_lst = []
        for line in f.readlines():  # Loop through all lines of the file
            m = re.match(r"^ [0-9a-f]+:\t([a-f0-9 ]+)", line)
            if m is not None:
                vals = m.group(1)  # Pull binary data
                vals = vals.split()
                new = []
                for i in vals:
                    new.append(int(i, 16))  # Save as dec list
                if new == [0]:
                    bin_lst[len(bin_lst) - 1].append(0)  # If single 0 value add it to the previous entry
                else:
                    bin_lst.append(new)  # add to bin_lst
                if new == [195]:  # Break if return value
                    break

        # close the file
        f.close()
        full_dict[func]['inst_bytes'] = bin_lst  # update the inst_bytes value.

    with open(filepath, 'rb') as f:
        elffile = ELFFile(f)
        # find text_addr
        for section in elffile.iter_sections():
            if section.name == ".text":
                text_addr = hex(section['sh_addr'])
        # find binary_filename
        binary_filename = filename.split('/')[-1]
        # find arch
        if elffile.has_dwarf_info():
            dfile = elffile.get_dwarf_info()
            if elffile.get_machine_arch() == 'x86':
                arch = 'i386'
            else:
                arch = 'amd64'
        # find functions
        # find structures
        # find binRowBytes
        # find function_calls

    f.close()

    pickleme = {'functions': full_dict,
                'binary_filename': binary_filename,
                'arch': arch,
                'extern_functions': {},
                'text_addr': text_addr,
                'function_calls': {},
                'structures': {},
                'bin_raw_bytes': ""}

    fname = binary_filename + '.pkl'

    pickle.dump(pickleme, open(fname, "wb"))
