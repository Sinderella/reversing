'''
load_pdb.py - PDB Loader plugin for Binary Ninja

Copyright (c) 2016 Josh Watson

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
'''

import os

import pdbparse
from pdbparse.pe import Sections
from pdbparse.omap import Omap

import binaryninja as bn

def load_pdb(bv):
    # PDB file is assumed to be named the same as the file opened and be
    # located in the same directory as the file.
    # TODO: Verifying the PDB matches the GUID in the binary is an
    # exercise left to the user.
    pdb_path = os.path.splitext(bv.file.filename)[0] + '.pdb'

    pdb = pdbparse.parse(pdb_path)

    try:
        sections = pdb.STREAM_SECT_HDR_ORIG.sections
    except AttributeError as e:
        sections = pdb.STREAM_SECT_HDR.sections

    gsyms = pdb.STREAM_GSYM

    for sym in gsyms.globals:
        try:
            if sym.symtype == 2:
                function_addr = (bv.start +
                                 sym.offset +
                                 sections[sym.segment-1].VirtualAddress)

                bv.add_function(function_addr, bv.platform)

                func = bv.get_function_at(function_addr, bv.platform)

                # Demangle and name the function
                if func:
                    demangled_name = bn.demangle_ms(bv.arch, sym.name)[1]

                    # sometimes the demangled names are a list?
                    if isinstance(demangled_name, list):
                        bn.log_info(demangled_name)
                        demangled_name = demangled_name[0]

                    func.name = demangled_name
        except AttributeError:
            pass

    bv.update_analysis_and_wait()

bn.PluginCommand.register(
    'Load PDB',
    'Load a PDB in the same directory as the binary.',
    load_pdb
)
