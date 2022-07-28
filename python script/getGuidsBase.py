#!/usr/bin/env python

import sys
import os
import argparse
import mmap
import re
import itertools
import uuid
import fnmatch
import binascii
import json
import shutil
import subprocess
import pathlib
import time
import hashlib
import pefile
from os import walk

from uefi_firmware.uefi import *
from uefi_firmware.utils import *
from uefi_firmware.flash import FlashDescriptor
from uefi_firmware.me import MeContainer
from uefi_firmware.pfs import PFSFile
from uefi_firmware.generator import uefi as uefi_generator
from uefi_firmware.misc import checker


def flatten_objects(root):
    objects = [root]
    if hasattr(root, 'objects'):
        for object in [_f for _f in root.objects if _f]:
            objects.extend(flatten_objects(object))
    return objects


def brute_search_volumes(data, byte_align=16, limit=None):
    fvh_magic_re = re.compile(b'_FVH')
    matches = fvh_magic_re.finditer(data, 32)
    return [match.start(0) for match in matches]


def iter_volumes(image):
    for fvh_offset in (m.start(0) for m in re.finditer(b'_FVH', image)):
        try:
            addr = fvh_offset - 40
            volume = FirmwareVolume(image[addr:])
            if volume.valid_header:
                volume.process()
                yield addr, volume
        except Exception as e:
            print("[-] Caught error while parsing FV at %#x: %s" % \
                  (fvh_offset - 40, e))


def get_module_name(objects, module):
    try:
        ui = objects[objects.index(module) + 1]
        if ui.attrs.get('type_name') == 'User interface name':
            return ui.label
    except IndexError:
        pass
    return ''


def get_module_guid(objects, module):
    module_idx = objects.index(module)
    for i, obj in enumerate(objects[module_idx::-1]):
        if isinstance(obj, FirmwareFile):
            return uuid.UUID(bytes_le=obj.guid)
    return uuid.UUID(int=0)


def find_modules(objects):
    for obj in objects:
        type = getattr(obj, 'attrs', {}).get('type_name')
        if type != 'PE32 image':
            continue
        yield obj

def find_module_name(guid, whitelist):
    keys = list(whitelist.keys())
    for x in keys:
        if str(whitelist[x].get('guid')) == str(guid).upper():
            return whitelist[x].get('name')
    return None

def main():

    parser = argparse.ArgumentParser(
        description="Extract, import to Ghidra and analyze UEFI firmware")
    parser.add_argument('-e', '--extract', default=None,
                        help="EFI image file")
    parser.add_argument('-sd', '--smramdump', default=None,
                        help="SMRam dump file")
    parser.add_argument('-o', '--outdir', default='temp',
                    help="Extract modules to the given directory")
    parser.add_argument('-wl', '--efi_whitelist', default=None, 
                        help='Name of json file with efi-whitelist')
    args = parser.parse_args()

    if args.extract != None:
        if os.path.exists(args.outdir):
            print("Out dir is exists")
            return
        else:
            os.mkdir(args.outdir, 0o700)

        try:
            with open(args.extract, 'r+b') as fd:
                image = mmap.mmap(fd.fileno(), 0)
        except IOError as e:
            print("[-] %s" % e)
            return -1
        if args.efi_whitelist != None:
            try:
                with open(args.efi_whitelist) as f:
                    whitelist = json.load(f)
            except IOError as e:
                print("[-] %s" % e)
                return -1

        print("[+] Working on %s" % os.path.abspath(args.extract))

        volumes = list(iter_volumes(image))
        if not volumes:
            print("[-] Not an EFI image (no volumes found).")
            return -1


        for addr, volume in volumes:
            print("[*] Found firmware volume @ %#x" % addr)
            objects = flatten_objects(volume)
            for module in find_modules(objects):
                moduleType = getattr(module, 'attrs', {}).get('type_name')
                module_idx = objects.index(module)
                path = getattr(objects[module_idx-2], 'attrs', {}).get('type_name')   
                guid = get_module_guid(objects, module)
                name = ''
                if name == '' and args.efi_whitelist != None:
                    name = find_module_name(guid, whitelist)
                print("[+]\t{%s} %s" % (guid, green(name) if sys.stdout.isatty() else name))

                if path == None:
                    path = 'None'

                path = path.replace("/", " ")

                if not os.path.exists(args.outdir + "/" + path):
                    os.mkdir(args.outdir + "/" + path, 0o700)

                if args.outdir:
                    filename = '%s_%s.efi' % (guid, name)
                    with open(os.path.join(args.outdir + "/" + path, filename), 'wb') as fd:
                        fd.write(module.content)

        print("[+] Extract done!")


    hashs = {}
    
    for dirname, dirnames, filenames in os.walk(args.outdir):
        # print path to all filenames.
        for filename in filenames:
            print(os.path.join(dirname, filename))
            pe = pefile.PE(dirname + '/' + filename)
            entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            f = open(os.path.join(dirname, filename), 'rb')
            f.seek(f.seek(pe.OPTIONAL_HEADER.AddressOfEntryPoint-(pe.sections[0].VirtualAddress-len(pe.header))))
            sha512 = hashlib.sha512()
            sha512.update(f.read(200))
            hashs.update({filename : sha512.hexdigest()})

    name = args.smramdump.split(".")   
    
    del name[-1]
    name = '.'.join(name) + ".json"


    with open(name, 'w') as convert_file:
        convert_file.write(json.dumps(hashs))
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
