#!/usr/bin/python2
# Copyright (C) 2015 Richard Hughes <richard@hughsie.com>
# Licensed under the GNU General Public License Version 2

import struct
import fnmatch

class CabFile(object):
    """An object representing a file in a Cab archive """
    def __init__(self):
        self.filename = None
        self.data = None
    def __str__(self):
        return self.filename
    def __repr__(self):
        return self.__str__()

class CabArchive(object):
    """An object representing a Microsoft Cab archive """

    def __init__(self):
        """ Set defaults """
        self.files = []
        self._buf_file = None
        self._buf_data = bytearray()
        self._nr_blocks = 0
        self._off_cfdata = 0

    def _parse_cffile(self, offset):
        """ Parse a CFFILE entry """
        fmt = 'I'       # uncompressed size
        fmt += 'I'      # uncompressed offset of this file in the folder
        fmt += 'H'      # index into the CFFOLDER area
        fmt += 'H'      # date
        fmt += 'H'      # time
        fmt += 'H'      # attribs
        fmt += '255s'   # filename
        vals = struct.unpack_from(fmt, self._buf_file, offset)
        filename = vals[6].split(b'\x00')[0].decode('utf-8')

        # add file
        f = CabFile()
        f.filename = filename
        f.data = self._buf_data[vals[1]:vals[1] + vals[0]]
        if len(f.data) != vals[0]:
            raise RuntimeError('Corruption inside archive')
        self.files.append(f)

        # return offset to next entry
        return 16 + len(filename) + 1

    def _parse_cffolder(self, offset):
        """ Parse a CFFOLDER entry """
        fmt = 'I'       # offset to CFDATA
        fmt += 'H'      # number of CFDATA blocks
        fmt += 'H'      # compression type
        vals = struct.unpack_from(fmt, self._buf_file, offset)

        # the start of CFDATA
        self._off_cfdata = vals[0]

        # no data blocks?
        self._nr_blocks = vals[1]
        if self._nr_blocks == 0:
            raise TypeError('No CFDATA blocks')

        # no compression is supported
        if vals[2] != 0:
            raise RuntimeError('Compressed cab files are not supported')

    def _parse_cfdata(self, offset):
        """ Parse a CFDATA entry """
        fmt = 'xxxx'    # checksum
        fmt += 'H'      # compressed bytes
        fmt += 'H'      # uncompressed bytes
        vals = struct.unpack_from(fmt, self._buf_file, offset)
        if vals[0] != vals[1]:
            raise RuntimeError('Mismatched data %i != %i' % (vals[0], vals[1]))
        hdr_sz = struct.calcsize(fmt)
        newbuf = self._buf_file[offset + hdr_sz:offset+vals[1] + hdr_sz]
        assert len(newbuf) == vals[1]
        self._buf_data += newbuf
        #print('block of %i' % vals[1])
        return vals[1] + hdr_sz

    def parse(self, buf):
        """ Parse .cab data """

        # slurp the whole buffer at once
        self._buf_file = buf

        # read the file header
        fmt = '<4s'     # signature
        fmt += 'xxxx'   # reserved1
        fmt += 'I'      # size
        fmt += 'xxxx'   # reserved2
        fmt += 'I'      # offset to CFFILE
        fmt += 'xxxx'   # reserved3
        fmt += 'BB'     # version minor, major
        fmt += 'H'      # no of CFFOLDERs
        fmt += 'H'      # no of CFFILEs
        fmt += 'H'      # flags
        fmt += 'H'      # setID
        fmt += 'H'      # cnt of cabs in set
#        fmt += 'H'      # reserved cab size
#        fmt += 'B'      # reserved folder size
#        fmt += 'B'      # reserved block size
#        fmt += 'B'      # per-cabinet reserved area
        vals = struct.unpack_from(fmt, self._buf_file, 0)

        # check magic bytes
        if vals[0] != b'MSCF':
            raise RuntimeError('Data is not application/vnd.ms-cab-compressed')

        # check size matches
        if vals[1] != len(self._buf_file):
            raise RuntimeError('Cab file internal size does not match data')

        # check version
        if vals[4] != 1  or vals[3] != 3:
            raise RuntimeError('Version %i.%i not supported' % (vals[4], vals[3]))

        # only one folder supported
        if vals[5] != 1:
            raise RuntimeError('Only one folder supported')

        # chained cabs not supported
        if vals[9] != 0:
            raise RuntimeError('Chained cab file not supported')

        # verify we actually have data
        nr_files = vals[6]
        if nr_files == 0:
            raise RuntimeError('The cab file is empty')

        # verify we got complete data
        off_cffile = vals[2]
        if off_cffile > len(self._buf_file):
            raise RuntimeError('Cab file corrupt')

        # chained cabs not supported
        if vals[7] != 0:
            raise RuntimeError('Expected header flags to be cleared')

        # parse CFFOLDER
        self._parse_cffolder(struct.calcsize(fmt))

        # parse CDATA
        offset = self._off_cfdata
        for i in range(0, self._nr_blocks):
            offset += self._parse_cfdata(offset)

        # parse CFFILEs
        for i in range(0, nr_files):
            off_cffile += self._parse_cffile(off_cffile)

    def parse_file(self, filename):
        """ Parse a .cab file """
        self.parse(open(filename, 'rb').read())

    def find_file(self, glob):
        """ Gets a file from the archive using a glob """
        for cf in self.files:
            if fnmatch.fnmatch(cf.filename, glob):
                return cf
        return None

def main():

    fn = '77454ea4ab0097c39cd948a469fe0fda7c86bdef-firmware-x28-parkcity.cab'

    cab = CabArchive()
    cab.parse_file(fn)
    print (cab.files)

    for cf in cab.files:
        if len(cf.data) < 10000:
            print (cf.data)
        if cf.filename != 'firmware.metainfo.xml':
            continue

        from appstream import Component
        md = Component()
        md.parse(str(cf.data))
        print ("GUID:    %s" % md.guid)
        print ("Version: %s" % md.version)

if __name__ == "__main__":
    main()
