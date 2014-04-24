#!/usr/bin/env python
# W.J. van der Laan, 2011
# Make spinning animation from a .png
# Requires imagemagick 6.7+
from __future__ import division
from os import path
from PIL import Image
from subprocess import Popen

# The source icon is copyright (c) 2014 John Doering <ghostlander@phoenixcoin.org>
# under the terms of the MIT Licence (see ../LICENCE)
SRC='images/reload.png'
TMPDIR='../src/qt/res/movies/'
TMPNAME='spinner-%02i.png'
NUMFRAMES=25
CLOCKWISE=True
FLIP=False
DSIZE=(16,16)

im_src = Image.open(SRC)

if FLIP:
    im_src = im_src.transpose(Image.FLIP_LEFT_RIGHT)

def frame_to_filename(frame):
    return path.join(TMPDIR, TMPNAME % frame)

frame_files = []
for frame in xrange(NUMFRAMES):
    rotation = (frame + 0.5) / NUMFRAMES * 360.0
    if CLOCKWISE:
        rotation = -rotation
    im_new = im_src.rotate(rotation, Image.BICUBIC)
    im_new.thumbnail(DSIZE, Image.ANTIALIAS)
    outfile = frame_to_filename(frame)
    im_new.save(outfile, 'png')
    frame_files.append(outfile)
