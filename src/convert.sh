#!/bin/bash

ffmpeg -f u8 -ar 8000 -i $1 -acodec libvorbis $1.ogg
