#!/usr/bin/python3
from pyzbar.pyzbar import decode
from PIL import Image

all_words=""
for i in range(0,69):
    all_words += decode(Image.open('qr/image-{}.png'.format(i)))[0].data.decode('utf-8')
    all_words += " "
print(all_words)
