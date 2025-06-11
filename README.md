# ImgPayload

**ImgPayload** is a Python-based shellcode injector that embeds raw payloads into image files using multiple stealth techniques: EOF markers, EXIF metadata, and LSB steganography. It's a flexible tool for red team operators, malware developers, and researchers focused on payload concealment and loader development.

🛠️ Inspired and originally based on [imgect by 0xZDH](https://github.com/0xZDH/imgect/), this version expands its capabilities significantly with modern injection methods and automation.

---

## ✨ Features

- ✅ **BMP/GIF Injection** via EOF markers (`/////` + `;`)
- ✅ **EXIF Injection**: stores shellcode in JPEG metadata (`UserComment`)
- ✅ **LSB Injection**: hides shellcode bit-by-bit in RGB channels
- ✅ **XOR Encoding**: optional obfuscation with customizable or random keys
- ✅ **Offset Detection**: output includes C++-ready `shellcodeStart` index
- ✅ **Hexdump Debug Mode**
- ✅ **No image corruption** — all output files remain valid and viewable

---

## 📦 Installation

```bash
pip install pillow piexif
````

---

## 🚀 Usage Examples

### Inject shellcode into a generated BMP image:

```bash
python3 imgect.py --bmp -f payload.bin -o bmp_payload
```

### Inject into a real existing image (EOF method):

```bash
python3 imgect.py --eof -f payload.bin -i input.gif -o final.gif
```

### EXIF metadata injection into JPEG:

```bash
python3 imgect.py --exif -f payload.bin -i photo.jpg -o img_exif.jpg
```

### Steganography with LSB (Least Significant Bit) in PNG:

```bash
python3 imgect.py --lsb -f payload.bin -i cover.png -o steg_img.png
```

### XOR encode shellcode before injection:

```bash
python3 imgect.py --gif -f payload.bin --encode -k SUPERSECRET -o encoded.gif
```

---

## 📌 Output Sample

After injection, you’ll get something like:

```
[=== Injection Summary ===]
[+] Technique: GIF
[+] Output File: encoded.gif
[+] Shellcode Size: 122 bytes
[+] XOR key (base64): U1VQRVJTRUNSRVQ=
[>] Use this offset in your C++ loader:
    const size_t shellcodeStart = 36;
```

Use the provided `shellcodeStart` offset in your custom runner:

```cpp
const std::string imagePath = "C:\\Temp\\encoded.gif";
const size_t shellcodeStart = 36;
```

---

## 💡 Shellcode Extraction

Extraction methods depend on the injection technique:

* **EOF / BMP / GIF**: Look for `/////` marker, read until `;`
* **EXIF**: Parse `UserComment` with `piexif`, base64-decode and XOR-decode if needed
* **LSB**: Extract 3 LSBs from each pixel (RGB), recombine to restore the payload

---

## 🧠 Credits

* Original concept and core implementation by **[@0xZDH](https://github.com/0xZDH)** in [imgect](https://github.com/0xZDH/imgect/)
* This fork, **ImgPayload**, adds:

  * Multi-technique injection (`--exif`, `--lsb`)
  * Automated shellcode offset indexing
  * XOR + base64 encoding support
  * Enhanced CLI usability and debug output
  * Extraction documentation and C++ compatibility

---

## 📜 License

MIT License — Use responsibly.

```
