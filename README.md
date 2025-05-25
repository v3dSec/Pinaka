# Pinaka - Shellcode & Strings Obfuscation Tool

**Pinaka** is a command-line tool designed for penetration testers and red team operators to obfuscate shellcode and strings for static signature based evasion. It supports a wide range of encryption and encoding methods to help bypass static detection mechanisms employed by antivirus (AV) and endpoint detection and response (EDR) systems.

> **Introduces a novel technique to bypass shellcode signature detection using shellcode byte hashing.**

> ⚠️ **Disclaimer**: This tool is intended for authorized security testing and research purposes only.

---

## 🔍 Overview

* Encrypt shellcode & strings using:
    * `AES`
    * `RC4`
    * `XOR`
    * `Caesar cipher`
* Encode shellcode in multiple formats including:
    * `Binary`, `Octal`, `IPv4`, `IPv6`, `MAC`, `UUID`
    * `MD5`, `SHA1`, `SHA256`, `SHA512`
    * `Jenkins`, `DJB2`, `EPC`, `EUI64`
    * `Jigsaw`, `Words` (custom dictionary-based)
* Generate output in various programming languages:
    * `C`, `C#`, `F#`, `Go`, and `Nim`
* Add NOP padding to shellcode
* Export obfuscated shellcode as raw binary files for seamless integration into custom loaders or post-exploitation tools
* Calculate Shannon entropy for statistical analysis

---

## ⚠️ Important Note on Decryptors & Decoders

Pinaka is **not designed to generate decryptor or decoder functions** for the obfuscated shellcode. This is intentional because if the shellcode itself remains undetected, the added decryptor or decoder routines might still trigger detection by security tools.

**It is recommended that users implement their own custom decryptors and decoders** tailored to their specific payloads and environments to minimize detection risk.

> The decryptor and decoder code provided in the **`examples/`** directory are intended **only as illustrative samples or inspiration**. Using these implementations without modification provides no real advantage and may increase the chance of detection.


## 🔐 Encryption vs. Encoding: Techniques & Applications

Encryption and encoding transform data into unreadable or disguised formats. If no encryption key is provided, Pinaka will generate one automatically. Encryption is applicable to both shellcode and strings, while encoding is applied only to shellcode.

---

### 🔒 Encryption Schemes

- **AES** – Strong symmetric encryption used in secure communications.
- **RC4** – RC4 is a fast stream cipher used for lightweight encryption.
- **XOR** – Lightweight bitwise encryption.
- **Caesar Cipher** – Substitution cipher that shifts byte values.

**📌 Applicable To:**

- Shellcode  
- Strings (e.g., API names like `VirtualAlloc`)

> Encrypting strings like Windows API calls helps evade detection via static signature matching. This technique is inspired by the **Sektor7 Malware Development Essentials** course and is useful for function call obfuscation.

---

### 🔁 Encoding Methods

Encoding transforms shellcode bytes into different formats, useful for disguising payloads as benign data.

#### Standard Encodings

- **Binary, Octal** – Convert bytes to base-numeric strings.
- **IPv4, IPv6, MAC** – Format shellcode as network identifiers.
- **UUID** – Encode shellcode as UUID strings.
- **EUI64, EPC** – Use hardware or RFID identifier formats.

**📌 Applicable To:**

- **Shellcode only** (Encoding is *not* applied to strings)

---

### 🔍 Novel Hash-Based Encoding Techniques

These novel hash-based encoding techniques were **introduced and implemented by myself (v3dSec), to enhance evasion capabilities.**

These are **non-reversible** encodings where each shellcode byte is individually hashed:

- **MD5, SHA1, SHA256, SHA512**
- **Jenkins, DJB2**

🔐 These hashes require **brute force (0–255)** per byte for decoding, with **shellcode length used as a salt** to make the hashes polymorphic. This makes decoding **resource-intensive** and may help **bypass sandbox environments** by causing timeouts due to CPU-heavy operations.

---

### 🧩 Custom Techniques: Jargon & Jigsaw

Inspired by research from **Mike Saunders**, these innovative methods enhance evasion:

- **Jargon** – Converts shellcode into a sequence of dictionary words, making it look like natural text.
- **Jigsaw** – Randomly shuffles shellcode bytes and maintains a mapping array for reassembly at runtime.

These techniques break static patterns and frustrate signature-based detection systems.

---

> 💡 **By combining encryption and encoding in layers, Pinaka enables creation of payloads that are highly evasive, modular, and adaptable to a variety of detection environments.**


## 🚀 Installation

### Prerequisites
- Make sure you have **Python 3** installed on your system.

**Clone the repository:**
   ```bash
   git clone https://github.com/v3dSec/pinaka.git
   cd pinaka
   pip install -r requirements.txt
```

## 🧪 Examples

1. Encrypt and Encode Shellcode

Encrypt shellcode with AES, encode as IPv4 addresses, and output in C:

```bash

python pinaka.py -s shellcode.bin -a aes -k "mysecretkey12345" -e ipv4 -l c
```

Encrypt shellcode with XOR (random key), encode as UUIDs, and output in C#:
```bash

python pinaka.py -s shellcode.bin -a xor -e uuid -l csharp
```

Encode shellcode directly to words format (no encryption) using a custom dictionary, and output in Go:
```bash

python pinaka.py -s shellcode.bin -e words -d my_custom_dictionary.txt -l go
```

Encrypt shellcode with RC4, add 10 NOPs, and output the raw encrypted shellcode to a file:
```bash

python pinaka.py -s shellcode.bin -a rc4 -n 10 -r encrypted_sc.bin
```

2. Encrypt and Encode Strings (Words)

Encrypt a list of words with Caesar cipher and output as a C array of strings:
```bash

python pinaka.py -w dictionary_file.txt -a caesar -k "3" -l c
```

Encrypt a list of words with AES (random key) and encode as SHA256 hashes, output in FSharp:
```bash

python pinaka.py -w dictionary_file.txt -a aes -e sha256 -l fsharp
```

3. Calculate Shannon Entropy

Calculate the entropy of an encrypted shellcode file:
```bash

python pinaka.py --entropy encrypted_shellcode.bin
```

4. Display Help Message

View all available options and their descriptions:
```bash

python pinaka.py --help
```

## 📚 Credits & References

This project builds on extensive research and contributions in the field of shellcode obfuscation. 

Special thanks to:

* Mike Saunders ([Twitter](https://twitter.com/hardwaterhacker))  for his insightful research and detailed blog series on shellcode obfuscation techniques. His work—particularly on methods such as Jargon and Jigsaw—has been instrumental in the development of this tool.
* Articles from Red Siege’s blog series on shellcode obfuscation techniques (sorted chronologically):
    * [Part 1 - Overview](https://redsiege.com/blog/2024/06/adventures-in-shellcode-obfuscation-part-1-overview/)
    * [Part 2 - Hail Caesar](https://redsiege.com/blog/2024/06/adventures-in-shellcode-obfuscation-part-2-hail-caesar/)
    * [Part 3 - Encryption](https://redsiege.com/blog/2024/07/adventures-in-shellcode-obfuscation-part-3-encryption/)
    * [Part 4 - RC4 with a Twist](https://redsiege.com/blog/2024/07/adventures-in-shellcode-obfuscation-part-4-rc4-with-a-twist/)
    * [Part 5 - Base64](https://redsiege.com/blog/2024/07/advenutures-in-shellcode-obfuscation-part-5-base64/)
    * [Part 6 - Two Array Method](https://redsiege.com/blog/2024/07/adventures-in-shellcode-obfuscation-part-6-two-array-method/)
    * [Part 7 - Flipping the Script](https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-7-flipping-the-script/)
    * [Part 8 - Shellcode as UUIDs](https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-8-shellcode-as-uuids/)
    * [Part 9 - Shellcode as IP addresses](https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-9-shellcode-as-ip-addresses/)
    * [Part 10 - Shellcode as MAC addresses](https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-10-shellcode-as-mac-addresses/)
    * [Part 11 - Jargon](https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-11-jargon/)
    * [Part 12 - Jigsaw](https://redsiege.com/blog/2024/09/adventures-in-shellcode-obfuscation-part-12-jigsaw/)

