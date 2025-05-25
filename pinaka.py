import argparse
import hashlib
import math
import os
import random
import sys
import uuid
from collections import Counter

from Crypto.Cipher import AES, ARC4

banner = """
    ██▓███   ██▓ ███▄    █  ▄▄▄       ██ ▄█▀▄▄▄               Author: Ved Prakash Gupta (v3dSec)
   ▓██░  ██▒▓██▒ ██ ▀█   █ ▒████▄     ██▄█▒▒████▄             Github: https://github.com/v3dSec
   ▓██░ ██▓▒▒██▒▓██  ▀█ ██▒▒██  ▀█▄  ▓███▄░▒██  ▀█▄           Twitter: https://x.com/v3dSec
   ▒██▄█▓▒ ▒░██░▓██▒  ▐▌██▒░██▄▄▄▄██ ▓██ █▄░██▄▄▄▄██ 
   ▒██▒ ░  ░░██░▒██░   ▓██░ ▓█   ▓██▒▒██▒ █▄▓█   ▓██▒
   ▒▓▒░ ░  ░░▓  ░ ▒░   ▒ ▒  ▒▒   ▓▒█░▒ ▒▒ ▓▒▒▒   ▓▒█░
   ░▒ ░      ▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░▒ ▒░ ▒   ▒▒ ░
   ░░        ▒ ░   ░   ░ ░   ░   ▒   ░ ░░ ░  ░   ▒   
             ░           ░       ░  ░░  ░        ░  ░
"""


def nop_gen(nops):
    """Add nops to the shellcode"""
    nops = b"\x90" * nops
    return nops


def pad_gen(data, block_size):
    """Pad data with null bytes to make its length a multiple of block_size"""
    padded_data = data + (
        ((block_size - len(data) % block_size) % block_size) * b"\x00"
    )
    return padded_data


def encrypt_data(encryption_algorithm, data, key, word=False):
    """Encrypt data with the specified algorithm"""

    if word:
        data = data + b"\x00"

    if encryption_algorithm == "aes":
        key = hashlib.sha256(key).digest()
        iv = 16 * b"\x00"
        data = pad_gen(data, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data

    elif encryption_algorithm == "caesar":
        encrypted_data = bytes([(b + key) % 256 for b in data])
        return encrypted_data

    elif encryption_algorithm == "rc4":
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data

    elif encryption_algorithm == "xor":
        encrypted_data = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        return encrypted_data

    elif encryption_algorithm == "none":
        encrypted_data = data
        return encrypted_data


def key_gen(encryption_algorithm, custom_key=None):
    """Generate key according to the encryption algorithm"""

    valid_key_lengths = {
        "aes": 16,
        "caesar": 1,
        "rc4": 16,
        "xor": 16,
        "none": 0,
    }

    if custom_key:

        if encryption_algorithm == "caesar":

            if not custom_key.isnumeric():
                print("The caesar-cipher encryption key must be an integer value\n")
                sys.exit()

            else:
                key = int(custom_key)

        else:

            if len(custom_key) != valid_key_lengths[encryption_algorithm]:
                required_size = valid_key_lengths[encryption_algorithm]
                print(
                    f"{encryption_algorithm.upper()} requires a key of size {required_size} bytes\n"
                )
                sys.exit()

            elif custom_key.isnumeric():
                key = bytes.fromhex(custom_key)

            else:
                key = custom_key.encode()

    else:

        if encryption_algorithm == "caesar":
            key = random.randint(1, 99)

        else:
            key = os.urandom(valid_key_lengths[encryption_algorithm])

    return key


def encode_data(encoding_scheme, data, words_file=None, words=False):
    """Encode data with the specified encoding scheme"""

    if encoding_scheme == "binary":
        encoded_data = [bin(byte)[2:].zfill(8) for byte in data]
        return encoded_data

    elif encoding_scheme == "djb2":
        encoded_data = []
        for integer in data:
            byte_sequence = integer.to_bytes((integer.bit_length() + 7) // 8, "little")
            hash_value = 5381
            for c in byte_sequence:
                hash_value = ((hash_value << 5) + hash_value) + c
            encoded_data.append(hash_value & 0xFFFFFFFF)
        return encoded_data

    elif encoding_scheme == "epc":
        chunks = [data[i : i + 12] for i in range(0, len(data), 12)]
        padded_chunks = [chunk.ljust(12, b"\x00") for chunk in chunks]
        encoded_data = [
            f"{chunk.hex()[:6]}-{chunk.hex()[6:12]}-{chunk.hex()[12:]}"
            for chunk in padded_chunks
        ]
        return encoded_data

    elif encoding_scheme == "eui64":
        data += (8 - len(data) % 8) % 8 * b"\x00"
        encoded_data = [
            ":".join(f"{byte:02x}" for byte in data[i : i + 8])
            for i in range(0, len(data), 8)
        ]
        return encoded_data

    elif encoding_scheme == "ipv4":
        data += (4 - len(data) % 4) % 4 * b"\x00"
        encoded_data = [
            ".".join(map(str, data[i : i + 4])) for i in range(0, len(data), 4)
        ]
        return encoded_data

    elif encoding_scheme == "ipv6":
        data += (16 - len(data) % 16) % 16 * b"\x00"
        encoded_data = [
            ":".join(f"{data[i:i + 2].hex()}" for i in range(j, j + 16, 2))
            for j in range(0, len(data), 16)
        ]
        return encoded_data

    elif encoding_scheme == "jenkins":
        hashes = []
        for integer in data:
            byte_sequence = integer.to_bytes((integer.bit_length() + 7) // 8, "little")
            hash_value = 0
            for c in byte_sequence:
                hash_value += c
                hash_value += hash_value << 10
                hash_value ^= hash_value >> 6
            hash_value += hash_value << 3
            hash_value ^= hash_value >> 11
            hash_value += hash_value << 15
            hashes.append(hash_value & 0xFFFFFFFF)
        encoded_data = hashes
        return encoded_data

    elif encoding_scheme == "jigsaw":
        sc_len = len(data)
        raw_positions = list(range(sc_len))
        random.shuffle(raw_positions)
        encoded_data = [data[position] for position in raw_positions]
        return encoded_data, raw_positions

    elif encoding_scheme == "mac":
        data += (6 - len(data) % 6) % 6 * b"\x00"
        encoded_data = [
            ":".join(f"{byte:02x}" for byte in data[i : i + 6])
            for i in range(0, len(data), 6)
        ]
        return encoded_data

    elif encoding_scheme in ["md5", "sha1", "sha256", "sha512"]:

        hash_function = hashlib.md5
        if encoding_scheme == "sha1":
            hash_function = hashlib.sha1
        elif encoding_scheme == "sha256":
            hash_function = hashlib.sha256
        elif encoding_scheme == "sha512":
            hash_function = hashlib.sha512

        if words:
            encoded_data = []
            hash_digest = hash_function(data.encode("utf-8")).hexdigest()
            encoded_data.append(hash_digest)
            return encoded_data

        else:
            encoded_data = []
            data_length = str(len(data))
            for byte in data:
                decimal_representation = str(byte) + data_length
                hash_digest = hash_function(decimal_representation.encode()).hexdigest()
                encoded_data.append(hash_digest)
            return encoded_data

    elif encoding_scheme == "octal":
        encoded_data = [oct(byte)[2:].zfill(3) for byte in data]
        return encoded_data

    elif encoding_scheme == "uuid":
        data += (16 - len(data) % 16) % 16 * b"\x00"
        encoded_data = [
            str(uuid.UUID(bytes=data[i : i + 16])) for i in range(0, len(data), 16)
        ]
        return encoded_data

    elif encoding_scheme == "words":
        if not words_file:
            print("A words file must be provided for the 'words' encoding type\n")
            sys.exit()
        with open(words_file, "r") as f:
            words = f.read().splitlines()
        if len(words) >= 256:
            selected_words = random.sample(words, 256)
            encoded_data = [selected_words[b] for b in data]
            return encoded_data, selected_words
        else:
            print("A word file should contain 256 words\n")
            sys.exit()


def print_array(
    data, var_name, language, elements_count=17, is_digit=False, is_string=False
):
    """Print the output based on language and type"""

    line_prefix = "    "

    array_declaration = {
        "c": (
            f"\nint {var_name}[{len(data)}] = {{"
            if is_digit
            else (
                f"\nconst char* {var_name}[] = {{"
                if is_string
                else f"\nunsigned char {var_name}[{len(data)}] = {{"
            )
        ),
        "csharp": (
            f"\nint[] {var_name} = new int[{len(data)}] {{"
            if is_digit
            else (
                f"\nstring[] {var_name} = new string[{len(data)}] {{"
                if is_string
                else f"\nbyte[] {var_name} = new byte[{len(data)}] {{"
            )
        ),
        "fsharp": (
            f"\nlet {var_name} : int[] = [|"
            if is_digit
            else (
                f"\nlet {var_name} : string[] = [|"
                if is_string
                else f"\nlet {var_name} : byte [] = [|"
            )
        ),
        "go": (
            f"\n{var_name} := [{len(data)}]int{{"
            if is_digit
            else (
                f"\n{var_name} := [{len(data)}]string{{"
                if is_string
                else f"\n{var_name} := [{len(data)}]byte{{"
            )
        ),
        "nim": (
            f"\nvar {var_name}: array[{len(data)}, int] = ["
            if is_digit
            else (
                f"\nvar {var_name}: array[{len(data)}, string] = ["
                if is_string
                else f"\nvar {var_name}: array[{len(data)}, byte] = ["
            )
        ),
    }[language]

    print(array_declaration)

    if language == "c" or language == "csharp" or language == "go" or language == "nim":
        element_format = (
            "{b}"
            if is_digit and is_string or is_digit
            else '"{b}"' if is_string else "0x{b:02x}"
        )
        for i in range(0, len(data), elements_count):
            line = ", ".join(
                element_format.format(b=b) for b in data[i : i + elements_count]
            )
            print(
                f"{line_prefix}{line}" + ("," if i + elements_count < len(data) else "")
            )

    elif language == "fsharp":
        element_format = (
            "{b}"
            if is_digit and is_string or is_digit
            else '"{b}"' if is_string else "0x{b:02x}uy"
        )
        for i in range(0, len(data), elements_count):
            line = "; ".join(
                element_format.format(b=b) for b in data[i : i + elements_count]
            )
            print(
                f"{line_prefix}{line}" + (";" if i + elements_count < len(data) else "")
            )

    if language == "c" or language == "csharp":
        closing = "};"
        print(closing)

    elif language == "fsharp":
        closing = "|]"
        print(closing)

    elif language == "go":
        closing = "}"
        print(closing)

    elif language == "nim":
        closing = "]"
        print(closing)


def print_length(length, name, language):
    """Print the length of the data in the specified language"""

    len_str = (
        "let"
        if language in ["fsharp", "nim"]
        else ("var" if language == "go" else "int")
    )
    semicolon = ";" if language not in ["fsharp", "go"] else ""
    if language == "nim":
        print(f"\n{len_str} {name}: int = {length}")
    else:
        print(f"\n{len_str} {name} = {length}{semicolon}")


def shannon_entropy(file_path):
    """Calculate shannon entropy of a given file"""

    with open(file_path, "rb") as file:
        file_content = file.read()
        byte_counter = Counter(file_content)
        file_length = len(file_content)
        entropy = 0

        for byte, elements_count in byte_counter.items():
            frequency = elements_count / file_length
            entropy += frequency * math.log2(frequency)

        entropy = -entropy
        if entropy < 3:
            category = "low"
        elif 3 <= entropy < 5:
            category = "medium"
        elif 5 <= entropy < 6:
            category = "high"
        else:
            category = "very high"

        print(f"\nThe entropy of the file is: {entropy} ({category})\n")


class HelpFormat(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            (metavar,) = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                default = action.dest.upper()
                args_string = self._format_args(action, default)
                parts.extend(action.option_strings)
                parts[-1] += " {}".format(args_string)
            return ", ".join(parts)


def main():
    """Main function"""

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: HelpFormat(prog, max_help_position=40, width=145),
        description=(
            "This tool empowers you to combat AVs and EDRs by cloaking shellcode and strings in an unseen veil. It "
            "directs a covert dance of shellcode and strings, silently bypassing static detections, and raising the "
            "art of evasion to unprecedented heights"
        ),
    )

    parser.add_argument(
        "-s",
        "--shellcode_file",
        type=str,
        help="shellcode file that needs to be encrypted and encoded",
    )

    parser.add_argument(
        "-w",
        "--words_file",
        type=str,
        help="word file containing a list of words, each on a separate line, that needs to be encrypted "
        "and encoded",
    )

    parser.add_argument(
        "-d",
        "--dictionary_file",
        type=str,
        help="dictionary file to use for mapping during the shellcode-to-words encoding phase",
    )

    parser.add_argument(
        "-r",
        "--raw",
        type=str,
        help="specify -r or --raw file_name to output encrypted shellcode as a raw file",
    )

    parser.add_argument(
        "-n",
        "--nops",
        type=int,
        help="add nops to the shellcode",
    )

    parser.add_argument(
        "-a",
        "--algorithm",
        choices=[
            "aes",
            "caesar",
            "rc4",
            "xor",
        ],
        default="none",
        help="encryption algorithm for shellcode or stings encryption (default is 'none')",
    )

    parser.add_argument(
        "-k",
        "--key",
        type=str,
        help="key for shellcode encryption, if not provided, a random key will be generated",
    )

    parser.add_argument(
        "-e",
        "--encode",
        choices=[
            "binary",
            "djb2",
            "epc",
            "eui64",
            "ipv4",
            "ipv6",
            "jigsaw",
            "jenkins",
            "mac",
            "md5",
            "octal",
            "sha1",
            "sha256",
            "sha512",
            "uuid",
            "words",
        ],
        help="encoding option for shellcode encoding",
    )

    parser.add_argument(
        "-l",
        "--language",
        choices=[
            "c",
            "csharp",
            "fsharp",
            "go",
            "nim",
        ],
        default="c",
        help="language for output (default is 'c')",
    )

    parser.add_argument(
        "--entropy",
        type=str,
        help="calculate the Shannon Entropy",
    )

    args = parser.parse_args()

    key = key_gen(args.algorithm, args.key)

    if args.entropy:

        if os.path.exists(args.entropy):
            shannon_entropy(args.entropy)

        else:
            print(f"\n{args.entropy} not found !\n")

        sys.exit()

    if args.raw and args.shellcode_file:

        if os.path.exists(args.shellcode_file):

            with open(args.shellcode_file, "rb") as f:
                shellcode = f.read()

            if args.nops:
                nops = nop_gen(args.nops)
                shellcode = shellcode + nops

            encrypted_shellcode = encrypt_data(args.algorithm, shellcode, key)

            with open(args.raw, "wb") as f:
                f.write(encrypted_shellcode)

    elif args.words_file and not args.shellcode_file:

        if os.path.exists(args.words_file):

            with open(args.words_file, mode="r", encoding="utf-8") as f:
                words = f.readlines()

                for i, word in enumerate(words):

                    word = word.strip()
                    variable_name = f"word_{i + 1}"

                    if args.algorithm:

                        encrypted_word = encrypt_data(
                            args.algorithm, word.strip().encode(), key, True
                        )
                        variable_name = f"word_{i + 1}"
                        print_array(
                            encrypted_word,
                            variable_name,
                            args.language,
                            17,
                            False,
                            False,
                        )
                        print_length(
                            len(encrypted_word), variable_name + "_len", args.language
                        )

                    elif args.encode:
                        columns = {
                            "binary": 14,
                            "djb2": 14,
                            "epc": 6,
                            "eui64": 6,
                            "ipv4": 8,
                            "jigsaw": 17,
                            "jenkins": 13,
                            "mac": 8,
                            "ipv6": 4,
                            "md5": 4,
                            "uuid": 4,
                            "octal": 20,
                            "sha1": 4,
                            "sha256": 2,
                            "sha512": 1,
                            "words": 14,
                        }

                        if args.encode == "djb2" or args.encode == "jenkins":
                            encoded = encode_data(args.encode, word, None, True)

                            print_array(
                                encoded,
                                variable_name,
                                args.language,
                                columns[args.encode],
                                True,
                                False,
                            )

                        elif (
                            args.encode == "md5"
                            or args.encode == "sha1"
                            or args.encode == "sha256"
                            or args.encode == "sha512"
                        ):
                            encoded_shellcode = encode_data(
                                args.encode, word, False, True
                            )

                            print_array(
                                encoded_shellcode,
                                variable_name,
                                args.language,
                                columns[args.encode],
                                False,
                                True,
                            )

                        print_length(len(word), variable_name + "_len", args.language)

    elif args.shellcode_file:

        if os.path.exists(args.shellcode_file):

            with open(args.shellcode_file, "rb") as f:
                shellcode = f.read()

            if args.nops:
                nops = nop_gen(args.nops)
                shellcode = shellcode + nops

            encrypted_shellcode = encrypt_data(args.algorithm, shellcode, key)

            if args.encode:
                columns = {
                    "binary": 14,
                    "djb2": 14,
                    "epc": 6,
                    "eui64": 6,
                    "ipv4": 8,
                    "jigsaw": 17,
                    "jenkins": 13,
                    "mac": 8,
                    "ipv6": 4,
                    "md5": 4,
                    "uuid": 4,
                    "octal": 20,
                    "sha1": 4,
                    "sha256": 2,
                    "sha512": 1,
                    "words": 14,
                }

                if args.encode == "djb2" or args.encode == "jenkins":
                    encoded = encode_data(args.encode, encrypted_shellcode, None)

                    print_array(
                        encoded,
                        "encoded",
                        args.language,
                        columns[args.encode],
                        True,
                        False,
                    )

                elif args.encode == "jigsaw":
                    encoded, positions = encode_data(
                        args.encode, encrypted_shellcode, None
                    )

                    print_array(
                        encoded,
                        "encoded",
                        args.language,
                        columns[args.encode],
                        False,
                        False,
                    )

                    print_array(
                        positions,
                        "positions",
                        args.language,
                        columns[args.encode],
                        True,
                        False,
                    )

                elif args.encode == "words":
                    encoded, selected_words = encode_data(
                        args.encode, encrypted_shellcode, args.dictionary_file
                    )

                    print_array(
                        encoded,
                        "encoded",
                        args.language,
                        columns[args.encode],
                        False,
                        True,
                    )

                    print_array(
                        selected_words,
                        "selected_words",
                        args.language,
                        columns[args.encode],
                        False,
                        True,
                    )

                else:
                    encoded_shellcode = encode_data(args.encode, encrypted_shellcode)

                    print_array(
                        encoded_shellcode,
                        "encoded",
                        args.language,
                        columns[args.encode],
                        False,
                        True,
                    )

                print_length(len(encrypted_shellcode), "shellcode_len", args.language)

            elif args.raw:

                with open(args.raw, "wb") as f:
                    f.write(encrypted_shellcode)

                print_length(len(encrypted_shellcode), "shellcode_len", args.language)

            else:

                print_array(
                    encrypted_shellcode, "shellcode", args.language, 17, False, False
                )

                print_length(len(encrypted_shellcode), "shellcode_len", args.language)

        else:

            print(f"\n{args.shellcode_file} not found !\n")
            sys.exit()

    if args.algorithm == "caesar":
        print_length(key, "key", args.language)

    elif args.algorithm != "none":
        print_array(key, "key", args.language, 17, False, False)
        print_length(len(key), "key_len", args.language)

    if len(sys.argv) == 1:
        print(banner)
        parser.print_help()

    print()
    sys.exit()


if "-h" in sys.argv or "--help" in sys.argv:
    print(banner)

if __name__ == "__main__":
    main()
