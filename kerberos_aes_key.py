import argparse
import hashlib
from Crypto.Cipher import AES

class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog):
        super().__init__(prog, max_help_position=50)

AES256_CONSTANT = bytes.fromhex('6B65726265726F737B9B5B2B93132B935C9BDCDAD95C9899C4CAE4DEE6D6CAE4')
AES128_CONSTANT = bytes.fromhex('6B65726265726F737B9B5B2B93132B93')
IV = b'\x00' * 16

def encrypt_aes_cbc(key, data):
    return AES.new(key, AES.MODE_CBC, IV).encrypt(data)

def get_kerberos_aes_key(password, salt, iteration=4096):
    dk = hashlib.pbkdf2_hmac('sha1', password.encode(), salt.encode(), iteration, 32)
    aes256_key_part1 = encrypt_aes_cbc(dk, AES256_CONSTANT)
    aes256_key_part2 = encrypt_aes_cbc(dk, aes256_key_part1)
    aes256_key = aes256_key_part1[:16] + aes256_key_part2[:16]
    aes128_key = encrypt_aes_cbc(dk[:16], AES128_CONSTANT)
    return aes128_key.hex().upper(), aes256_key.hex().upper()

def main():
    parser = argparse.ArgumentParser(description='Generate Kerberos AES keys from username, password, and realm.', formatter_class=CustomHelpFormatter)
    parser.add_argument('-u', '--username', required=True, help='Username (case-sensitive)')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-r', '--realm', required=True, help='Kerberos realm')
    parser.add_argument('-i', '--iteration', type=int, default=4096, help='PBKDF2 iteration count (default: 4096)')
    args = parser.parse_args()
    salt = args.realm.upper() + args.username
    aes128_key, aes256_key = get_kerberos_aes_key(args.password, salt, args.iteration)
    print(f"[*] AES128 Key: {aes128_key}")
    print(f"[*] AES256 Key: {aes256_key}")

if __name__ == '__main__':
    main()