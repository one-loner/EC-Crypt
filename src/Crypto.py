import binascii
import pyelliptic
from pyelliptic import *
import base58
import FormatKeys




# ------------------------ P-256 CURVE PARAMETERS ------------------------ #
# Can be verified here: http://www.secg.org/sec1-v2.pdf
P = int('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16)
A = int('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC', 16)
B = int('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16)
#
# ------------------------------------------------------------------------ #




def run_test():
    n = OpenSSL.rand(64)
    m = OpenSSL.rand(64)
    if n == m:
        return False
    else:
        return True

def byte_to_int(n):
    return int((binascii.hexlify(n)), 16)


def int_to_byte(n, width = 32):
    return binascii.unhexlify(hex(n)[2:-1].zfill((width * 2)))


def point_compress(x, y):
    sign = chr(2 + (byte_to_int(y) % 2))
    return sign + x


def point_decompress(sb, xb):
    x = byte_to_int(xb)
    beta = pow(x * x * x + A * x + B, (P + 1) / 4, P)
    y = (P - beta) if ((beta + byte_to_int(sb)) % 2) else beta
    return xb, int_to_byte(y)


def generate_new_key():
    newkey = pyelliptic.ECC(curve='prime256v1')
    priv, pubX, pubY = newkey._generate()
    return priv, pubX + pubY 


def generate_secret():
    return OpenSSL.rand(64)


def ecdh_secret(alice_priv, alice_pub, bob_pub):
    alice_key = pyelliptic.ECC(curve='prime256v1', pubkey=alice_pub, privkey=alice_priv)
    bob_key = pyelliptic.ECC(pubkey=bob_pub, curve='prime256v1')
    return alice_key.get_ecdh_key(bob_key.get_pubkey())


def encrypt_text(ss, txt):
    key = ss[0:32]
    iv = ss[32:48]
    ctx = pyelliptic.Cipher(key, iv, 1, ciphername='aes-256-cbc')
    ciphermsg = ctx.update(txt)
    ciphermsg += ctx.final()
    return ciphermsg


def decrypt_text(ss, txt):
    key = ss[0:32]
    iv = ss[32:48]
    ctx = pyelliptic.Cipher(key, iv, 0, ciphername='aes-256-cbc')
    ciphermsg = ctx.update(txt)
    ciphermsg += ctx.final()
    return ciphermsg


def encrypt_attach(ss, attach):
    key = ss[0:32]
    iv = ss[48:64]
    ctx = pyelliptic.Cipher(key, iv, 1, ciphername='aes-256-cbc')
    ciphermsg = ctx.update(attach)
    ciphermsg += ctx.final()
    return ciphermsg


def decrypt_attach(ss, attach):
    key = ss[0:32]
    iv = ss[48:64]
    ctx = pyelliptic.Cipher(key, iv, 0, ciphername='aes-256-cbc')
    ciphermsg = ctx.update(attach)
    ciphermsg += ctx.final()
    return ciphermsg


def make_sig(priv_bin, pub_bin, data):
    usr_key = pyelliptic.ECC(curve='prime256v1', pubkey=pub_bin, privkey=priv_bin)
    return usr_key.sign(data)


def verify_sig(pubkey, sig, data):
    if pyelliptic.ECC(pubkey=pubkey).verify(sig, data) is True:
        return True
    elif pyelliptic.ECC(pubkey=pubkey).verify(sig, data) is False:
        return False


def check_pubkey(pubkey):
    try:
        libkey = FormatKeys.fmt_pub(pubkey, 'readable2lib')
        try:
            elliptic_instance = pyelliptic.ECC()
            elliptic_instance._decode_pubkey(libkey)
            return True
        except:
            return False
    except ValueError:
        return False

