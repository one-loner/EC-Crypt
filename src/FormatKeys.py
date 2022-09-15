import hashlib
import base64
import codecs
import base58
import Crypto
from Parsing import UnicodeConfigParser 




class ECCryptException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class Key:
    def __init__(self, key_id = None):
        if key_id is None: 
            self.raw_privkey, self.raw_pubkey = Crypto.generate_new_key()
            self.lib_privkey = format_privkey(self.raw_privkey, 'bin')
            self.lib_pubkey = fmt_pub(self.raw_pubkey, 'raw2lib')
            self.msg_pubkey = fmt_pub(self.raw_pubkey, 'raw2msg')
        elif not key_id is None:
            b58_priv, b58_pub = retrieve_masterkey(key_id)
            self.lib_privkey = base58.b58decode(b58_priv)
            self.lib_pubkey = fmt_pub(b58_pub, 'readable2lib')
            self.msg_pubkey = fmt_pub(b58_pub, 'readable2msg')


    def get_pub(self, fmt):
        if fmt is 'msg':
            return self.msg_pubkey
        elif fmt is 'lib':
            return self.lib_pubkey


    def get_priv(self, fmt):
        if fmt is 'raw':
            return self.raw_privkey
        elif fmt is 'lib':
            return self.lib_privkey




def format_privkey(privkey, return_form = 'bin'):
    if return_form is 'bin': 
        return '\x01\x9f\x00\x20' + privkey
    elif return_form is 'b58': 
        return base58.b58encode('\x01\x9f\x00\x20' + privkey)


def fmt_pub(pubkey, type, encoded=False):
    if type is 'lib2msg':
        x = pubkey[4:36]
        y = pubkey[38:70]
        return Crypto.point_compress(x, y)
    elif type is 'msg2lib':
        sb = pubkey[0:1]
        xb = pubkey[1:34]
        x, y = Crypto.point_decompress(sb, xb)
        return '\x01\x9f\x00\x20' + x + '\x00\x20' + y
    elif type is 'raw2lib':
        return '\x01\x9f\x00\x20' + pubkey[0:32] + '\x00\x20' + pubkey[32:64]
    elif type is 'raw2msg':
        x = pubkey[0:32]
        y = pubkey[32:64]
        return Crypto.point_compress(x, y)
    elif type is 'raw2readable':
        short = fmt_pub(pubkey, 'raw2msg')
        return 'ECCRYPT' + (base58.b58encode(short))
    elif type is 'readable2msg':
        short = pubkey[7:]
        return base58.b58decode(short)
    elif type is 'readable2lib':
        key = fmt_pub(pubkey, 'readable2msg')
        return fmt_pub(key, 'msg2lib')
    elif type is 'lib2readable':
        short = fmt_pub(pubkey, 'lib2msg')
        return 'ECCRYPT' + (base58.b58encode(short))
    elif type is 'readable2raw':
        key = base58.b58decode(pubkey[7:])
        sb = key[0:1]
        xb = key[1:34]
        x, y = Crypto.point_decompress(sb, xb)
        return x + y
    elif type is 'msg2raw':
        sb = pubkey[0:1]
        xb = pubkey[1:34]
        x, y = Crypto.point_decompress(sb, xb)
        return x + y
    elif type is 'msg2readable':
        return 'ECCRYPT' + (base58.b58encode(pubkey))


cconf = UnicodeConfigParser()
mconf = UnicodeConfigParser()


def form_key_id(pubkey_bin):
    hash_pubkey = hashlib.sha512(pubkey_bin).digest()
    making_key_id = base64.b32encode(hash_pubkey[0:5])
    return making_key_id.upper()


def load_contact_keys():
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        contact_key_id_list = cconf.sections()
        contact_alias_list = []
        for id in contact_key_id_list:
            contact_key_iter_alias = cconf.get(id, 'alias')
            pubkey = cconf.get(id, 'publickey')
            contact_alias_list.append(contact_key_iter_alias)
        return ([x + '::' + y for x, y in zip(contact_key_id_list, contact_alias_list)])


def generate_new_master_key():
    new_privkey, new_pubkey = Crypto.generate_new_key()
    new_key_id = form_key_id(new_pubkey)
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        mconf.add_section(new_key_id)
        mconf.set(new_key_id, 'privatekey', (format_privkey(new_privkey, 'b58')))
        mconf.set(new_key_id, 'publickey', (fmt_pub(new_pubkey, 'raw2readable')))
        mconf.set(new_key_id, 'alias', '(none)')
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)
    return new_key_id


def edit_master_key(chosen_master_edit_index, alias_new):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        mconf.set(chosen_master_edit_index, 'alias', alias_new)
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def delete_master_key(id_list):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        for id in id_list:
            mconf.remove_section(id)
    with codecs.open('keyring/master_keyring.dat', 'wb+', 'utf-8') as mwrite:
        mconf.write(mwrite)


def retrieve_masterkey(key_id):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as master_keyring:
        mconf.readfp(master_keyring)
        known_keys = mconf.sections()
        if any(key_id in id for id in known_keys):
            return (mconf.get(key_id, 'privatekey')), (mconf.get(key_id, 'publickey'))
        elif not any(key_id in id for id in known_keys):
            e = 'This message is for {}, don\'t have Master Key with this key ID'.format(key_id)
            raise ECCryptException(e)


def retrieve_masterkey_id_from_list(key_id_list):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as master_keyring:
        mconf.readfp(master_keyring)
        known_keys = mconf.sections()
        for id in known_keys:
            if id in key_id_list:
                return id
        e = 'This message is for {}, don\'t have Master Key(s) with this key ID'.format(', '.join(key_id_list))
        raise ECCryptException(e)


def retrieve_masterkey_id_list():
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        masterkey_id_list = mconf.sections()
        return masterkey_id_list


def retrieve_master_alias(id):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        return (mconf.get(id, 'alias'))


def retrieve_master_key(id):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        return (mconf.get(id, 'publickey'))



def retrieve_contactkey_id_list():
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        contact_key_id_list = cconf.sections()
        return contact_key_id_list


def retrieve_contact_alias(id):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        return (cconf.get(id, 'alias'))


def retrieve_contact_key(id):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        return (cconf.get(id, 'publickey'))


def show_master_key(chosen_master_edit_index):
    with codecs.open('keyring/master_keyring.dat', 'r', 'utf-8') as mfile:
        mconf.readfp(mfile)
        return mconf.get(chosen_master_edit_index, 'publickey')


def delete_contact_key(id_list):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        for id in id_list:
            cconf.remove_section(id)
    with codecs.open('keyring/contact_keyring.dat', 'wb+', 'utf-8') as cwrite:
        cconf.write(cwrite)


def add_new_contact_key(new_id, new_key):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        known_contacts = cconf.sections()
        cconf.add_section(new_id)
        cconf.set(new_id, 'publickey', new_key)
        cconf.set(new_id, 'alias', '(none)')
    with codecs.open('keyring/contact_keyring.dat', 'wb+', 'utf-8') as cwrite:
        cconf.write(cwrite)


def edit_contact_key(chosen_contact_edit_index, alias_new):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        cconf.set(chosen_contact_edit_index, 'alias', alias_new)
    with codecs.open('keyring/contact_keyring.dat', 'wb+', 'utf-8') as cwrite:
        cconf.write(cwrite)


def check_contact_identity(key_id):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as contact_keyring:
        cconf.readfp(contact_keyring)
        known_contacts = cconf.sections()
        if any(key_id in id for id in known_contacts):
            return True
        elif not any(key_id in id for id in known_contacts):
            return False


def show_contact_key(chosen_contact_edit_index):
    with codecs.open('keyring/contact_keyring.dat', 'r', 'utf-8') as cfile:
        cconf.readfp(cfile)
        contact_pubkey = cconf.get(chosen_contact_edit_index, 'publickey')
    return contact_pubkey

