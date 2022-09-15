import argparse
import os
import sys
import Crypto
import FormatKeys
import Messaging
import Parsing


class ECCryptException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


'''Checking if encryption/decryption directories exist'''
frozen = getattr(sys,'frozen', None)
def check_decrypt_dir():
    if 'win32' in sys.platform or 'win64' in sys.platform:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.dirname(sys.executable)
        else:
            localadditionpath = os.path.dirname(__file__)
        decryptpath = localadditionpath + '/decrypted/'
        norm_decrypt_path = os.path.normpath(decryptpath)
        try: 
            os.makedirs(norm_decrypt_path)
        except OSError:
            if not os.path.isdir(norm_decrypt_path):
                raise
    else: 
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.abspath(sys.executable)
        else:
            localadditionpath = os.path.abspath(__file__)
        decryptpath = os.path.dirname(localadditionpath) + '/decrypted/'
        norm_decrypt_path = os.path.normcase(decryptpath)
        if not os.path.isdir(norm_decrypt_path):
            os.makedirs(norm_decrypt_path)


def check_encrypt_dir():
    if 'win32' in sys.platform or 'win64' in sys.platform:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.dirname(sys.executable)
        else:
            localadditionpath = os.path.dirname(__file__)
        encryptpath = localadditionpath + '/encrypted/'
        norm_encrypt_path = os.path.normcase(encryptpath)
        try: 
            os.makedirs(norm_encrypt_path)
        except OSError:
            if not os.path.isdir(norm_encrypt_path):
                raise
    else: 
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.abspath(sys.executable)
        else:
            localadditionpath = os.path.abspath(__file__)
        encryptpath = os.path.dirname(localadditionpath) + '/encrypted/'
        norm_encrypt_path = os.path.normcase(encryptpath)
        if not os.path.isdir(norm_encrypt_path):
            os.makedirs(norm_encrypt_path)


def check_keyring_files():
    if 'win32' in sys.platform or 'win64' in sys.platform:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.dirname(sys.executable)
        else:
            localadditionpath = os.path.dirname(__file__)
        keyring_path = localadditionpath + '/keyring/'
        norm_keyring_path = os.path.normcase(keyring_path)
        try:
            os.makedirs(norm_keyring_path)
        except OSError:
            if not os.path.isdir(norm_keyring_path):
                raise
        open('keyring/master_keyring.dat', 'a').close()
        open('keyring/contact_keyring.dat', 'a').close()
    else:
        if getattr(sys, 'frozen', False):
            localadditionpath = os.path.abspath(sys.executable)
        else:
            localadditionpath = os.path.abspath(__file__)
        keyring_path = os.path.dirname(localadditionpath) + '/keyring/'
        norm_keyring_path = os.path.normcase(keyring_path)
        if not os.path.isdir(norm_keyring_path):
            os.makedirs(norm_keyring_path)
        open('keyring/master_keyring.dat', 'a+').close()
        open('keyring/contact_keyring.dat', 'a+').close()


'''Check if data folders exist'''
check_decrypt_dir()
check_encrypt_dir()
check_keyring_files()

'''Simple test for PRNG'''
if Crypto.run_test() is False:
    sys.exit()




def get_message_type():
    if not args.incognito and args.file is None:
        return 12
    elif not args.incognito and args.file is not None:
        return 24
    elif args.incognito and args.file is None:
        return 36
    elif args.incognito and args.file is not None:
        return 48


def encrypt_message(args):
    try:
        check_masterkey_id(args.master_key)
        check_contact_id(args.id)
        text_message, tn = read_file(args.msg)
        if args.file:
            attach_data, attach_name = read_file(args.file)
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return
    msg_type = get_message_type()
    if msg_type is 12: 
        enc_msg, msg_name = Messaging.encrypt12type(args.master_key,
                                                    list(set(args.id)),
                                                    text_message)
    elif msg_type is 24: 
        enc_msg, msg_name = Messaging.encrypt24type(args.master_key,
                                                    list(set(args.id)),
                                                    text_message,
                                                    attach_data,
                                                    attach_name)
    elif msg_type is 36: 
        enc_msg, msg_name = Messaging.encrypt36type(list(set(args.id)),
                                                    text_message)
    elif msg_type is 48: 
        enc_msg, msg_name = Messaging.encrypt48type(list(set(args.id)), 
                                                    text_message, 
                                                    attach_data,
                                                    attach_name)
    if args.hide_ids:
        enc_msg, msg_name = Messaging.encrypt60type(list(set(args.id)),
                                                    enc_msg)
    if not args.binary:
        enc_msg = Messaging.message_encode(enc_msg)
    if not args.output:
        print_message('Message:\n' + ('--------\n\n') + enc_msg)
    elif args.output:
        try:
            check_dir(args.output)
            write_file(args.output, enc_msg)
            print_message('Encrypted message to: ' + args.output)
        except ECCryptException, (instance): 
            print_error(instance.parameter)
            return



def decrypt_message(args):
    try: 
        message_text, tn = read_file(args.msg)
        if not args.binary:
            message = Messaging.message_decode(message_text)
        elif args.binary:
            message = message_text
        decrypting(message)
    except Messaging.ECCryptException, (instance): 
        print_error(instance.parameter)
    except FormatKeys.ECCryptException, (instance):
        print_error(instance.parameter)
    except Parsing.ECCryptException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return


def decrypting(message):
    msg_type = ord(message[0:1])
    if msg_type is 12:
        text, sender_id, status, info = Messaging.decrypt12type(message)
    elif msg_type is 24:
        text, sender_id, attach, attach_name, status, info = Messaging.decrypt24type(message)
        write_file('decrypted/' + attach_name, attach)
    elif msg_type is 36:
        text, status, info = Messaging.decrypt36type(message)
    elif msg_type is 48:
        text, attach, attach_name, status, info = Messaging.decrypt48type(message)
        write_file('decrypted/' + attach_name, attach)
    elif msg_type is 60:
        decrypted_payload = Messaging.decrypt60type(message)
        decrypting(decrypted_payload)
    else: 
        print_error('Not an EC-Crypt message!')
        return
    print_message(status + '\n\n' + info)
    if args.output: 
        try:
            check_dir(args.output)
            write_file(args.output, text)
            print_message('Decrypted message to: ' + args.output)
        except ECCryptException, (instance): 
            print_error(instance.parameter)
            return 
    elif not args.output:
        print_message('Message:\n' + ('--------\n\n') + text)


def write_file(self, path, data):
    with open(path, 'wb') as f:
        f.write(data)


def write_signed(path, data):
    with open(path, 'wb') as f:
        f.write(data.encode('utf-8') + '\n')


def read_file(path):
    with open(path, 'rb') as f:
        data = f.read()
        filename = os.path.basename(f.name)
    return data, filename


def sign_message(args):
    try:
        check_masterkey_id(args.master_key)
        text_message, tn = read_file(args.msg)
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return
    if not args.timestamp: 
        signed_text = Messaging.sign7type(args.master_key, text_message)
    elif args.timestamp: 
        signed_text = Messaging.sign14type(args.master_key, text_message)
    print_message('Signed message with key: ' + args.master_key)
    if args.output: 
        write_signed(args.output, signed_text)
    elif not args.output:
        print_message('Message:\n' + ('--------\n\n') + signed_text)


def sign_file(args):
    try:
        check_masterkey_id(args.master_key)
        file_data, tn = read_file(args.file)
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return
    if not args.timestamp: 
        file_sig = Messaging.sign21type(args.master_key, file_data)
    elif args.timestamp: 
        file_sig = Messaging.sign28type(args.master_key, file_data)
    print_message('Signed file with key: ' + args.master_key)
    if args.output: 
        try:
            check_dir(args.output)
            write_file(args.output, file_sig)
            print_message('Wrote sigature to: ' + args.output)
        except ECCryptException, (instance): 
            print_error(instance.parameter)
            return
    elif not args.output:
        print_message('Signature:\n' + ('----------\n\n') + file_sig)


def verify_message(args):
    try: 
        message_text, tn = read_file(args.msg)
        data, sig = Messaging.msg_signature_decode(message_text)
        verifying(data, sig)
    except Messaging.ECCryptException, (instance): 
        print_error(instance.parameter)
    except FormatKeys.ECCryptException, (instance):
        print_error(instance.parameter)
    except Parsing.ECCryptException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return


def verify_file(args):
    try:
        data, fn = read_file(args.file)
        sig_data, sn = read_file(args.sig)
        sig = Messaging.file_signature_decode(sig_data)
        verifying(data, sig)
    except Messaging.ECCryptException, (instance): 
        print_error(instance.parameter)
    except FormatKeys.ECCryptException, (instance):
        print_error(instance.parameter)
    except Parsing.ECCryptException, (instance):
        print_error(instance.parameter)
    except IOError, (instance):
        print_error('No such file or directory: {}'.format(args.msg))
        return


def verifying(data, sig):
    sig_type = ord(sig[0:1])
    if sig_type is 7:
        status, info = Messaging.verify7sig(data, sig)
    elif sig_type is 14:
        status, info = Messaging.verify14sig(data, sig)
    elif sig_type is 21:
        status, info = Messaging.verify21sig(data, sig)
    elif sig_type is 28:
        status, info = Messaging.verify28sig(data, sig)
    else: 
        print 'Not an EC-Crypt signature!'
        return
    print_message(status + '\n\n' + info)


def print_masterkeys(args):
    master_id_list = FormatKeys.retrieve_masterkey_id_list()
    s = u'Master keys:\n\n'
    for id in master_id_list:
        alias = FormatKeys.retrieve_master_alias(id)
        pub = FormatKeys.retrieve_master_key(id)
        s += u'[{}]\n    Public key: {}\n    Alias:      {}\n\n'.format(id, pub, alias)
    print_message(s)


def gen_masterkey(args):
    new_key_id = FormatKeys.generate_new_master_key()
    master_id_list = FormatKeys.retrieve_masterkey_id_list()
    print_message('Generated new key {}, edit alias for usability'.format(new_key_id))


def del_masterkey(args):
    try:
        check_masterkey_id(list(set(args.id)))
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    FormatKeys.delete_master_key(list(set(args.id)))
    master_id_list = FormatKeys.retrieve_masterkey_id_list()
    print_message('Key(s) {} deleted'.format(', '.join(list(set(args.id)))))


def print_contacts(args):
    s = u'Contact keys:\n\n'
    contact_id_list = FormatKeys.retrieve_contactkey_id_list()
    for id in contact_id_list:
        alias = FormatKeys.retrieve_contact_alias(id)
        pub = FormatKeys.retrieve_contact_key(id)
        s += u'[{}]\n    Public key: {}\n    Alias:      {}\n\n'.format(id, pub, alias)
    print_message(s)


def add_contactkey(args):
    validation = Crypto.check_pubkey(args.pubkey)
    if validation is True:
        new_key_raw = FormatKeys.fmt_pub(args.pubkey, 'readable2raw')
        new_key_id = FormatKeys.form_key_id(new_key_raw)
        if FormatKeys.check_contact_identity(new_key_id) is True:
            print_message('This key is already in key ring!')
        elif FormatKeys.check_contact_identity(new_key_id) is False:
            FormatKeys.add_new_contact_key(new_key_id, args.pubkey)
            print_message('New contact added: {}, edit alias for usability'.format(new_key_id))
            if args.alias:
                FormatKeys.edit_contact_key(new_key_id, args.alias)
    elif validation is False:
        print_message('Invalid contact key!')


def del_contactkey(args):
    try:
        check_contact_id(list(set(args.id)),)
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    FormatKeys.delete_contact_key(list(set(args.id)),)
    master_id_list = FormatKeys.retrieve_contactkey_id_list()
    print_message('Key(s) {} deleted'.format(', '.join(list(set(args.id)))))


def edit_contactalias(args):
    try:
        check_contact_id(args.contact_id)
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    FormatKeys.edit_contact_key(args.contact_id, args.alias)
    print_message('Changed alias for contact key {}'.format(args.contact_id))


def edit_masterkeyalias(args):
    try:
        check_masterkey_id(args.master_key)
    except ECCryptException, (instance): 
        print_error(instance.parameter)
        return
    FormatKeys.edit_master_key(args.master_key, args.alias)
    print_message('Changed alias for contact key {}'.format(args.master_key))



def check_contact_id(ids_to_check):
    contact_id_list = FormatKeys.retrieve_contactkey_id_list()
    if isinstance(ids_to_check, basestring):
        if not ids_to_check in contact_id_list:
            e = 'No such key: {}'.format(ids_to_check)
            raise ECCryptException(e)
    else:
        for id in ids_to_check:
            if not id in contact_id_list:
                e = 'No such key: {}'.format(id)
                raise ECCryptException(e)
            

def check_masterkey_id(ids_to_check):
    master_id_list = FormatKeys.retrieve_masterkey_id_list()
    if isinstance(ids_to_check, basestring):
        if not ids_to_check in master_id_list:
            e = 'No such key: {}'.format(ids_to_check)
            raise ECCryptException(e)
    else:
        for id in ids_to_check:
            if not id in master_id_list:
                e = 'No such key: {}'.format(id)
                raise ECCryptException(e)


def check_dir(path_to_check):
    dir_path = os.path.dirname(path_to_check)
    if not os.path.exists(dir_path):
        e = 'No such directory: {}'.format(dir_path)
        raise ECCryptException(e)


def print_message(msg):
    if args.no_verbose is True:
        pass
    elif args.no_verbose is False:
        print '\n\n' + msg + '\n\n'


def print_error(msg):
    if args.no_verbose is True:
        pass
    elif args.no_verbose is False:
        prog_name = os.path.basename(sys.argv[0])
        print '{}: error: {}\n'.format(prog_name, msg)




arg_parser = argparse.ArgumentParser(description = 'EC-Crypt cryptographic tool')
subparsers = arg_parser.add_subparsers(help = 'Sub-command help')


parser_encrypt = subparsers.add_parser('encrypt', 
    help = 'Encrypt message')
parser_encrypt.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify master key to encrypt messages with')
parser_encrypt.add_argument('--msg',
    type = str,
    required = True,
    help = 'Specify text message file to encrypt')
parser_encrypt.add_argument('--output',
    type = str,
    help = 'Specify output file')
parser_encrypt.add_argument('--contact-id',
    dest = 'id',
    nargs = '+',
    type = str,
    required = True,
    help = 'Specify contacts to encrypt message for')
parser_encrypt.add_argument('--attachment', 
    dest = 'file',
    type = str,
    default = None,
    help = 'Additional file to include in encrypted message')
parser_encrypt.add_argument('--incognito', 
    action = 'store_true', 
    help = 'Do not include identifiers in encrypted message')
parser_encrypt.add_argument('--hide-ids', 
    action = 'store_true', 
    help = 'Obfuscate IDs in encrypted message')
parser_encrypt.add_argument('--binary', 
    action = 'store_true', 
    help = 'Do not MIME-encode encrypted message')
parser_encrypt.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_encrypt.set_defaults(func = encrypt_message)


parser_decrypt = subparsers.add_parser('decrypt', 
    help = 'Decrypt message')
parser_decrypt.add_argument('--msg',
    type = str,
    required = True,
    help = 'Specify text message file to decrypt')
parser_decrypt.add_argument('--output',
    type = str,
    help = 'Specify output file for decrypted message')
parser_decrypt.add_argument('--binary', 
    action = 'store_true', 
    help = 'Decrypt binary (not encoded) message')
parser_decrypt.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_decrypt.set_defaults(func = decrypt_message)


parser_signmsg = subparsers.add_parser('sign-message', 
    help = 'Sign message')
parser_signmsg.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify master key to sign messages with')
parser_signmsg.add_argument('--msg', 
    type = str,
    required = True,
    help = 'Specify text document to sign')
parser_signmsg.add_argument('--output',
    type = str,
    help = 'Specify output file for signed message')
parser_signmsg.add_argument('--timestamp', 
    action = 'store_true', 
    help = 'Include timestamp in the file signature (reveals system clock)')
parser_signmsg.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_signmsg.set_defaults(func = sign_message)


parser_signfile = subparsers.add_parser('sign-file', 
    help = 'Sign file')
parser_signfile.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify master key to file messages with')
parser_signfile.add_argument('--file', 
    type = str,
    required = True,
    help = 'Specify file to sign')
parser_signfile.add_argument('--output',
    type = str,
    help = 'Specify output file for signature')
parser_signfile.add_argument('--timestamp', 
    action = 'store_true', 
    help = 'Include timestamp in the file signature (reveals system clock)')
parser_signfile.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_signfile.set_defaults(func = sign_file)


parser_verifymsg = subparsers.add_parser('verify-message', 
    help = 'Verify signed message')
parser_verifymsg.add_argument('--msg', 
    type = str,
    required = True,
    help = 'Specify text message file with signed message to verify')
parser_verifymsg.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_verifymsg.set_defaults(func = verify_message)


parser_verifyfile = subparsers.add_parser('verify-file',
    help = 'Verify signed file')
parser_verifyfile.add_argument('--file',
    type = str,
    required = True,
    help = 'Specify file to verify')
parser_verifyfile.add_argument('--signature',
    dest = 'sig',
    type = str,
    required = True,
    help = 'Specify file signature to verify')
parser_verifyfile.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_verifyfile.set_defaults(func = verify_file)


parser_showmasterkeys = subparsers.add_parser('master-keys',
    help = 'Display all private keys (Master keys)')
parser_showmasterkeys.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_showmasterkeys.set_defaults(func = print_masterkeys)


parser_showcontacts = subparsers.add_parser('contacts',
    help = 'Display all contact keys')
parser_showcontacts.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_showcontacts.set_defaults(func = print_contacts)


parser_genkey = subparsers.add_parser('gen-key',
    help = 'Generate new private key (Master key)')
parser_genkey.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_genkey.set_defaults(func = gen_masterkey)


parser_addcontact = subparsers.add_parser('add-contact',
    help = 'Add contact public key to the key ring')
parser_addcontact.add_argument('--public-key',
    dest = 'pubkey',
    required = True,
    help = 'Public key to add to the key ring')
parser_addcontact.add_argument('--alias',
    type = str,
    help = 'Alias for added contact')
parser_addcontact.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_addcontact.set_defaults(func = add_contactkey)


parser_editmasterkey = subparsers.add_parser('set-key-alias',
    help = 'Set an alias for a given private key (Master key)')
parser_editmasterkey.add_argument('--master-key',
    type = str,
    required = True,
    help = 'Specify private key (Master keys)')
parser_editmasterkey.add_argument('--alias',
    type = str,
    required = True,
    help = 'Specify alias string')
parser_editmasterkey.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_editmasterkey.set_defaults(func = edit_masterkeyalias)


parser_editcontact = subparsers.add_parser('set-contact-alias',
    help = 'Set an alias for a given contact key')
parser_editcontact.add_argument('--contact-id',
    type = str,
    required = True,
    help = 'Specify contact key')
parser_editcontact.add_argument('--alias',
    type = str,
    required = True,
    help = 'Specify alias string')
parser_editcontact.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_editcontact.set_defaults(func = edit_contactalias)


parser_delkey = subparsers.add_parser('del-master-key',
    help = 'Delete one or more private keys (Master keys)')
parser_delkey.add_argument('--master-key',
    nargs = '+',
    dest = 'id',
    type = str,
    required = True,
    help = 'Specify one or more keys to delete')
parser_delkey.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_delkey.set_defaults(func = del_masterkey)


parser_delcontact = subparsers.add_parser('del-contact',
    help = 'Delete one or more contact keys')
parser_delcontact.add_argument('--contact-id',
    nargs = '+',
    dest = 'id',
    type = str,
    required = True,
    help = 'Specify one or more keys to delete')
parser_delcontact.add_argument('--no-verbose', 
    action = 'store_true',
    help = 'Supress all notifications')
parser_delcontact.set_defaults(func = del_contactkey)




if len(sys.argv) < 2:
    while(True):
        try:
            a = raw_input('{} > '.format(os.path.basename(sys.argv[0])))
            args = arg_parser.parse_args(a.split())
            args.func(args)
        except SystemExit as e:
            pass
        except KeyboardInterrupt:
            sys.exit()
else:
    args = arg_parser.parse_args()
    args.func(args)

