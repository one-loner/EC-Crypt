import binascii
import os
import re
import time
import zlib
import base58
import FormatKeys
import Crypto
import Parsing


class ECCryptException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


def encrypt12type(your_id, their_id, txt):
    usr_key = FormatKeys.Key(key_id = your_id)
    eph_key = FormatKeys.Key()
    token = Crypto.generate_secret()
    comp_message = zlib.compress(txt)
    timestamp = (time.strftime("%m%d%H%M%S"))
    encrypted_text = Crypto.encrypt_text(token, comp_message)
    ss_list = []
    for id in their_id:
        their_pub = FormatKeys.retrieve_contact_key(id)
        rec_pub_bin = FormatKeys.fmt_pub(their_pub, 'readable2lib')
        secret = Crypto.ecdh_secret(eph_key.get_priv('lib'), 
                                    eph_key.get_pub('lib'), 
                                    rec_pub_bin)
        enc_token = Crypto.encrypt_text(secret, token)
        ss_list.append(enc_token)
    Parser = Parsing.Parser(type = 12, 
                            usr_priv = usr_key.get_priv('lib'), 
                            usr_pub = usr_key.get_pub('lib'),
                            sender_pub_msg = usr_key.get_pub('msg'))
    newmsg = Parser.type12construct(their_id, 
                                    ss_list,
                                    eph_key.get_pub('msg'),
                                    encrypted_text)
    msg_name = timestamp + '.msg'        
    return newmsg, msg_name


def encrypt24type(your_id, their_id, txt, attach_file, attach_filename):
    usr_key = FormatKeys.Key(key_id = your_id)
    eph_key = FormatKeys.Key()
    token = Crypto.generate_secret()
    text = txt + ('\n' * 7) + ('_' * 24) + '\n' +\
            unicode(attach_filename).encode('utf-8')
    comp_message = zlib.compress(text)
    timestamp = (time.strftime("%m%d%H%M%S"))
    encrypted_text = Crypto.encrypt_text(token, comp_message)
    encrypted_attach = Crypto.encrypt_attach(token, attach_file)
    ss_list = []
    for id in their_id:
        their_pub = FormatKeys.retrieve_contact_key(id)
        rec_pub_bin = FormatKeys.fmt_pub(their_pub, 'readable2lib')
        secret = Crypto.ecdh_secret(eph_key.get_priv('lib'), 
                                    eph_key.get_pub('lib'), 
                                    rec_pub_bin)
        enc_token = Crypto.encrypt_text(secret, token)
        ss_list.append(enc_token)
    Parser = Parsing.Parser(type = 24, 
                            usr_priv = usr_key.get_priv('lib'), 
                            usr_pub = usr_key.get_pub('lib'),
                            sender_pub_msg = usr_key.get_pub('msg'))
    newmsg = Parser.type24construct(their_id, 
                                    ss_list,
                                    eph_key.get_pub('msg'),
                                    encrypted_text,
                                    encrypted_attach)
    msg_name = timestamp + '.msg'        
    return newmsg, msg_name


def encrypt36type(their_id, txt):
    eph_key = FormatKeys.Key()
    token = Crypto.generate_secret()
    comp_message = zlib.compress(txt)
    timestamp = (time.strftime("%m%d%H%M%S"))
    encrypted_text = Crypto.encrypt_text(token, comp_message)
    ss_list = []
    for id in their_id:
        their_pub = FormatKeys.retrieve_contact_key(id)
        rec_pub_bin = FormatKeys.fmt_pub(their_pub, 'readable2lib')
        secret = Crypto.ecdh_secret(eph_key.get_priv('lib'), 
                                    eph_key.get_pub('lib'), 
                                    rec_pub_bin)
        enc_token = Crypto.encrypt_text(secret, token)
        ss_list.append(enc_token)
    Parser = Parsing.Parser(type = 36, 
                            usr_priv = eph_key.get_priv('lib'), 
                            usr_pub = eph_key.get_pub('lib'),
                            sender_pub_msg = eph_key.get_pub('msg'))
    newmsg = Parser.type36construct(their_id, 
                                    ss_list,
                                    eph_key.get_pub('msg'),
                                    encrypted_text)
    msg_name = timestamp + '.msg'        
    return newmsg, msg_name


def encrypt48type(their_id, txt, attach_file, attach_filename):
    eph_key = FormatKeys.Key()
    token = Crypto.generate_secret() 
    text = txt + ('\n' * 7) + ('_' * 24) + '\n' +\
            unicode(attach_filename).encode('utf-8')
    comp_message = zlib.compress(text)
    timestamp = (time.strftime("%m%d%H%M%S"))
    encrypted_text = Crypto.encrypt_text(token, comp_message)
    encrypted_attach = Crypto.encrypt_attach(token, attach_file)
    ss_list = []
    for id in their_id:
        their_pub = FormatKeys.retrieve_contact_key(id)
        rec_pub_bin = FormatKeys.fmt_pub(their_pub, 'readable2lib')
        secret = Crypto.ecdh_secret(eph_key.get_priv('lib'), 
                                    eph_key.get_pub('lib'), 
                                    rec_pub_bin)
        enc_token = Crypto.encrypt_text(secret, token)
        ss_list.append(enc_token)
    Parser = Parsing.Parser(type = 48, 
                            usr_priv = eph_key.get_priv('lib'), 
                            usr_pub = eph_key.get_pub('lib'),
                            sender_pub_msg = eph_key.get_pub('msg'))
    newmsg = Parser.type48construct(their_id, 
                                    ss_list,
                                    eph_key.get_pub('msg'),
                                    encrypted_text,
                                    encrypted_attach)
    msg_name = timestamp + '.msg'        
    return newmsg, msg_name


def encrypt60type(their_id, payload):
    eph_key = FormatKeys.Key()
    token = Crypto.generate_secret()
    timestamp = (time.strftime("%m%d%H%M%S"))
    enc_payload = Crypto.encrypt_text(token, payload)
    ss_list = []
    for id in their_id:
        their_pub = FormatKeys.retrieve_contact_key(id)
        rec_pub_bin = FormatKeys.fmt_pub(their_pub, 'readable2lib')
        secret = Crypto.ecdh_secret(eph_key.get_priv('lib'), 
                                    eph_key.get_pub('lib'), 
                                    rec_pub_bin)
        enc_token = Crypto.encrypt_text(secret, token)
        ss_list.append(enc_token)
    Parser = Parsing.Parser(type = 60, 
                            usr_priv = eph_key.get_priv('lib'), 
                            usr_pub = eph_key.get_pub('lib'),
                            sender_pub_msg = eph_key.get_pub('msg'))
    newmsg = Parser.type60construct(ss_list,
                                    eph_key.get_pub('msg'),
                                    enc_payload)
    msg_name = timestamp + '.msg'
    return newmsg, msg_name


def decrypt12type(message):
    Parser = Parsing.Parser(type = 12) 
    their_pub, eph_key, id_list, ss_list, enc_txt = Parser.type12deconstruct(message)
    your_id = FormatKeys.retrieve_masterkey_id_from_list(id_list)
    usr_key = FormatKeys.Key(key_id = your_id)
    list_posit = id_list.index(your_id)
    enc_token = ss_list[list_posit]
    their_pub_raw = FormatKeys.fmt_pub(their_pub, 'msg2raw')
    their_id = FormatKeys.form_key_id(their_pub_raw)
    ephem_pub_bin = FormatKeys.fmt_pub(eph_key, 'msg2lib')
    secret = Crypto.ecdh_secret(usr_key.get_priv('lib'), 
                                usr_key.get_pub('lib'), 
                                ephem_pub_bin)
    decr_token = Crypto.decrypt_text(secret, enc_token)
    comp_text = Crypto.decrypt_text(decr_token, enc_txt)
    text = zlib.decompress(comp_text)
    contact_known = FormatKeys.check_contact_identity(their_id)
    msg_info = form_msg_info(your_id, their_id, id_list, text)
    if contact_known is True:
        status = 'Decrypted message from: ' + their_id
    elif contact_known is False:
        msg_info += 'Unknown key: {}'.format(FormatKeys.fmt_pub(their_pub, 'msg2readable'))
        status = 'Unknown sender. Copy public key in info field'
    return text, their_id, status, msg_info


def decrypt24type(message):
    Parser = Parsing.Parser(type = 24) 
    their_pub, eph_key, id_list, ss_list, enc_txt, attach = Parser.type24deconstruct(message)
    your_id = FormatKeys.retrieve_masterkey_id_from_list(id_list)
    usr_key = FormatKeys.Key(key_id = your_id)
    list_posit = id_list.index(your_id)
    enc_token = ss_list[list_posit]
    ephem_pub_bin = FormatKeys.fmt_pub(eph_key, 'msg2lib')
    their_pub_raw = FormatKeys.fmt_pub(their_pub, 'msg2raw')
    their_id = FormatKeys.form_key_id(their_pub_raw)
    secret = Crypto.ecdh_secret(usr_key.get_priv('lib'), 
                                usr_key.get_pub('lib'), 
                                ephem_pub_bin)
    decr_token = Crypto.decrypt_text(secret, enc_token)
    comp_text = Crypto.decrypt_text(decr_token, enc_txt)
    decr_attach = Crypto.decrypt_attach(decr_token, attach)
    text = zlib.decompress(comp_text)
    attach_name = unicode(''.join(text.splitlines()[-1:]), 'utf-8')
    contact_known = FormatKeys.check_contact_identity(their_id)
    msg_info = form_msg_info(your_id, their_id, id_list, text, attach, attach_name)
    if contact_known is True:
        status = 'Decrypted message from: ' + their_id
    elif contact_known is False:
        msg_info += 'Unknown key: {}'.format(FormatKeys.fmt_pub(their_pub, 'msg2readable'))
        status = 'Unknown sender. Copy public key in info field'
    return text, their_id, decr_attach, attach_name, status, msg_info


def decrypt36type(message):
    Parser = Parsing.Parser(type = 36) 
    eph_key, id_list, ss_list, enc_txt = Parser.type36deconstruct(message)
    your_id = FormatKeys.retrieve_masterkey_id_from_list(id_list)
    usr_key = FormatKeys.Key(key_id = your_id)
    list_posit = id_list.index(your_id)
    enc_token = ss_list[list_posit]
    ephem_pub_bin = FormatKeys.fmt_pub(eph_key, 'msg2lib')
    secret = Crypto.ecdh_secret(usr_key.get_priv('lib'), 
                                usr_key.get_pub('lib'), 
                                ephem_pub_bin)
    decr_token = Crypto.decrypt_text(secret, enc_token)
    comp_text = Crypto.decrypt_text(decr_token, enc_txt)
    text = zlib.decompress(comp_text)
    status = 'Decrypted message from Incognito sender '
    msg_info = form_msg_info(your_id, 'Incognito', id_list, text)
    return text, status, msg_info


def decrypt48type(message):
    Parser = Parsing.Parser(type = 48) 
    eph_key, id_list, ss_list, enc_txt, attach = Parser.type48deconstruct(message)
    your_id = FormatKeys.retrieve_masterkey_id_from_list(id_list)
    usr_key = FormatKeys.Key(key_id = your_id)
    list_posit = id_list.index(your_id)
    enc_token = ss_list[list_posit]
    ephem_pub_bin = FormatKeys.fmt_pub(eph_key, 'msg2lib')
    secret = Crypto.ecdh_secret(usr_key.get_priv('lib'), 
                                usr_key.get_pub('lib'), 
                                ephem_pub_bin)
    decr_token = Crypto.decrypt_text(secret, enc_token)
    comp_text = Crypto.decrypt_text(decr_token, enc_txt)
    decr_attach = Crypto.decrypt_attach(decr_token, attach)
    text = zlib.decompress(comp_text)
    attach_name = unicode(''.join(text.splitlines()[-1:]), 'utf-8')
    status = 'Decrypted message from Incognito sender ' +\
                        '; Attachment: ' + attach_name
    
    msg_info = form_msg_info(your_id, 'Incognito', id_list, text, attach, attach_name)
    return text, decr_attach, attach_name, status, msg_info


def decrypt60type(message):
    Parser = Parsing.Parser(type = 60) 
    eph_key, ss_list, payload = Parser.type60deconstruct(message)
    ephem_pub_bin = FormatKeys.fmt_pub(eph_key, 'msg2lib')
    usr_id_list = FormatKeys.retrieve_masterkey_id_list()
    for enc_token in ss_list:
        for id in usr_id_list:
            usr_key = FormatKeys.Key(key_id = id)
            secret = Crypto.ecdh_secret(usr_key.get_priv('lib'), 
                                        usr_key.get_pub('lib'), 
                                        ephem_pub_bin)
            try:
                decr_token = Crypto.decrypt_text(secret, enc_token)
                return Crypto.decrypt_text(decr_token, payload)
            except Exception:
                pass
    e = 'No keys present in the keyring to decrypt this message!'
    raise ECCryptException(e)


def sign7type(your_id, text):
    usr_key = FormatKeys.Key(key_id = your_id)
    Parser = Parsing.Parser(type = 7,
                            usr_priv = usr_key.get_priv('lib'), 
                            usr_pub = usr_key.get_pub('lib'),
                            sender_pub_msg = usr_key.get_pub('msg'))
    newsig = Parser.sig7construct(text)
    return msg_signature_encode(text, newsig)


def sign14type(your_id, text):
    usr_key = FormatKeys.Key(key_id = your_id)
    Parser = Parsing.Parser(type = 14, 
                            usr_priv = usr_key.get_priv('lib'), 
                            usr_pub = usr_key.get_pub('lib'),
                            sender_pub_msg = usr_key.get_pub('msg'))
    timestamp = int(time.time())
    newsig = Parser.sig14construct(text, timestamp)
    return msg_signature_encode(text, newsig)


def sign21type(your_id, file_data):
    usr_key = FormatKeys.Key(key_id = your_id)
    Parser = Parsing.Parser(type = 21,
                            usr_priv = usr_key.get_priv('lib'), 
                            usr_pub = usr_key.get_pub('lib'),
                            sender_pub_msg = usr_key.get_pub('msg'))
    newsig = Parser.sig21construct(file_data)
    return file_signature_encode(newsig)


def sign28type(your_id, file_data):
    usr_key = FormatKeys.Key(key_id = your_id)
    Parser = Parsing.Parser(type = 28, 
                            usr_priv = usr_key.get_priv('lib'), 
                            usr_pub = usr_key.get_pub('lib'),
                            sender_pub_msg = usr_key.get_pub('msg'))
    timestamp = int(time.time())
    newsig = Parser.sig28construct(file_data, timestamp)
    return file_signature_encode(newsig)


def verify7sig(data, sig):
    Parser = Parsing.Parser(type = 7)
    their_pub_msg = Parser.sig7deconstruct(data, sig)
    their_pub = FormatKeys.fmt_pub(their_pub_msg, 'msg2readable')
    their_pub_raw = FormatKeys.fmt_pub(their_pub_msg, 'msg2raw')
    their_id = FormatKeys.form_key_id(their_pub_raw)
    sig_info = form_sig_info(their_id, their_pub, data)
    status = 'Good message signature from: ' + their_id
    return status, sig_info


def verify14sig(data, sig):
    Parser = Parsing.Parser(type = 14)
    their_pub_msg, timestamp = Parser.sig14deconstruct(data, sig)
    their_pub = FormatKeys.fmt_pub(their_pub_msg, 'msg2readable')
    their_pub_raw = FormatKeys.fmt_pub(their_pub_msg, 'msg2raw')
    their_id = FormatKeys.form_key_id(their_pub_raw)
    timestamp_readable = time.ctime(timestamp)
    sig_info = form_sig_info(their_id, their_pub, data, timestamp_readable)
    status = 'Good message signature from: ' + their_id
    return status, sig_info


def verify21sig(data, sig):
    Parser = Parsing.Parser(type = 21)
    their_pub_msg = Parser.sig21deconstruct(data, sig)
    their_pub = FormatKeys.fmt_pub(their_pub_msg, 'msg2readable')
    their_pub_raw = FormatKeys.fmt_pub(their_pub_msg, 'msg2raw')
    their_id = FormatKeys.form_key_id(their_pub_raw)
    sig_info = form_sig_info(their_id, their_pub, data)
    status = 'Good file signature from: ' + their_id
    return status, sig_info


def verify28sig(data, sig):
    Parser = Parsing.Parser(type = 28)
    their_pub_msg, timestamp = Parser.sig28deconstruct(data, sig)
    their_pub = FormatKeys.fmt_pub(their_pub_msg, 'msg2readable')
    their_pub_raw = FormatKeys.fmt_pub(their_pub_msg, 'msg2raw')
    their_id = FormatKeys.form_key_id(their_pub_raw)
    timestamp_readable = time.ctime(timestamp)
    sig_info = form_sig_info(their_id, their_pub, data, timestamp_readable)
    status = 'Good file signature from: ' + their_id
    return status, sig_info




def message_encode(bin_msg):
    s = '-----BEGIN EC-CRYPT MESSAGE-----\n' 
    s += ascii_armor(bin_msg)
    s += '-----END EC-CRYPT MESSAGE-----'
    return s


def message_decode(mime_msg):
    begin_header = r'-----BEGIN EC-CRYPT MESSAGE-----'
    b64_encoding = r'([A-Za-z0-9+/=\n\s]+)'
    end_header = r'-----END EC-CRYPT MESSAGE-----'
    reg = re.compile(begin_header + b64_encoding + end_header, re.DOTALL|re.M)
    tag_match = reg.search(mime_msg)
    if tag_match:
        b64msg = (tag_match.group(1).strip())
    elif not tag_match:
        raise ECCryptException('Corrupted/invalid message - parsing failure!')
    try:
        message = binascii.a2b_base64(b64msg)
    except binascii.Error: 
        raise ECCryptException('Corrupted/invalid message - decoding failure!')
    return message


def msg_signature_encode(text, sig):
    s = u'-----BEGIN EC-CRYPT SIGNED MESSAGE-----\n'
    s += text.decode('utf-8')
    s += u'\n-----BEGIN EC-CRYPT SIGNATURE-----\n'
    s += ascii_armor(sig)
    s += u'-----END EC-CRYPT SIGNATURE-----'
    return s


def msg_signature_decode(msg):
    begin_header = r'-----BEGIN EC-CRYPT SIGNED MESSAGE-----'
    get_txt = r'(.*)'
    end_header = r'-----BEGIN EC-CRYPT SIGNATURE-----'
    reg1 = re.compile(begin_header + get_txt + end_header, re.DOTALL)
    text_tag_match = reg1.search(msg)
    if text_tag_match:
        h_text = (text_tag_match.group(0).strip())
        text = h_text[len(begin_header + '\n'):-len(end_header + '\n')]
    elif not text_tag_match:
        raise ECCryptException('Corrupted/invalid signature - parsing failure!')
    begin_header = r'-----BEGIN EC-CRYPT SIGNATURE-----'
    b64_encoding = r'([A-Za-z0-9+/=\n\s]+)'
    end_header = r'-----END EC-CRYPT SIGNATURE-----'
    reg2 = re.compile(begin_header + b64_encoding + end_header, re.DOTALL|re.M)
    b64_tag_match = reg2.search(msg)
    if b64_tag_match:
        b64_sig = (b64_tag_match.group(1).strip())
    elif not b64_tag_match:
        raise ECCryptException('Corrupted/invalid signature - parsing failure!')
    try:
        signature = binascii.a2b_base64(b64_sig)
    except binascii.Error: 
        raise ECCryptException('Corrupted/invalid signature - decoding failure!')
    return text, signature


def file_signature_encode(sig):
    s = u'-----BEGIN EC-CRYPT FILE SIGNATURE-----\n'
    s += ascii_armor(sig)
    s += u'-----END EC-CRYPT FILE SIGNATURE-----'
    return s


def file_signature_decode(mime_sig):
    begin_header = r'-----BEGIN EC-CRYPT FILE SIGNATURE-----'
    b64_encoding = r'([A-Za-z0-9+/=\n\s]+)'
    end_header = r'-----END EC-CRYPT FILE SIGNATURE-----'
    reg = re.compile(begin_header + b64_encoding + end_header, re.DOTALL|re.M)
    tag_match = reg.search(mime_sig)
    if tag_match:
        b64msg = (tag_match.group(1).strip())
    elif not tag_match:
        raise ECCryptException('Corrupted/invalid signature - parsing failure!')
    try:
        sig = binascii.a2b_base64(b64msg)
    except binascii.Error: 
        raise ECCryptException('Corrupted/invalid signature - decoding failure!')
    return sig


def form_msg_info(your_id, their_id, id_list, text, attach = None, attach_name = None):
    contact_known = FormatKeys.check_contact_identity(their_id)
    if contact_known is True:
        their_alias = FormatKeys.retrieve_contact_alias(their_id)
    elif contact_known is False:
        their_alias = ''
    s = u'Message from:     {} {}'.format(their_id, their_alias) + '\n'
    s += u'Decrypted with:   {}'.format(your_id) + '\n'
    s += u'Message for:      {}'.format(', '.join(id_list)) + '\n'
    s += u'Text length:      {} byte(s)'.format(len(bytes(text))) + '\n'
    if attach:
        s += u'Attachment:       {}'.format(attach_name) + '\n'
        s += u'Attachment size:  {} byte(s)'.format(len(attach)) + '\n'
    return s


def form_sig_info(their_id, their_pub, data, timestamp = None):
    contact_known = FormatKeys.check_contact_identity(their_id)
    if contact_known is True:
        their_alias = FormatKeys.retrieve_contact_alias(their_id)
    elif contact_known is False:
        their_alias = ''
    s = u'Signed by:  {} {}'.format(their_id, their_alias) + '\n'
    s += u'Public key: {}'.format(their_pub) + '\n'
    s += u'Data size:  {} byte(s)'.format(len(bytes(data))) + '\n'
    if timestamp:
        s += u'Signed on:  {}'.format(timestamp) + '\n'
    return s


def ascii_armor(s):
    line_length = 64
    binsize = (line_length // 4) * 3
    pieces = []
    for i in range(0, len(s), binsize):
        chunk = s[i : i + binsize]
        pieces.append(binascii.b2a_base64(chunk))
    return "".join(pieces)

