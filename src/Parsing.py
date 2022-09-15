from construct import *
import Crypto
import FormatKeys


class ECCryptException(Exception):
    def __init__(self, value):
        self.parameter = value
    def __str__(self):
        return repr(self.parameter)


class Parser:
    def __init__(self, usr_priv = None, usr_pub = None, 
                sender_pub_msg = None, type = None, message = None):
        if type is None and message is not None:
            self.type = type
        elif type is not None:
            self.type = type
        self.usr_priv = usr_priv
        self.usr_pub = usr_pub
        self.usr_pub_msg = sender_pub_msg


        '''Message structures that define message types. '''

        '''Signature string. '''
        self.sig = PascalString('signature', length_field = UBInt8('length'))

        '''Type 12 message. Identified, without attachment'''
        self.type12u = Struct('pre_signed',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))),
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('send_pub', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')), )
        self.type12s = Struct('msg',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('send_pub', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')),
            PascalString('signature', length_field = UBInt8('length')), )

        '''Type 24 message. Identified, with attachment'''
        self.type24u = Struct('pre_signed',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('send_pub', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')),
            PascalString('att', length_field = UBInt32('length')), )
        self.type24s = Struct('msg',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('send_pub', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')),
            PascalString('att', length_field = UBInt32('length')),
            PascalString('signature', length_field = UBInt8('length')), )

        '''Type 36 message, unidentified (incognito) without attachment'''
        self.type36u = Struct('pre_signed',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')), )
        self.type36s = Struct('msg',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')),
            PascalString('signature', length_field = UBInt8('length')), )

        '''Type 48 message, unidentified (incognito) with attachment'''
        self.type48u = Struct('pre_signed',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')),
            PascalString('att', length_field = UBInt32('length')), )
        self.type48s = Struct('msg',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('id_list', length_field = UBInt8('length'))),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('txt', length_field = UBInt32('length')),
            PascalString('att', length_field = UBInt32('length')),
            PascalString('signature', length_field = UBInt8('length')), )
        
        '''Type 60 message. Hides all other message types inside'''
        self.type60u = Struct('pre_signed',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('payload', length_field = UBInt32('length')), )
        self.type60s = Struct('msg',
            UBInt8('type'),
            UBInt8('rec_count'),
            Array(lambda ctx: ctx.rec_count, 
                PascalString('token_list', length_field = UBInt8('length'))), 
            PascalString('eph_key', length_field = UBInt8('length')),
            PascalString('payload', length_field = UBInt32('length')),
            PascalString('signature', length_field = UBInt8('length')), )


        '''Signature structures'''

        '''Signature type 7, signed text message with no timestamp'''
        self.sig7u = Struct('pre-signed', 
            UBInt8('type'),
            PascalString('send_pub', length_field = UBInt8('length')), )
        self.sig7s = Struct('msg', 
            UBInt8('type'),
            PascalString('send_pub', length_field = UBInt8('length')), 
            PascalString('signature', length_field = UBInt8('length')), )

        '''Signature type 14, signed text message with timestamp'''
        self.sig14u = Struct('pre-signed', 
            UBInt8('type'),
            UBInt32('timestamp'),
            PascalString('send_pub', length_field = UBInt8('length')), )
        self.sig14s = Struct('msg', 
            UBInt8('type'),
            UBInt32('timestamp'),
            PascalString('send_pub', length_field = UBInt8('length')), 
            PascalString('signature', length_field = UBInt8('length')), )

        '''Signature type 21, signed file with no timestamp'''
        self.sig21u = Struct('pre-signed', 
            UBInt8('type'),
            PascalString('send_pub', length_field = UBInt8('length')), )
        self.sig21s = Struct('msg', 
            UBInt8('type'),
            PascalString('send_pub', length_field = UBInt8('length')), 
            PascalString('signature', length_field = UBInt8('length')), )

        '''Signature type 28, signed file with timestamp'''
        self.sig28u = Struct('pre-signed', 
            UBInt8('type'),
            UBInt32('timestamp'),
            PascalString('send_pub', length_field = UBInt8('length')), )
        self.sig28s = Struct('msg', 
            UBInt8('type'),
            UBInt32('timestamp'),
            PascalString('send_pub', length_field = UBInt8('length')), 
            PascalString('signature', length_field = UBInt8('length')), )




    '''Message construction functions '''

    def type12construct(self, rec_id_list, ss_list, ephem_pub_msg, ciphertext):
        msg = self.type12u.build(Container(type = self.type,
                                            rec_count = len(rec_id_list),
                                            id_list = rec_id_list,
                                            token_list = ss_list,
                                            eph_key = ephem_pub_msg,
                                            send_pub = self.usr_pub_msg,
                                            txt = ciphertext))
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, msg)
        msg += self.sig.build(signature)
        return msg


    def type24construct(self, rec_id_list, ss_list, ephem_pub_msg, ciphertext, attach):
        msg = self.type24u.build(Container(type = self.type,
                                            rec_count = len(rec_id_list),
                                            id_list = rec_id_list,
                                            token_list = ss_list,
                                            eph_key = ephem_pub_msg,
                                            send_pub = self.usr_pub_msg,
                                            txt = ciphertext,
                                            att = attach))
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, msg)
        msg += self.sig.build(signature)
        return msg


    def type36construct(self, rec_id_list, ss_list, ephem_pub_msg, ciphertext):
        msg = self.type36u.build(Container(type = self.type,
                                            rec_count = len(rec_id_list),
                                            id_list = rec_id_list,
                                            token_list = ss_list,
                                            eph_key = ephem_pub_msg,
                                            txt = ciphertext))
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, msg)
        msg += self.sig.build(signature)
        return msg


    def type48construct(self, rec_id_list, ss_list, ephem_pub_msg, ciphertext, attach):
        msg = self.type48u.build(Container(type = self.type,
                                            rec_count = len(rec_id_list),
                                            id_list = rec_id_list,
                                            token_list = ss_list,
                                            eph_key = ephem_pub_msg,
                                            txt = ciphertext,
                                            att = attach))
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, msg)
        msg += self.sig.build(signature)
        return msg


    def type60construct(self, ss_list, ephem_pub_msg, payload_msg):
        msg = self.type60u.build(Container(type = self.type,
                                            rec_count = len(ss_list),
                                            token_list = ss_list,
                                            eph_key = ephem_pub_msg,
                                            payload = payload_msg))
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, msg)
        msg += self.sig.build(signature)
        return msg


    '''Message deconstruction functions'''

    def type12deconstruct(self, message):
        try:
            msg = self.type12s.parse(message)
            msg2verify = self.type12u.build(Container(type = self.type,
                                            rec_count = msg.rec_count,
                                            id_list = msg.id_list,
                                            token_list = msg.token_list,
                                            eph_key = msg.eph_key,
                                            send_pub = msg.send_pub,
                                            txt = msg.txt))
            pubkey_lib = FormatKeys.fmt_pub(msg.send_pub, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, msg.signature, msg2verify) is True:
                return msg.send_pub, msg.eph_key, msg.id_list, msg.token_list, msg.txt
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def type24deconstruct(self, message):
        try:
            msg = self.type24s.parse(message)
            msg2verify = self.type24u.build(Container(type = self.type,
                                            rec_count = msg.rec_count,
                                            id_list = msg.id_list,
                                            token_list = msg.token_list,
                                            eph_key = msg.eph_key,
                                            send_pub = msg.send_pub,
                                            txt = msg.txt,
                                            att = msg.att))
            pubkey_lib = FormatKeys.fmt_pub(msg.send_pub, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, msg.signature, msg2verify) is True:
                return msg.send_pub, msg.eph_key, msg.id_list, msg.token_list, msg.txt, msg.att
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def type36deconstruct(self, message):
        try:
            msg = self.type36s.parse(message)
            msg2verify = self.type36u.build(Container(type = self.type,
                                            rec_count = msg.rec_count,
                                            id_list = msg.id_list,
                                            token_list = msg.token_list,
                                            eph_key = msg.eph_key,
                                            txt = msg.txt))
            pubkey_lib = FormatKeys.fmt_pub(msg.eph_key, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, msg.signature, msg2verify) is True:
                return msg.eph_key, msg.id_list, msg.token_list, msg.txt
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def type48deconstruct(self, message):
        try:
            msg = self.type48s.parse(message)
            msg2verify = self.type48u.build(Container(type = self.type,
                                            rec_count = msg.rec_count,
                                            id_list = msg.id_list,
                                            token_list = msg.token_list,
                                            eph_key = msg.eph_key,
                                            txt = msg.txt,
                                            att = msg.att))
            pubkey_lib = FormatKeys.fmt_pub(msg.eph_key, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, msg.signature, msg2verify) is True:
                return msg.eph_key, msg.id_list, msg.token_list, msg.txt, msg.att
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def type60deconstruct(self, message):
        try:
            msg = self.type60s.parse(message)
            msg2verify = self.type60u.build(Container(type = self.type,
                                                        rec_count = msg.rec_count,
                                                        token_list = msg.token_list,
                                                        eph_key = msg.eph_key,
                                                        payload = msg.payload))
            pubkey_lib = FormatKeys.fmt_pub(msg.eph_key, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, msg.signature, msg2verify) is True:
                return msg.eph_key, msg.token_list, msg.payload
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    '''Signature construction functions'''

    def sig7construct(self, data):
        sig_md = self.sig7u.build(Container(type = self.type,
                                            send_pub = self.usr_pub_msg))
        data += sig_md
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, data)
        sig_md += self.sig.build(signature)
        return sig_md


    def sig14construct(self, data, time):
        sig_md = self.sig14u.build(Container(type = self.type,
                                            timestamp = time,
                                            send_pub = self.usr_pub_msg))
        data += sig_md
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, data)
        sig_md += self.sig.build(signature)
        return sig_md


    def sig21construct(self, data):
        sig_md = self.sig21u.build(Container(type = self.type,
                                            send_pub = self.usr_pub_msg))
        data += sig_md
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, data)
        sig_md += self.sig.build(signature)
        return sig_md


    def sig28construct(self, data, time):
        sig_md = self.sig28u.build(Container(type = self.type,
                                            timestamp = time,
                                            send_pub = self.usr_pub_msg))
        data += sig_md
        signature = Crypto.make_sig(self.usr_priv, self.usr_pub, data)
        sig_md += self.sig.build(signature)
        return sig_md


    '''Signature deconstruction functions'''

    def sig7deconstruct(self, data, sig_md):
        try:
            sig = self.sig7s.parse(sig_md)
            sig2verify = self.sig7u.build(Container(type = sig.type,
                                                    send_pub = sig.send_pub))
            data += sig2verify
            pubkey_lib = FormatKeys.fmt_pub(sig.send_pub, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, sig.signature, data) is True:
                return sig.send_pub
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def sig14deconstruct(self, data, sig_md):
        try:
            sig = self.sig14s.parse(sig_md)
            sig2verify = self.sig14u.build(Container(type = sig.type,
                                                    timestamp = sig.timestamp,
                                                    send_pub = sig.send_pub))
            data += sig2verify
            pubkey_lib = FormatKeys.fmt_pub(sig.send_pub, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, sig.signature, data) is True:
                return sig.send_pub, sig.timestamp
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def sig21deconstruct(self, data, sig_md):
        try:
            sig = self.sig21s.parse(sig_md)
            sig2verify = self.sig21u.build(Container(type = sig.type,
                                                    send_pub = sig.send_pub))
            data += sig2verify
            pubkey_lib = FormatKeys.fmt_pub(sig.send_pub, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, sig.signature, data) is True:
                return sig.send_pub
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')


    def sig28deconstruct(self, data, sig_md):
        try:
            sig = self.sig28s.parse(sig_md)
            sig2verify = self.sig28u.build(Container(type = sig.type,
                                                    timestamp = sig.timestamp,
                                                    send_pub = sig.send_pub))
            data += sig2verify
            pubkey_lib = FormatKeys.fmt_pub(sig.send_pub, 'msg2lib')
            if Crypto.verify_sig(pubkey_lib, sig.signature, data) is True:
                return sig.send_pub, sig.timestamp
            else:
                raise ECCryptException('Corrupted message - signature failure!')
        except (FieldError, AttributeError, OverflowError):
            raise ECCryptException('Corrupted message - parsing failure!')




import ConfigParser


class UnicodeConfigParser(ConfigParser.RawConfigParser):
 
    def __init__(self, *args, **kwargs):
        ConfigParser.RawConfigParser.__init__(self, *args, **kwargs)
 
    def write(self, fp):
        """Fixed for Unicode output"""
        if self._defaults:
            fp.write("[%s]\n" % DEFAULTSECT)
            for (key, value) in self._defaults.items():
                fp.write("%s = %s\n" % (key, unicode(value).replace('\n', '\n\t')))
            fp.write("\n")
        for section in self._sections:
            fp.write("[%s]\n" % section)
            for (key, value) in self._sections[section].items():
                if key != "__name__":
                    fp.write("%s = %s\n" %
                             (key, unicode(value).replace('\n','\n\t')))
            fp.write("\n")
 
    # This function is needed to override default lower-case conversion
    # of the parameter's names. They will be saved 'as is'.
    def optionxform(self, strOut):
        return strOut

