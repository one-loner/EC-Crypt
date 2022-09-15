import os
import sys
import Crypto
import FormatKeys
import Messaging
import Parsing
from PyQt4 import QtCore, QtGui




try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)


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



''' Qt GUI class. All this messy code is generated automatically '''

class Ui_ECcrypt(QtGui.QMainWindow):

    def __init__(self):
        '''Load Master Keys and Contacts.'''
        self.contact_id_list = FormatKeys.retrieve_contactkey_id_list()
        self.master_key_list = FormatKeys.retrieve_masterkey_id_list()
        self.encrypt_for_list = []
        self.delete_contact_list = []
        self.delete_masterkey_list = []
        '''Set attachment and file to decrypt to (default) None'''
        self.attach_to_encrypt = None
        self.file_to_decrypt = None
        '''Set key indexes for dropdowns (comboboxes)'''
        self.chosen_enc_masterkey_id = 'Choose Master Key'
        self.chosen_sig_masterkey_id = 'Choose Master Key'

        QtGui.QMainWindow.__init__(self)
        self.setupUi(self)

    def setupUi(self, ECcrypt):
        ECcrypt.setObjectName(_fromUtf8("ECcrypt"))
        ECcrypt.resize(900, 520)
        font = QtGui.QFont()
        font.setFamily(_fromUtf8("Courier New"))
        font.setPointSize(8)
        self.centralwidget = QtGui.QWidget(ECcrypt)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.gridLayout = QtGui.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.tabWidget = QtGui.QTabWidget(self.centralwidget)
        self.tabWidget.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tabWidget.sizePolicy().hasHeightForWidth())
        self.tabWidget.setSizePolicy(sizePolicy)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.tab_newMsg = QtGui.QWidget()
        self.tab_newMsg.setObjectName(_fromUtf8("tab_newMsg"))
        self.gridLayout_2 = QtGui.QGridLayout(self.tab_newMsg)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.groupBox_EncryptionOpt = QtGui.QGroupBox(self.tab_newMsg)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_EncryptionOpt.sizePolicy().hasHeightForWidth())
        self.groupBox_EncryptionOpt.setSizePolicy(sizePolicy)
        self.groupBox_EncryptionOpt.setObjectName(_fromUtf8("groupBox_EncryptionOpt"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.groupBox_EncryptionOpt)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.radioButtonNormalType = QtGui.QRadioButton(self.groupBox_EncryptionOpt)
        self.radioButtonNormalType.setObjectName(_fromUtf8("radioButtonNormalType"))
        self.verticalLayout_2.addWidget(self.radioButtonNormalType)
        self.radioButtonIncognitoType = QtGui.QRadioButton(self.groupBox_EncryptionOpt)
        self.radioButtonIncognitoType.setObjectName(_fromUtf8("radioButtonIncognitoType"))
        self.verticalLayout_2.addWidget(self.radioButtonIncognitoType)
        self.checkBoxHideIDs = QtGui.QCheckBox(self.groupBox_EncryptionOpt)
        self.checkBoxHideIDs.setObjectName(_fromUtf8("checkBoxHideIDs"))
        self.verticalLayout_2.addWidget(self.checkBoxHideIDs)
        self.gridLayout_2.addWidget(self.groupBox_EncryptionOpt, 3, 0, 1, 2)
        self.groupBox_MsgInput = QtGui.QGroupBox(self.tab_newMsg)
        self.groupBox_MsgInput.setObjectName(_fromUtf8("groupBox_MsgInput"))
        self.gridLayout_12 = QtGui.QGridLayout(self.groupBox_MsgInput)
        self.gridLayout_12.setObjectName(_fromUtf8("gridLayout_12"))
        self.label_ch_attach = QtGui.QLabel(self.groupBox_MsgInput)
        self.label_ch_attach.setObjectName(_fromUtf8("label_ch_attach"))
        self.gridLayout_12.addWidget(self.label_ch_attach, 2, 0, 1, 1)
        self.pushButtonResetAttach = QtGui.QPushButton(self.groupBox_MsgInput)
        self.pushButtonResetAttach.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonResetAttach.sizePolicy().hasHeightForWidth())
        self.pushButtonResetAttach.setSizePolicy(sizePolicy)
        self.pushButtonResetAttach.setMaximumSize(QtCore.QSize(40, 16777215))
        self.pushButtonResetAttach.setObjectName(_fromUtf8("pushButtonResetAttach"))
        self.gridLayout_12.addWidget(self.pushButtonResetAttach, 2, 5, 1, 1)
        self.toolButtonChooseAttach = QtGui.QToolButton(self.groupBox_MsgInput)
        self.toolButtonChooseAttach.setObjectName(_fromUtf8("toolButtonChooseAttach"))
        self.gridLayout_12.addWidget(self.toolButtonChooseAttach, 2, 1, 1, 1)
        self.lineAttachPath = QtGui.QLineEdit(self.groupBox_MsgInput)
        self.lineAttachPath.setReadOnly(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.lineAttachPath.sizePolicy().hasHeightForWidth())
        self.lineAttachPath.setSizePolicy(sizePolicy)
        self.lineAttachPath.setObjectName(_fromUtf8("lineAttachPath"))
        self.gridLayout_12.addWidget(self.lineAttachPath, 2, 2, 1, 3)
        self.inputMessageBox = QtGui.QPlainTextEdit(self.groupBox_MsgInput)
        self.inputMessageBox.setFont(font)
        self.inputMessageBox.setObjectName(_fromUtf8("inputMessageBox"))
        self.gridLayout_12.addWidget(self.inputMessageBox, 1, 0, 1, 6)
        self.gridLayout_2.addWidget(self.groupBox_MsgInput, 5, 0, 1, 8)
        self.groupBox_Keys = QtGui.QGroupBox(self.tab_newMsg)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_Keys.sizePolicy().hasHeightForWidth())
        self.groupBox_Keys.setSizePolicy(sizePolicy)
        self.groupBox_Keys.setObjectName(_fromUtf8("groupBox_Keys"))
        self.gridLayout_11 = QtGui.QGridLayout(self.groupBox_Keys)
        self.gridLayout_11.setObjectName(_fromUtf8("gridLayout_11"))
        self.tableWidgetContacts = QtGui.QTableWidget(self.groupBox_Keys)
        self.tableWidgetContacts.setEnabled(True)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidgetContacts.sizePolicy().hasHeightForWidth())
        self.tableWidgetContacts.setSizePolicy(sizePolicy)
        self.tableWidgetContacts.setColumnCount(4)
        self.tableWidgetContacts.setObjectName(_fromUtf8("tableWidgetContacts"))
        self.tableWidgetContacts.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignVCenter|QtCore.Qt.AlignCenter)
        self.tableWidgetContacts.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetContacts.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetContacts.setHorizontalHeaderItem(2, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetContacts.setHorizontalHeaderItem(3, item)
        self.gridLayout_11.addWidget(self.tableWidgetContacts, 5, 0, 1, 1)
        self.choosePrivkey = QtGui.QComboBox(self.groupBox_Keys)
        self.choosePrivkey.setEnabled(True)
        self.choosePrivkey.setEditable(False)
        self.choosePrivkey.setSizeAdjustPolicy(QtGui.QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.choosePrivkey.setDuplicatesEnabled(False)
        self.choosePrivkey.setFrame(True)
        self.choosePrivkey.setObjectName(_fromUtf8("choosePrivkey"))
        self.gridLayout_11.addWidget(self.choosePrivkey, 3, 0, 1, 1)
        self.label_encryptfor = QtGui.QLabel(self.groupBox_Keys)
        self.label_encryptfor.setObjectName(_fromUtf8("label_encryptfor"))
        self.gridLayout_11.addWidget(self.label_encryptfor, 4, 0, 1, 1)
        self.label_from = QtGui.QLabel(self.groupBox_Keys)
        self.label_from.setObjectName(_fromUtf8("label_from"))
        self.gridLayout_11.addWidget(self.label_from, 2, 0, 1, 1)
        self.gridLayout_2.addWidget(self.groupBox_Keys, 3, 8, 4, 1)
        self.groupBox_OutputOpt = QtGui.QGroupBox(self.tab_newMsg)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_OutputOpt.sizePolicy().hasHeightForWidth())
        self.groupBox_OutputOpt.setSizePolicy(sizePolicy)
        self.groupBox_OutputOpt.setObjectName(_fromUtf8("groupBox_OutputOpt"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.groupBox_OutputOpt)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.radioButtonMimeEncode = QtGui.QRadioButton(self.groupBox_OutputOpt)
        self.radioButtonMimeEncode.setObjectName(_fromUtf8("radioButtonMimeEncode"))
        self.verticalLayout_3.addWidget(self.radioButtonMimeEncode)
        self.radioButtonToFile = QtGui.QRadioButton(self.groupBox_OutputOpt)
        self.radioButtonToFile.setObjectName(_fromUtf8("radioButtonToFile"))
        self.verticalLayout_3.addWidget(self.radioButtonToFile)
        self.gridLayout_2.addWidget(self.groupBox_OutputOpt, 3, 2, 1, 1)
        self.pushButtonEncrypt = QtGui.QPushButton(self.tab_newMsg)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonEncrypt.sizePolicy().hasHeightForWidth())
        self.pushButtonEncrypt.setSizePolicy(sizePolicy)
        self.pushButtonEncrypt.setObjectName(_fromUtf8("pushButtonEncrypt"))
        self.gridLayout_2.addWidget(self.pushButtonEncrypt, 6, 0, 1, 1)
        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_2.addItem(spacerItem, 3, 5, 1, 1)
        self.tabWidget.addTab(self.tab_newMsg, _fromUtf8(""))
        self.tab_DecryptMsg = QtGui.QWidget()
        self.tab_DecryptMsg.setObjectName(_fromUtf8("tab_DecryptMsg"))
        self.gridLayout_3 = QtGui.QGridLayout(self.tab_DecryptMsg)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.pushButtonDecrypt = QtGui.QPushButton(self.tab_DecryptMsg)
        self.pushButtonDecrypt.setObjectName(_fromUtf8("pushButtonDecrypt"))
        self.gridLayout_3.addWidget(self.pushButtonDecrypt, 6, 0, 1, 1, QtCore.Qt.AlignLeft)
        self.groupBox_DecrMsg = QtGui.QGroupBox(self.tab_DecryptMsg)
        self.groupBox_DecrMsg.setObjectName(_fromUtf8("groupBox_DecrMsg"))
        self.gridLayout_14 = QtGui.QGridLayout(self.groupBox_DecrMsg)
        self.gridLayout_14.setObjectName(_fromUtf8("gridLayout_14"))
        self.textDecryptedMessageDisplay = QtGui.QPlainTextEdit(self.groupBox_DecrMsg)
        self.textDecryptedMessageDisplay.setReadOnly(True)
        self.textDecryptedMessageDisplay.setFont(font)
        self.textDecryptedMessageDisplay.setObjectName(_fromUtf8("textDecryptedMessageDisplay"))
        self.gridLayout_14.addWidget(self.textDecryptedMessageDisplay, 0, 0, 1, 1)
        self.gridLayout_3.addWidget(self.groupBox_DecrMsg, 5, 0, 1, 2)
        self.groupBox_DecMsgInfo = QtGui.QGroupBox(self.tab_DecryptMsg)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_DecMsgInfo.sizePolicy().hasHeightForWidth())
        self.groupBox_DecMsgInfo.setSizePolicy(sizePolicy)
        self.groupBox_DecMsgInfo.setObjectName(_fromUtf8("groupBox_DecMsgInfo"))
        self.formLayout = QtGui.QFormLayout(self.groupBox_DecMsgInfo)
        self.formLayout.setObjectName(_fromUtf8("formLayout"))
        self.label_decr_info = QtGui.QLabel(self.groupBox_DecMsgInfo)
        self.label_decr_info.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.label_decr_info.setFont(font)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_decr_info.sizePolicy().hasHeightForWidth())
        self.label_decr_info.setSizePolicy(sizePolicy)
        self.label_decr_info.setObjectName(_fromUtf8("label_decr_info"))
        self.formLayout.setWidget(0, QtGui.QFormLayout.LabelRole, self.label_decr_info)
        self.gridLayout_3.addWidget(self.groupBox_DecMsgInfo, 3, 1, 2, 1)
        self.groupBox_DecryptionOpt = QtGui.QGroupBox(self.tab_DecryptMsg)
        self.groupBox_DecryptionOpt.setObjectName(_fromUtf8("groupBox_DecryptionOpt"))
        self.gridLayout_13 = QtGui.QGridLayout(self.groupBox_DecryptionOpt)
        self.gridLayout_13.setObjectName(_fromUtf8("gridLayout_13"))
        self.toolButtonChooseDecryptFile = QtGui.QToolButton(self.groupBox_DecryptionOpt)
        self.toolButtonChooseDecryptFile.setObjectName(_fromUtf8("toolButtonChooseDecryptFile"))
        self.gridLayout_13.addWidget(self.toolButtonChooseDecryptFile, 2, 1, 1, 1)
        self.radioButton_DecryptFile = QtGui.QRadioButton(self.groupBox_DecryptionOpt)
        self.radioButton_DecryptFile.setObjectName(_fromUtf8("radioButton_DecryptFile"))
        self.gridLayout_13.addWidget(self.radioButton_DecryptFile, 1, 0, 1, 1)
        self.pushButtonResetDecryption = QtGui.QPushButton(self.groupBox_DecryptionOpt)
        self.gridLayout_13.addWidget(self.pushButtonResetDecryption, 2, 8, 1, 1)
        self.lineDecryptionFilePath = QtGui.QLineEdit(self.groupBox_DecryptionOpt)
        self.lineDecryptionFilePath.setReadOnly(True)
        self.lineDecryptionFilePath.setObjectName(_fromUtf8("lineDecryptionFilePath"))
        self.gridLayout_13.addWidget(self.lineDecryptionFilePath, 2, 2, 1, 1)
        self.label_ch_file = QtGui.QLabel(self.groupBox_DecryptionOpt)
        self.label_ch_file.setMaximumSize(QtCore.QSize(180, 16777215))
        self.label_ch_file.setObjectName(_fromUtf8("label_ch_file"))
        self.gridLayout_13.addWidget(self.label_ch_file, 2, 0, 1, 1)
        self.radioButton_DecryptMime = QtGui.QRadioButton(self.groupBox_DecryptionOpt)
        self.radioButton_DecryptMime.setObjectName(_fromUtf8("radioButton_DecryptMime"))
        self.gridLayout_13.addWidget(self.radioButton_DecryptMime, 0, 0, 1, 1)
        self.gridLayout_3.addWidget(self.groupBox_DecryptionOpt, 3, 0, 2, 1)
        self.tabWidget.addTab(self.tab_DecryptMsg, _fromUtf8(""))
        self.tab_Sign = QtGui.QWidget()
        self.tab_Sign.setObjectName(_fromUtf8("tab_Sign"))
        self.gridLayout_20 = QtGui.QGridLayout(self.tab_Sign)
        self.gridLayout_20.setObjectName(_fromUtf8("gridLayout_20"))
        self.groupBox_SignOpt = QtGui.QGroupBox(self.tab_Sign)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_SignOpt.sizePolicy().hasHeightForWidth())
        self.groupBox_SignOpt.setSizePolicy(sizePolicy)
        self.groupBox_SignOpt.setObjectName(_fromUtf8("groupBox_SignOpt"))
        self.gridLayout_17 = QtGui.QGridLayout(self.groupBox_SignOpt)
        self.gridLayout_17.setObjectName(_fromUtf8("gridLayout_17"))
        self.toolButtonChooseSignFile = QtGui.QToolButton(self.groupBox_SignOpt)
        self.toolButtonChooseSignFile.setObjectName(_fromUtf8("toolButtonChooseSignFile"))
        self.gridLayout_17.addWidget(self.toolButtonChooseSignFile, 3, 1, 1, 1)
        self.radioButton_SignMessage = QtGui.QRadioButton(self.groupBox_SignOpt)
        self.radioButton_SignMessage.setObjectName(_fromUtf8("radioButton_SignMessage"))
        self.gridLayout_17.addWidget(self.radioButton_SignMessage, 1, 0, 1, 1)
        self.radioButton_SignFile = QtGui.QRadioButton(self.groupBox_SignOpt)
        self.radioButton_SignFile.setObjectName(_fromUtf8("radioButton_SignFile"))
        self.gridLayout_17.addWidget(self.radioButton_SignFile, 2, 0, 1, 1)
        self.label_ch_sig_file = QtGui.QLabel(self.groupBox_SignOpt)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_ch_sig_file.sizePolicy().hasHeightForWidth())
        self.label_ch_sig_file.setSizePolicy(sizePolicy)
        self.label_ch_sig_file.setMaximumSize(QtCore.QSize(180, 16777215))
        self.label_ch_sig_file.setObjectName(_fromUtf8("label_ch_sig_file"))
        self.gridLayout_17.addWidget(self.label_ch_sig_file, 3, 0, 1, 1)
        self.lineEditSigFilePath = QtGui.QLineEdit(self.groupBox_SignOpt)
        self.lineEditSigFilePath.setReadOnly(True)
        self.lineEditSigFilePath.setObjectName(_fromUtf8("lineEditSigFilePath"))
        self.gridLayout_17.addWidget(self.lineEditSigFilePath, 3, 2, 1, 1)
        self.pushButtonResetSigFile = QtGui.QPushButton(self.groupBox_SignOpt)
        self.pushButtonResetSigFile.setMaximumSize(QtCore.QSize(40, 16777215))
        self.pushButtonResetSigFile.setObjectName(_fromUtf8("pushButtonResetSigFile"))
        self.gridLayout_17.addWidget(self.pushButtonResetSigFile, 3, 3, 1, 1)
        self.checkBoxIncludeTime = QtGui.QCheckBox(self.groupBox_SignOpt)
        self.checkBoxIncludeTime.setObjectName(_fromUtf8("checkBoxIncludeTime"))
        self.gridLayout_17.addWidget(self.checkBoxIncludeTime, 4, 0, 1, 2)
        self.gridLayout_20.addWidget(self.groupBox_SignOpt, 0, 0, 1, 1)
        self.groupBox_SigKey = QtGui.QGroupBox(self.tab_Sign)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_SigKey.sizePolicy().hasHeightForWidth())
        self.groupBox_SigKey.setSizePolicy(sizePolicy)
        self.groupBox_SigKey.setObjectName(_fromUtf8("groupBox_SigKey"))
        self.gridLayout_19 = QtGui.QGridLayout(self.groupBox_SigKey)
        self.gridLayout_19.setObjectName(_fromUtf8("gridLayout_19"))
        self.chooseSigningKey = QtGui.QComboBox(self.groupBox_SigKey)
        self.chooseSigningKey.setObjectName(_fromUtf8("chooseSigningKey"))
        self.gridLayout_19.addWidget(self.chooseSigningKey, 0, 0, 1, 1)
        self.gridLayout_20.addWidget(self.groupBox_SigKey, 0, 1, 1, 1)
        self.pushButtonSign = QtGui.QPushButton(self.tab_Sign)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonSign.sizePolicy().hasHeightForWidth())
        self.pushButtonSign.setSizePolicy(sizePolicy)
        self.pushButtonSign.setObjectName(_fromUtf8("pushButtonSign"))
        self.gridLayout_20.addWidget(self.pushButtonSign, 2, 0, 1, 1)
        self.groupBoxSignMessage = QtGui.QGroupBox(self.tab_Sign)
        self.groupBoxSignMessage.setObjectName(_fromUtf8("groupBoxSignMessage"))
        self.gridLayout_18 = QtGui.QGridLayout(self.groupBoxSignMessage)
        self.gridLayout_18.setObjectName(_fromUtf8("gridLayout_18"))
        self.plainTextEditSigInput = QtGui.QPlainTextEdit(self.groupBoxSignMessage)
        self.plainTextEditSigInput.setFont(font)
        self.plainTextEditSigInput.setObjectName(_fromUtf8("plainTextEditSigInput"))
        self.gridLayout_18.addWidget(self.plainTextEditSigInput, 0, 0, 1, 1)
        self.gridLayout_20.addWidget(self.groupBoxSignMessage, 1, 0, 1, 2)
        self.tabWidget.addTab(self.tab_Sign, _fromUtf8(""))
        self.tab_Verify = QtGui.QWidget()
        self.tab_Verify.setObjectName(_fromUtf8("tab_Verify"))
        self.gridLayout_23 = QtGui.QGridLayout(self.tab_Verify)
        self.gridLayout_23.setObjectName(_fromUtf8("gridLayout_23"))
        self.groupBoxVerOptions = QtGui.QGroupBox(self.tab_Verify)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBoxVerOptions.sizePolicy().hasHeightForWidth())
        self.groupBoxVerOptions.setSizePolicy(sizePolicy)
        self.groupBoxVerOptions.setObjectName(_fromUtf8("groupBoxVerOptions"))
        self.gridLayout_21 = QtGui.QGridLayout(self.groupBoxVerOptions)
        self.gridLayout_21.setObjectName(_fromUtf8("gridLayout_21"))
        self.radioButtonVerifyMessage = QtGui.QRadioButton(self.groupBoxVerOptions)
        self.radioButtonVerifyMessage.setObjectName(_fromUtf8("radioButtonVerifyMessage"))
        self.gridLayout_21.addWidget(self.radioButtonVerifyMessage, 0, 0, 1, 2)
        self.radioButtonVerifyFileSig = QtGui.QRadioButton(self.groupBoxVerOptions)
        self.radioButtonVerifyFileSig.setObjectName(_fromUtf8("radioButtonVerifyFileSig"))
        self.gridLayout_21.addWidget(self.radioButtonVerifyFileSig, 1, 0, 1, 1)
        self.label_ch_ver_file = QtGui.QLabel(self.groupBoxVerOptions)
        self.label_ch_ver_file.setObjectName(_fromUtf8("label_ch_ver_file"))
        self.gridLayout_21.addWidget(self.label_ch_ver_file, 2, 0, 1, 1)
        self.toolButtonChooseVerFile = QtGui.QToolButton(self.groupBoxVerOptions)
        self.toolButtonChooseVerFile.setObjectName(_fromUtf8("toolButtonChooseVerFile"))
        self.gridLayout_21.addWidget(self.toolButtonChooseVerFile, 2, 1, 1, 1)
        self.lineEditVerFilePath = QtGui.QLineEdit(self.groupBoxVerOptions)
        self.lineEditVerFilePath.setReadOnly(True)
        self.lineEditVerFilePath.setObjectName(_fromUtf8("lineEditVerFilePath"))
        self.gridLayout_21.addWidget(self.lineEditVerFilePath, 2, 2, 1, 1)
        self.pushButtonResetVerFile = QtGui.QPushButton(self.groupBoxVerOptions)
        self.pushButtonResetVerFile.setMaximumSize(QtCore.QSize(40, 16777215))
        self.pushButtonResetVerFile.setObjectName(_fromUtf8("pushButtonResetVerFile"))
        self.gridLayout_21.addWidget(self.pushButtonResetVerFile, 2, 3, 1, 1)
        self.label_ch_ver_sig = QtGui.QLabel(self.groupBoxVerOptions)
        self.label_ch_ver_sig.setObjectName(_fromUtf8("label_ch_ver_sig"))
        self.gridLayout_21.addWidget(self.label_ch_ver_sig, 3, 0, 1, 1)
        self.toolButtonChooseVerSig = QtGui.QToolButton(self.groupBoxVerOptions)
        self.toolButtonChooseVerSig.setObjectName(_fromUtf8("toolButtonChooseVerSig"))
        self.gridLayout_21.addWidget(self.toolButtonChooseVerSig, 3, 1, 1, 1)
        self.lineEditVerSigPath = QtGui.QLineEdit(self.groupBoxVerOptions)
        self.lineEditVerSigPath.setReadOnly(True)
        self.lineEditVerSigPath.setObjectName(_fromUtf8("lineEditVerSigPath"))
        self.gridLayout_21.addWidget(self.lineEditVerSigPath, 3, 2, 1, 1)
        self.pushButtonResetVerSig = QtGui.QPushButton(self.groupBoxVerOptions)
        self.pushButtonResetVerSig.setMaximumSize(QtCore.QSize(40, 16777215))
        self.pushButtonResetVerSig.setObjectName(_fromUtf8("pushButtonResetVerSig"))
        self.gridLayout_21.addWidget(self.pushButtonResetVerSig, 3, 3, 1, 1)
        self.gridLayout_23.addWidget(self.groupBoxVerOptions, 1, 0, 1, 1, QtCore.Qt.AlignTop)
        self.groupBoxVerMessageInput = QtGui.QGroupBox(self.tab_Verify)
        self.groupBoxVerMessageInput.setObjectName(_fromUtf8("groupBoxVerMessageInput"))
        self.gridLayout_22 = QtGui.QGridLayout(self.groupBoxVerMessageInput)
        self.gridLayout_22.setObjectName(_fromUtf8("gridLayout_22"))
        self.plainTextEditVerifyInput = QtGui.QPlainTextEdit(self.groupBoxVerMessageInput)
        self.plainTextEditVerifyInput.setFont(font)
        self.plainTextEditVerifyInput.setObjectName(_fromUtf8("plainTextEditVerifyInput"))
        self.gridLayout_22.addWidget(self.plainTextEditVerifyInput, 0, 0, 1, 1)
        self.pushButtonVerify = QtGui.QPushButton(self.tab_Verify)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonVerify.sizePolicy().hasHeightForWidth())
        self.pushButtonVerify.setSizePolicy(sizePolicy)
        self.pushButtonVerify.setObjectName(_fromUtf8("pushButtonVerify"))
        self.gridLayout_23.addWidget(self.pushButtonVerify, 3, 0, 1, 1)
        self.gridLayout_23.addWidget(self.groupBoxVerMessageInput, 2, 0, 1, 2)
        self.groupBoxVerifyInfo = QtGui.QGroupBox(self.tab_Verify)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBoxVerifyInfo.sizePolicy().hasHeightForWidth())
        self.groupBoxVerifyInfo.setSizePolicy(sizePolicy)
        self.groupBoxVerifyInfo.setObjectName(_fromUtf8("groupBoxVerifyInfo"))
        self.gridLayout_24 = QtGui.QGridLayout(self.groupBoxVerifyInfo)
        self.gridLayout_24.setObjectName(_fromUtf8("gridLayout_24"))
        self.label_ver_info = QtGui.QLabel(self.groupBoxVerifyInfo)
        self.label_ver_info.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.label_ver_info.setFont(font)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label_ver_info.sizePolicy().hasHeightForWidth())
        self.label_ver_info.setSizePolicy(sizePolicy)
        self.label_ver_info.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.label_ver_info.setObjectName(_fromUtf8("label_ver_info"))
        self.gridLayout_24.addWidget(self.label_ver_info, 0, 0, 1, 1)
        self.gridLayout_23.addWidget(self.groupBoxVerifyInfo, 1, 1, 1, 1)
        self.tabWidget.addTab(self.tab_Verify, _fromUtf8(""))
        self.tab_ManageKeys = QtGui.QWidget()
        self.tab_ManageKeys.setEnabled(True)
        self.tab_ManageKeys.setObjectName(_fromUtf8("tab_ManageKeys"))
        self.gridLayout_16 = QtGui.QGridLayout(self.tab_ManageKeys)
        self.gridLayout_16.setObjectName(_fromUtf8("gridLayout_16"))
        self.groupBox_EditDisplayKeys = QtGui.QGroupBox(self.tab_ManageKeys)
        self.groupBox_EditDisplayKeys.setObjectName(_fromUtf8("groupBox_EditDisplayKeys"))
        self.gridLayout_6 = QtGui.QGridLayout(self.groupBox_EditDisplayKeys)
        self.gridLayout_6.setObjectName(_fromUtf8("gridLayout_6"))
        self.lineDisplayMasterPublic = QtGui.QLineEdit(self.groupBox_EditDisplayKeys)
        self.lineDisplayMasterPublic.setReadOnly(True)
        self.lineDisplayMasterPublic.setObjectName(_fromUtf8("lineDisplayMasterPublic"))
        self.gridLayout_6.addWidget(self.lineDisplayMasterPublic, 2, 1, 1, 2)
        self.chooseMasterkeyToDisplay = QtGui.QComboBox(self.groupBox_EditDisplayKeys)
        self.chooseMasterkeyToDisplay.setObjectName(_fromUtf8("chooseMasterkeyToDisplay"))
        self.gridLayout_6.addWidget(self.chooseMasterkeyToDisplay, 0, 1, 2, 3)
        self.label_pub_here = QtGui.QLabel(self.groupBox_EditDisplayKeys)
        self.label_pub_here.setObjectName(_fromUtf8("label_pub_here"))
        self.gridLayout_6.addWidget(self.label_pub_here, 2, 0, 1, 1)
        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_6.addItem(spacerItem1, 4, 1, 1, 1)
        self.label_ch_ed_key = QtGui.QLabel(self.groupBox_EditDisplayKeys)
        self.label_ch_ed_key.setObjectName(_fromUtf8("label_ch_ed_key"))
        self.gridLayout_6.addWidget(self.label_ch_ed_key, 0, 0, 1, 1)
        self.gridLayout_16.addWidget(self.groupBox_EditDisplayKeys, 1, 2, 1, 1)
        self.groupBox_Manage_Keys = QtGui.QGroupBox(self.tab_ManageKeys)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox_Manage_Keys.sizePolicy().hasHeightForWidth())
        self.groupBox_Manage_Keys.setSizePolicy(sizePolicy)
        self.groupBox_Manage_Keys.setObjectName(_fromUtf8("groupBox_Manage_Keys"))
        self.gridLayout_15 = QtGui.QGridLayout(self.groupBox_Manage_Keys)
        self.gridLayout_15.setObjectName(_fromUtf8("gridLayout_15"))
        self.label_ch_del_masterkeys = QtGui.QLabel(self.groupBox_Manage_Keys)
        self.label_ch_del_masterkeys.setObjectName(_fromUtf8("label_ch_del_masterkeys"))
        self.gridLayout_15.addWidget(self.label_ch_del_masterkeys, 0, 0, 1, 1)
        self.tableWidgetManageMasterkeys = QtGui.QTableWidget(self.groupBox_Manage_Keys)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidgetManageMasterkeys.sizePolicy().hasHeightForWidth())
        self.tableWidgetManageMasterkeys.setSizePolicy(sizePolicy)
        self.tableWidgetManageMasterkeys.setObjectName(_fromUtf8("tableWidgetManageMasterkeys"))
        self.tableWidgetManageMasterkeys.setColumnCount(3)
        self.tableWidgetManageMasterkeys.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetManageMasterkeys.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetManageMasterkeys.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetManageMasterkeys.setHorizontalHeaderItem(2, item)
        self.tableWidgetManageMasterkeys.horizontalHeader().setStretchLastSection(True)
        self.gridLayout_15.addWidget(self.tableWidgetManageMasterkeys, 1, 0, 1, 1)
        self.pushButtonDelKeys = QtGui.QPushButton(self.groupBox_Manage_Keys)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonDelKeys.sizePolicy().hasHeightForWidth())
        self.pushButtonDelKeys.setSizePolicy(sizePolicy)
        self.pushButtonDelKeys.setObjectName(_fromUtf8("pushButtonDelKeys"))
        self.gridLayout_15.addWidget(self.pushButtonDelKeys, 2, 0, 1, 1)
        self.gridLayout_16.addWidget(self.groupBox_Manage_Keys, 0, 6, 4, 1)
        self.groupBox_GenKey = QtGui.QGroupBox(self.tab_ManageKeys)
        self.groupBox_GenKey.setObjectName(_fromUtf8("groupBox_GenKey"))
        self.gridLayout_4 = QtGui.QGridLayout(self.groupBox_GenKey)
        self.gridLayout_4.setObjectName(_fromUtf8("gridLayout_4"))
        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_4.addItem(spacerItem2, 0, 1, 1, 1)
        self.pushButtonGenKey = QtGui.QPushButton(self.groupBox_GenKey)
        self.pushButtonGenKey.setObjectName(_fromUtf8("pushButtonGenKey"))
        self.gridLayout_4.addWidget(self.pushButtonGenKey, 0, 0, 1, 1)
        self.gridLayout_16.addWidget(self.groupBox_GenKey, 0, 2, 1, 1)
        spacerItem3 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout_16.addItem(spacerItem3, 3, 2, 1, 1)
        self.tabWidget.addTab(self.tab_ManageKeys, _fromUtf8(""))
        self.tab_Contacts = QtGui.QWidget()
        self.tab_Contacts.setEnabled(True)
        self.tab_Contacts.setObjectName(_fromUtf8("tab_Contacts"))
        self.gridLayout_9 = QtGui.QGridLayout(self.tab_Contacts)
        self.gridLayout_9.setObjectName(_fromUtf8("gridLayout_9"))
        self.groupBox_EditDisplayContacts = QtGui.QGroupBox(self.tab_Contacts)
        self.groupBox_EditDisplayContacts.setObjectName(_fromUtf8("groupBox_EditDisplayContacts"))
        self.gridLayout_10 = QtGui.QGridLayout(self.groupBox_EditDisplayContacts)
        self.gridLayout_10.setObjectName(_fromUtf8("gridLayout_10"))
        self.label_ch_con_key = QtGui.QLabel(self.groupBox_EditDisplayContacts)
        self.label_ch_con_key.setObjectName(_fromUtf8("label_ch_con_key"))
        self.gridLayout_10.addWidget(self.label_ch_con_key, 0, 0, 1, 1)
        self.chooseContactToDisplay = QtGui.QComboBox(self.groupBox_EditDisplayContacts)
        self.chooseContactToDisplay.setObjectName(_fromUtf8("chooseContactToDisplay"))
        self.gridLayout_10.addWidget(self.chooseContactToDisplay, 0, 1, 1, 2)
        self.label_cont_pub_here = QtGui.QLabel(self.groupBox_EditDisplayContacts)
        self.label_cont_pub_here.setObjectName(_fromUtf8("label_cont_pub_here"))
        self.gridLayout_10.addWidget(self.label_cont_pub_here, 1, 0, 1, 1)
        spacerItem4 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout_10.addItem(spacerItem4, 2, 1, 1, 1)
        self.lineDisplayContactPublic = QtGui.QLineEdit(self.groupBox_EditDisplayContacts)
        self.lineDisplayContactPublic.setReadOnly(True)
        self.lineDisplayContactPublic.setObjectName(_fromUtf8("lineDisplayContactPublic"))
        self.gridLayout_10.addWidget(self.lineDisplayContactPublic, 1, 1, 1, 1)
        self.gridLayout_9.addWidget(self.groupBox_EditDisplayContacts, 1, 0, 1, 1)
        self.groupBox_AddContacts = QtGui.QGroupBox(self.tab_Contacts)
        self.groupBox_AddContacts.setObjectName(_fromUtf8("groupBox_AddContacts"))
        self.gridLayout_8 = QtGui.QGridLayout(self.groupBox_AddContacts)
        self.gridLayout_8.setObjectName(_fromUtf8("gridLayout_8"))
        self.pushButtonAddKey = QtGui.QPushButton(self.groupBox_AddContacts)
        self.pushButtonAddKey.setObjectName(_fromUtf8("pushButtonAddKey"))
        self.gridLayout_8.addWidget(self.pushButtonAddKey, 0, 2, 1, 1)
        self.lineEditAddContact = QtGui.QLineEdit(self.groupBox_AddContacts)
        self.lineEditAddContact.setObjectName(_fromUtf8("lineEditAddContact"))
        self.gridLayout_8.addWidget(self.lineEditAddContact, 0, 1, 1, 1)
        self.gridLayout_9.addWidget(self.groupBox_AddContacts, 0, 0, 1, 1)
        self.groupBox_ManageContacts = QtGui.QGroupBox(self.tab_Contacts)
        self.groupBox_ManageContacts.setObjectName(_fromUtf8("groupBox_ManageContacts"))
        self.gridLayout_7 = QtGui.QGridLayout(self.groupBox_ManageContacts)
        self.gridLayout_7.setObjectName(_fromUtf8("gridLayout_7"))
        self.pushButtonDelContacts = QtGui.QPushButton(self.groupBox_ManageContacts)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonDelContacts.sizePolicy().hasHeightForWidth())
        self.pushButtonDelContacts.setSizePolicy(sizePolicy)
        self.pushButtonDelContacts.setObjectName(_fromUtf8("pushButtonDelContacts"))
        self.gridLayout_7.addWidget(self.pushButtonDelContacts, 2, 0, 1, 1)
        self.label_ch_del_contacts = QtGui.QLabel(self.groupBox_ManageContacts)
        self.label_ch_del_contacts.setObjectName(_fromUtf8("label_ch_del_contacts"))
        self.gridLayout_7.addWidget(self.label_ch_del_contacts, 0, 0, 1, 1)
        self.tableWidgetManageContacts = QtGui.QTableWidget(self.groupBox_ManageContacts)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tableWidgetManageContacts.sizePolicy().hasHeightForWidth())
        self.tableWidgetManageContacts.setSizePolicy(sizePolicy)
        self.tableWidgetManageContacts.setObjectName(_fromUtf8("tableWidgetManageContacts"))
        self.tableWidgetManageContacts.setColumnCount(3)
        self.tableWidgetManageContacts.setRowCount(0)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetManageContacts.setHorizontalHeaderItem(0, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetManageContacts.setHorizontalHeaderItem(1, item)
        item = QtGui.QTableWidgetItem()
        self.tableWidgetManageContacts.setHorizontalHeaderItem(2, item)
        self.tableWidgetManageContacts.horizontalHeader().setStretchLastSection(True)
        self.gridLayout_7.addWidget(self.tableWidgetManageContacts, 1, 0, 1, 1)
        self.gridLayout_9.addWidget(self.groupBox_ManageContacts, 0, 1, 4, 1)
        spacerItem5 = QtGui.QSpacerItem(20, 206, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.gridLayout_9.addItem(spacerItem5, 3, 0, 1, 1)

        self.tabWidget.addTab(self.tab_Contacts, _fromUtf8(""))
        self.gridLayout.addWidget(self.tabWidget, 0, 0, 1, 1)
        ECcrypt.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(ECcrypt)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        ECcrypt.setStatusBar(self.statusbar)

        self.retranslateUi(ECcrypt)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(ECcrypt)

    def retranslateUi(self, ECcrypt):
        ECcrypt.setWindowTitle(_translate("ECcrypt", "EC-crypt", None))
        ECcrypt.setWindowIcon(QtGui.QIcon('manual/img/icon.png'))
        self.groupBox_EncryptionOpt.setTitle(_translate("ECcrypt", "Encryption Options", None))
        self.radioButtonNormalType.setText(_translate("ECcrypt", "Normal", None))
        self.radioButtonIncognitoType.setText(_translate("ECcrypt", "Incognito", None))
        self.checkBoxHideIDs.setText(_translate("ECcrypt", "Hide IDs", None))
        self.groupBox_MsgInput.setTitle(_translate("ECcrypt", "Message", None))
        self.label_ch_attach.setText(_translate("ECcrypt", "Choose Attachment:", None))
        self.pushButtonResetAttach.setText(_translate("ECcrypt", "Reset", None))
        self.toolButtonChooseAttach.setText(_translate("ECcrypt", "...", None))
        self.groupBox_Keys.setTitle(_translate("ECcrypt", "Keys", None))
        item = self.tableWidgetContacts.horizontalHeaderItem(1)
        item.setText(_translate("ECcrypt", "ID", None))
        item = self.tableWidgetContacts.horizontalHeaderItem(2)
        item.setText(_translate("ECcrypt", "Alias", None))
        item = self.tableWidgetContacts.horizontalHeaderItem(3)
        item.setText(_translate("ECcrypt", "Public Key", None))
        self.label_encryptfor.setText(_translate("ECcrypt", "Encrypt for:", None))
        self.label_from.setText(_translate("ECcrypt", "From:", None))
        self.groupBox_OutputOpt.setTitle(_translate("ECcrypt", "Output Options", None))
        self.radioButtonMimeEncode.setText(_translate("ECcrypt", "Output As Text (MIME Encoding)", None))
        self.radioButtonToFile.setText(_translate("ECcrypt", "Output As Binary File", None))
        self.pushButtonEncrypt.setText(_translate("ECcrypt", "Encrypt", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_newMsg), _translate("ECcrypt", "New Message", None))
        self.pushButtonDecrypt.setText(_translate("ECcrypt", "Decrypt", None))
        self.groupBox_DecrMsg.setTitle(_translate("ECcrypt", "Decrypted Message", None))
        self.groupBox_DecMsgInfo.setTitle(_translate("ECcrypt", "Message Info", None))
        self.label_decr_info.setText(_translate("ECcrypt", "(none)", None))
        self.groupBox_DecryptionOpt.setTitle(_translate("ECcrypt", "Decryption Options", None))
        self.toolButtonChooseDecryptFile.setText(_translate("ECcrypt", "...", None))
        self.radioButton_DecryptFile.setText(_translate("ECcrypt", "Decrypt Binary File", None))
        self.pushButtonResetDecryption.setText(_translate("ECcrypt", "Reset", None))
        self.label_ch_file.setText(_translate("ECcrypt", "Choose File to Decrypt:", None))
        self.radioButton_DecryptMime.setText(_translate("ECcrypt", "Decrypt MIME", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_DecryptMsg), _translate("ECcrypt", "Decrypt Message", None))
        self.groupBox_SignOpt.setTitle(_translate("ECcrypt", "Signing Options", None))
        self.toolButtonChooseSignFile.setText(_translate("ECcrypt", "...", None))
        self.radioButton_SignMessage.setText(_translate("ECcrypt", "Sign Message", None))
        self.radioButton_SignFile.setText(_translate("ECcrypt", "Sign File", None))
        self.label_ch_sig_file.setText(_translate("ECcrypt", "Choose File to Sign:", None))
        self.pushButtonResetSigFile.setText(_translate("ECcrypt", "Reset", None))
        self.checkBoxIncludeTime.setText(_translate("ECcrypt", "Include Timestamp (reveals system clock)", None))
        self.groupBox_SigKey.setTitle(_translate("ECcrypt", "Signing Key", None))
        self.pushButtonSign.setText(_translate("ECcrypt", "Sign", None))
        self.groupBoxSignMessage.setTitle(_translate("ECcrypt", "Message To Sign", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_Sign), _translate("ECcrypt", "Sign", None))
        self.groupBoxVerOptions.setTitle(_translate("ECcrypt", "Verify Options", None))
        self.radioButtonVerifyMessage.setText(_translate("ECcrypt", "Verify Message Signature", None))
        self.radioButtonVerifyFileSig.setText(_translate("ECcrypt", "Verify File Signature", None))
        self.label_ch_ver_file.setText(_translate("ECcrypt", "Choose File to Verify:", None))
        self.toolButtonChooseVerFile.setText(_translate("ECcrypt", "...", None))
        self.pushButtonResetVerFile.setText(_translate("ECcrypt", "Reset", None))
        self.label_ch_ver_sig.setText(_translate("ECcrypt", "Choose Signature to Verify:", None))
        self.toolButtonChooseVerSig.setText(_translate("ECcrypt", "...", None))
        self.pushButtonResetVerSig.setText(_translate("ECcrypt", "Reset", None))
        self.groupBoxVerMessageInput.setTitle(_translate("ECcrypt", "Message to Verify", None))
        self.pushButtonVerify.setText(_translate("ECcrypt", "Verify", None))
        self.groupBoxVerifyInfo.setTitle(_translate("ECcrypt", "Verify Info", None))
        self.label_ver_info.setText(_translate("ECcrypt", "(none)", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_Verify), _translate("ECcrypt", "Verify", None))
        self.groupBox_EditDisplayKeys.setTitle(_translate("ECcrypt", "Display Key", None))
        self.label_pub_here.setText(_translate("ECcrypt", "Public Master Key:", None))
        self.label_ch_ed_key.setText(_translate("ECcrypt", "Choose Key:", None))
        self.groupBox_Manage_Keys.setTitle(_translate("ECcrypt", "Keys", None))
        self.label_ch_del_masterkeys.setText(_translate("ECcrypt", "Choose Master Key(s) to delete:", None))
        item = self.tableWidgetManageMasterkeys.horizontalHeaderItem(1)
        item.setText(_translate("ECcrypt", "ID", None))
        item = self.tableWidgetManageMasterkeys.horizontalHeaderItem(2)
        item.setText(_translate("ECcrypt", "Alias", None))
        self.pushButtonDelKeys.setText(_translate("ECcrypt", "Delete", None))
        self.groupBox_GenKey.setTitle(_translate("ECcrypt", "Generate New Key", None))
        self.pushButtonGenKey.setText(_translate("ECcrypt", "Generate Key", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_ManageKeys), _translate("ECcrypt", "MasterKeys", None))
        self.groupBox_EditDisplayContacts.setTitle(_translate("ECcrypt", "Display Key", None))
        self.label_ch_con_key.setText(_translate("ECcrypt", "Choose Key:", None))
        self.label_cont_pub_here.setText(_translate("ECcrypt", "Public Contact Key:", None))
        self.groupBox_AddContacts.setTitle(_translate("ECcrypt", "Add Contact", None))
        self.pushButtonAddKey.setText(_translate("ECcrypt", "Add", None))
        self.groupBox_ManageContacts.setTitle(_translate("ECcrypt", "Contacts", None))
        self.pushButtonDelContacts.setText(_translate("ECcrypt", "Delete", None))
        self.label_ch_del_contacts.setText(_translate("ECcrypt", "Choose Contact key(s) to delete:", None))
        item = self.tableWidgetManageContacts.horizontalHeaderItem(1)
        item.setText(_translate("ECcrypt", "ID", None))
        item = self.tableWidgetManageContacts.horizontalHeaderItem(2)
        item.setText(_translate("ECcrypt", "Alias", None))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_Contacts), _translate("ECcrypt", "Contacts", None))

        ''' Connections '''
        self.choosePrivkey.addItem(_fromUtf8('Choose Master Key'))
        self.choosePrivkey.insertItems(1, self.master_key_list)
        self.choosePrivkey.currentIndexChanged[str].connect(self.set_enc_masterkey)
        self.chooseSigningKey.addItem(_fromUtf8('Choose Master Key'))
        self.chooseSigningKey.insertItems(1, self.master_key_list)
        self.chooseSigningKey.currentIndexChanged[str].connect(self.set_sig_masterkey)
        self.pushButtonEncrypt.clicked.connect(self.encrypt_message) 
        self.pushButtonDecrypt.clicked.connect(self.decrypt_message)
        self.pushButtonSign.clicked.connect(self.sign_message)
        self.pushButtonVerify.clicked.connect(self.verify_signature)
        self.toolButtonChooseAttach.clicked.connect(self.set_attach_filename)
        self.pushButtonResetAttach.clicked.connect(self.reset_attach_filename)
        self.toolButtonChooseDecryptFile.clicked.connect(self.set_decrypt_filename)
        self.pushButtonResetDecryption.clicked.connect(self.reset_decrypt_file)
        self.toolButtonChooseSignFile.clicked.connect(self.set_sign_filename)
        self.pushButtonResetSigFile.clicked.connect(self.reset_sign_filename)
        self.toolButtonChooseVerFile.clicked.connect(self.set_verified_file_filename)
        self.pushButtonResetVerFile.clicked.connect(self.reset_verified_file_filename)
        self.toolButtonChooseVerSig.clicked.connect(self.set_verified_sig_filename)
        self.pushButtonResetVerSig.clicked.connect(self.reset_verified_sig_filename)
        self.pushButtonGenKey.clicked.connect(self.generate_new_masterkey)
        self.pushButtonAddKey.clicked.connect(self.add_new_contactkey)
        self.chooseContactToDisplay.addItem(_fromUtf8('Choose contact key to display'))
        self.chooseContactToDisplay.insertItems(1, self.contact_id_list)
        self.chooseContactToDisplay.currentIndexChanged[str].connect(self.return_contact_edit_index)
        self.chooseContactToDisplay.currentIndexChanged[str].connect(self.show_contactkey)
        self.chooseMasterkeyToDisplay.addItem(_fromUtf8('Choose Master Key to display'))
        self.chooseMasterkeyToDisplay.insertItems(1, self.master_key_list)
        self.chooseMasterkeyToDisplay.currentIndexChanged[str].connect(self.set_display_masterkey_id)
        self.chooseMasterkeyToDisplay.currentIndexChanged[str].connect(self.show_masterkey)
        self.tableWidgetContacts.itemClicked.connect(self.choose_contacts_for_encrypt)
        self.tableWidgetManageContacts.itemChanged.connect(self.contact_edit_alias)
        self.tableWidgetManageContacts.itemClicked.connect(self.choose_contacts_to_delete)
        self.pushButtonDelContacts.clicked.connect(self.del_contactkey)
        self.tableWidgetManageMasterkeys.itemChanged.connect(self.masterkey_edit_alias)
        self.tableWidgetManageMasterkeys.itemClicked.connect(self.choose_masterkeys_to_delete)
        self.pushButtonDelKeys.clicked.connect(self.del_masterkey)
        self.radioButton_DecryptMime.clicked.connect(self.mime_decrypt_flag)
        self.radioButton_DecryptFile.clicked.connect(self.file_decrypt_flag)
        self.radioButton_SignMessage.clicked.connect(self.sign_message_flag)
        self.radioButton_SignFile.clicked.connect(self.sign_file_flag)
        self.radioButtonVerifyMessage.clicked.connect(self.mime_verify_flag)
        self.radioButtonVerifyFileSig.clicked.connect(self.file_verify_flag)
        self.set_defaults()
        self.load_contact_enc_table()
        self.load_contact_manage_table()
        self.load_masterkeys_manage_table()


    '''Setting default options'''
    def set_defaults(self):
        self.radioButtonNormalType.setChecked(True)
        self.radioButtonMimeEncode.setChecked(True)
        self.radioButton_DecryptMime.setChecked(True)
        self.radioButton_SignMessage.setChecked(True)
        self.radioButtonVerifyMessage.setChecked(True)
        self.checkBoxHideIDs.setChecked(False)
        self.checkBoxIncludeTime.setChecked(False)
        self.mime_decrypt_flag(True)
        self.sign_message_flag(True)
        self.mime_verify_flag(True)


    def load_contact_enc_table(self):
        for id in self.contact_id_list:
            row = self.tableWidgetContacts.rowCount()
            self.tableWidgetContacts.insertRow(row)
            self.check_box = QtGui.QTableWidgetItem()
            self.check_box.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
            self.check_box.setCheckState(QtCore.Qt.Unchecked)
            id_item = QtGui.QTableWidgetItem()
            id_item.setText(id)
            id_item.setFlags(id_item.flags() ^ QtCore.Qt.ItemIsEditable)
            alias = QtGui.QTableWidgetItem()
            alias.setText(FormatKeys.retrieve_contact_alias(id))
            alias.setFlags(alias.flags() ^ QtCore.Qt.ItemIsEditable)
            pub = QtGui.QTableWidgetItem()
            pub.setText(FormatKeys.retrieve_contact_key(id))
            pub.setFlags(pub.flags() ^ QtCore.Qt.ItemIsEditable)
            self.tableWidgetContacts.setItem(row, 0, self.check_box)
            self.tableWidgetContacts.setItem(row, 1, QtGui.QTableWidgetItem(id_item))
            self.tableWidgetContacts.setItem(row, 2, QtGui.QTableWidgetItem(alias))
            self.tableWidgetContacts.setItem(row, 3, QtGui.QTableWidgetItem(pub))
            self.tableWidgetContacts.resizeColumnToContents(0)
            self.tableWidgetContacts.resizeColumnToContents(1)
            self.tableWidgetContacts.resizeColumnToContents(2)
            self.tableWidgetContacts.resizeColumnToContents(3)


    def reset_enc_table(self):
        self.tableWidgetContacts.setRowCount(0)
        self.contact_id_list = FormatKeys.retrieve_contactkey_id_list()
        self.load_contact_enc_table()
        self.encrypt_for_list = []


    def load_contact_manage_table(self):
        for id in self.contact_id_list:
            row = self.tableWidgetManageContacts.rowCount()
            self.tableWidgetManageContacts.insertRow(row)
            self.check_box = QtGui.QTableWidgetItem()
            self.check_box.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
            self.check_box.setCheckState(QtCore.Qt.Unchecked)
            id_item = QtGui.QTableWidgetItem()
            id_item.setText(id)
            id_item.setFlags(id_item.flags() ^ QtCore.Qt.ItemIsEditable)
            alias = QtGui.QTableWidgetItem()
            alias.setText(FormatKeys.retrieve_contact_alias(id))
            self.tableWidgetManageContacts.setItem(row, 0, self.check_box)
            self.tableWidgetManageContacts.setItem(row, 1, QtGui.QTableWidgetItem(id_item))
            self.tableWidgetManageContacts.setItem(row, 2, QtGui.QTableWidgetItem(alias))
            self.tableWidgetManageContacts.resizeColumnToContents(0)
            self.tableWidgetManageContacts.resizeColumnToContents(1)
            self.tableWidgetManageContacts.resizeColumnToContents(2)


    def reset_contact_manage_table(self):
        self.tableWidgetManageContacts.setRowCount(0)
        self.contact_id_list = FormatKeys.retrieve_contactkey_id_list()
        self.load_contact_manage_table()
        self.encrypt_for_list = []


    def load_masterkeys_manage_table(self):
        for id in self.master_key_list:
            row = self.tableWidgetManageMasterkeys.rowCount()
            self.tableWidgetManageMasterkeys.insertRow(row)
            self.check_box = QtGui.QTableWidgetItem()
            self.check_box.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
            self.check_box.setCheckState(QtCore.Qt.Unchecked)
            id_item = QtGui.QTableWidgetItem()
            id_item.setText(id)
            id_item.setFlags(id_item.flags() ^ QtCore.Qt.ItemIsEditable)
            alias = QtGui.QTableWidgetItem()
            alias.setText(FormatKeys.retrieve_master_alias(id))
            self.tableWidgetManageMasterkeys.setItem(row, 0, self.check_box)
            self.tableWidgetManageMasterkeys.setItem(row, 1, QtGui.QTableWidgetItem(id_item))
            self.tableWidgetManageMasterkeys.setItem(row, 2, QtGui.QTableWidgetItem(alias))
            self.tableWidgetManageMasterkeys.resizeColumnToContents(0)
            self.tableWidgetManageMasterkeys.resizeColumnToContents(1)
            self.tableWidgetManageMasterkeys.resizeColumnToContents(2)


    def reset_masterkeys_manage_table(self):
        self.tableWidgetManageMasterkeys.setRowCount(0)
        self.master_key_list = FormatKeys.retrieve_masterkey_id_list()
        self.load_masterkeys_manage_table()
        self.encrypt_for_list = []


    def set_enc_masterkey(self, index):
        self.chosen_enc_masterkey_id = unicode(index[0:8])


    def set_sig_masterkey(self, index):
        self.chosen_sig_masterkey_id = unicode(index[0:8])


    def choose_contacts_for_encrypt(self, index):
        if index.checkState() == QtCore.Qt.Checked:
            id = self.tableWidgetContacts.item(index.row(), 1)
            id_text = str(id.text())
            self.encrypt_for_list.append(id_text)
        elif index.checkState() == QtCore.Qt.Unchecked:
            id = self.tableWidgetContacts.item(index.row(), 1)
            id_text = str(id.text())
            try:
                self.encrypt_for_list.remove(id_text)
            except:
                pass


    '''Encryption function'''
    def set_attach_filename(self):
        chooseAttachFileDialog = QtGui.QFileDialog.getOpenFileName(self, 'Open file', '')
        s = unicode(chooseAttachFileDialog)
        self.attach_to_encrypt = os.path.abspath(s)
        self.lineAttachPath.setText(self.attach_to_encrypt)


    def reset_attach_filename(self):
        if self.attach_to_encrypt is not None:
            self.attach_to_encrypt = None
            self.lineAttachPath.setText('')
            self.show_status_msg('Attachment cleared')
        elif self.attach_to_encrypt is None:
            self.show_status_msg('Nothing to reset')


    def get_message_type(self):
        if self.radioButtonNormalType.isChecked() and self.attach_to_encrypt is None:
            return 12
        elif self.radioButtonNormalType.isChecked() and self.attach_to_encrypt is not None:
            return 24
        elif self.radioButtonIncognitoType.isChecked() and self.attach_to_encrypt is None:
            return 36
        elif self.radioButtonIncognitoType.isChecked() and self.attach_to_encrypt is not None:
            return 48


    def encrypt_message(self):
        text_message = unicode(self.inputMessageBox.toPlainText()).encode('utf-8')
        if not 'Choose M' in self.chosen_enc_masterkey_id and self.encrypt_for_list:
            msg_type = self.get_message_type()
            if msg_type is 12: 
                enc_msg, msg_name = Messaging.encrypt12type(self.chosen_enc_masterkey_id,
                                                            self.encrypt_for_list,
                                                            text_message)
            elif msg_type is 24: 
                attach_data, attach_name = self.read_file(self.attach_to_encrypt)
                enc_msg, msg_name = Messaging.encrypt24type(self.chosen_enc_masterkey_id,
                                                            self.encrypt_for_list,
                                                            text_message, 
                                                            attach_data,
                                                            attach_name)
            elif msg_type is 36: 
                enc_msg, msg_name = Messaging.encrypt36type(self.encrypt_for_list,
                                                            text_message)
            elif msg_type is 48: 
                attach_data, attach_name = self.read_file(self.attach_to_encrypt)
                enc_msg, msg_name = Messaging.encrypt48type(self.encrypt_for_list, 
                                                            text_message, 
                                                            attach_data,
                                                            attach_name)
            if self.checkBoxHideIDs.isChecked():
                enc_msg, msg_name = Messaging.encrypt60type(self.encrypt_for_list,
                                                            enc_msg)
            if self.radioButtonMimeEncode.isChecked():
                self.inputMessageBox.setPlainText(Messaging.message_encode(enc_msg))
                self.show_status_msg('Copy MIME-encoded message')
            if self.radioButtonToFile.isChecked():
                self.write_file('encrypted/' + msg_name, enc_msg)
                self.inputMessageBox.setPlainText('')
                self.show_status_msg(('Encrypted message to: ' + msg_name))
            self.choosePrivkey.setCurrentIndex(0)
            self.reset_enc_table()
            self.attach_to_encrypt = None
            self.lineAttachPath.setText('')
            self.chosen_enc_masterkey_id = 'Choose Master Key'
            self.set_defaults()
        elif 'Choose M' in self.chosen_enc_masterkey_id:
            self.show_status_msg('Choose Master Key')
        elif not self.encrypt_for_list:
            self.show_status_msg('Choose Contact Key')


    '''Decryption functions'''

    def set_decrypt_filename(self):
        chooseDecryptFileDialog = QtGui.QFileDialog.getOpenFileName(self, 'Open file', '')
        s = unicode(chooseDecryptFileDialog)
        self.file_to_decrypt = os.path.abspath(s)
        self.lineDecryptionFilePath.setText(self.file_to_decrypt)


    def reset_decrypt_file(self):
        if self.file_to_decrypt is not None:
            self.set_decrypt_defaults()
            self.show_status_msg('File to decrypr cleared')
        elif self.file_to_decrypt is None:
            self.set_decrypt_defaults()
            self.show_status_msg('Nothing to reset')


    def mime_decrypt_flag(self, state):
        if state is True:
            self.textDecryptedMessageDisplay.setReadOnly(False)
            self.lineDecryptionFilePath.setText('')
            self.lineDecryptionFilePath.setEnabled(False)
            self.toolButtonChooseDecryptFile.setEnabled(False)
            self.pushButtonResetDecryption.setEnabled(False)
            self.file_to_decrypt = None


    def file_decrypt_flag(self, state):
        if state is True:
            self.textDecryptedMessageDisplay.setReadOnly(True)
            self.textDecryptedMessageDisplay.setPlainText('')
            self.lineDecryptionFilePath.setEnabled(True)
            self.toolButtonChooseDecryptFile.setEnabled(True)
            self.pushButtonResetDecryption.setEnabled(True)
            self.file_to_decrypt = None


    def decrypt_message(self):
        try: 
            message_text = unicode(self.textDecryptedMessageDisplay.toPlainText()).encode('utf-8')
            if message_text and self.radioButton_DecryptMime.isChecked():
                message = Messaging.message_decode(message_text)
            elif self.file_to_decrypt and not self.radioButton_DecryptMime.isChecked():
                message, fn = self.read_file(self.file_to_decrypt)
            else:
                self.show_status_msg('Paste message or choose file to decrypt')
                return
            self.decrypting(message)
            self.set_defaults()
        except Messaging.ECCryptException, (instance): 
            self.show_status_error_msg(instance.parameter)
        except FormatKeys.ECCryptException, (instance):
            self.show_status_error_msg(instance.parameter)
        except Parsing.ECCryptException, (instance):
            self.show_status_error_msg(instance.parameter)


    def decrypting(self, message):
        msg_type = ord(message[0:1])
        if msg_type is 12:
            text, sender_id, status, info = Messaging.decrypt12type(message)
            self.textDecryptedMessageDisplay.setPlainText(text.decode('utf-8'))
            self.textDecryptedMessageDisplay.setReadOnly(True)
            self.label_decr_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_decrypt = None
        elif msg_type is 24:
            text, sender_id, attach, attach_name, status, info = Messaging.decrypt24type(message)
            self.write_file('decrypted/' + attach_name, attach)
            self.textDecryptedMessageDisplay.setPlainText(text.decode('utf-8'))
            self.textDecryptedMessageDisplay.setReadOnly(True)
            self.label_decr_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_decrypt = None
        elif msg_type is 36:
            text, status, info = Messaging.decrypt36type(message)
            self.textDecryptedMessageDisplay.setPlainText(text.decode('utf-8'))
            self.textDecryptedMessageDisplay.setReadOnly(True)
            self.label_decr_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_decrypt = None
        elif msg_type is 48:
            text, attach, attach_name, status, info = Messaging.decrypt48type(message)
            self.write_file('decrypted/' + attach_name, attach)
            self.textDecryptedMessageDisplay.setPlainText(text.decode('utf-8'))
            self.textDecryptedMessageDisplay.setReadOnly(True)
            self.label_decr_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_decrypt = None
        elif msg_type is 60:
            decrypted_payload = Messaging.decrypt60type(message)
            self.decrypting(decrypted_payload)
        else: 
            self.show_status_error_msg('Not an EC-Crypt message!')
            self.file_to_decrypt = None


    def write_file(self, path, data):
        with open(path, 'wb') as f:
            f.write(data)


    def read_file(self, path):
        with open(path, 'rb') as f:
            data = f.read()
            filename = os.path.basename(f.name)
        return data, filename


    '''Signature functions'''
    
    def set_sign_filename(self):
        chooseSignFileDialog = QtGui.QFileDialog.getOpenFileName(self, 'Open file', '')
        s = unicode(chooseSignFileDialog)
        self.file_to_sign = os.path.abspath(s)
        self.lineEditSigFilePath.setText(self.file_to_sign)


    def reset_sign_filename(self):
        if self.file_to_sign is not None:
            self.file_to_sign = None
            self.lineEditSigFilePath.setText('')
            self.show_status_msg('File to sign cleared')
        elif self.file_to_sign is None:
            self.show_status_msg('Nothing to reset')


    def sign_message_flag(self, state):
        if state is True:
            self.plainTextEditSigInput.setReadOnly(False)
            self.lineEditSigFilePath.setEnabled(False)
            self.toolButtonChooseSignFile.setEnabled(False)
            self.pushButtonResetSigFile.setEnabled(False)
            self.file_to_sign = None


    def sign_file_flag(self, state):
        if state is True:
            self.plainTextEditSigInput.setReadOnly(True)
            self.plainTextEditSigInput.setPlainText('')
            self.lineEditSigFilePath.setEnabled(True)
            self.toolButtonChooseSignFile.setEnabled(True)
            self.pushButtonResetSigFile.setEnabled(True)
            self.file_to_sign = None


    def get_signature_type(self):
        if self.radioButton_SignMessage.isChecked() and not self.checkBoxIncludeTime.isChecked():
            return 7
        elif self.radioButton_SignMessage.isChecked() and self.checkBoxIncludeTime.isChecked():
            return 14
        elif self.radioButton_SignFile.isChecked() and not self.checkBoxIncludeTime.isChecked():
            return 21
        elif self.radioButton_SignFile.isChecked() and self.checkBoxIncludeTime.isChecked():
            return 28


    def sign_message(self):
        text_message = unicode(self.plainTextEditSigInput.toPlainText()).encode('utf-8')
        sig_type = self.get_signature_type()
        if not 'Choose M' in self.chosen_sig_masterkey_id:
            if not self.file_to_sign and not text_message:
                self.show_status_msg('Paste message or choose file to sign')
                return
            if sig_type is 7: 
                signed_text = Messaging.sign7type(self.chosen_sig_masterkey_id, text_message)
                self.plainTextEditSigInput.setPlainText(signed_text)
            elif sig_type is 14:
                signed_text = Messaging.sign14type(self.chosen_sig_masterkey_id, text_message)
                self.plainTextEditSigInput.setPlainText(signed_text)
            elif sig_type is 21:
                file, filename = self.read_file(self.file_to_sign)
                file_sig = Messaging.sign21type(self.chosen_sig_masterkey_id, file)
                write_sig = self.write_file(self.file_to_sign + '.sig', file_sig)
            elif sig_type is 28:
                file, filename = self.read_file(self.file_to_sign)
                file_sig = Messaging.sign28type(self.chosen_sig_masterkey_id, file)
                write_sig = self.write_file(self.file_to_sign + '.sig', file_sig)
            self.show_status_msg('Signed with key: ' + self.chosen_sig_masterkey_id)
            self.chooseSigningKey.setCurrentIndex(0)
            self.file_to_sign = None
            self.lineEditSigFilePath.setText('')
            self.chosen_sig_masterkey_id = 'Choose Master Key'
            self.set_defaults()
        elif 'Choose M' in self.chosen_sig_masterkey_id:
            self.show_status_msg('Choose Master Key')


    '''Verification functions'''

    def set_verified_file_filename(self):
        chooseVerifyFileDialog = QtGui.QFileDialog.getOpenFileName(self, 'Open file', '')
        s = unicode(chooseVerifyFileDialog)
        self.file_to_verify = os.path.abspath(s)
        self.lineEditVerFilePath.setText(self.file_to_verify)


    def reset_verified_file_filename(self):
        if self.file_to_verify is not None:
            self.file_to_verify = None
            self.lineEditVerFilePath.setText('')
            self.show_status_msg('File to verify cleared')
        elif self.file_to_verify is None:
            self.show_status_msg('Nothing to reset')


    def set_verified_sig_filename(self):
        chooseVerifySigFileDialog = QtGui.QFileDialog.getOpenFileName(self, 'Open file', '')
        s = unicode(chooseVerifySigFileDialog)
        self.sig_file_to_verify = os.path.abspath(s)
        self.lineEditVerSigPath.setText(self.sig_file_to_verify)


    def reset_verified_sig_filename(self):
        if self.sig_file_to_verify is not None:
            self.sig_file_to_verify = None
            self.lineEditVerSigPath.setText('')
            self.show_status_msg('Signature to verify cleared')
        elif self.sig_file_to_verify is None:
            self.show_status_msg('Nothing to reset')


    def mime_verify_flag(self, state):
        if state is True:
            self.plainTextEditVerifyInput.setReadOnly(False)
            self.lineEditVerFilePath.setText('')
            self.lineEditVerFilePath.setEnabled(False)
            self.lineEditVerSigPath.setText('')
            self.lineEditVerSigPath.setEnabled(False)
            self.toolButtonChooseVerFile.setEnabled(False)
            self.pushButtonResetVerFile.setEnabled(False)
            self.toolButtonChooseVerSig.setEnabled(False)
            self.pushButtonResetVerSig.setEnabled(False)
            self.file_to_verify = None
            self.sig_file_to_verify = None


    def file_verify_flag(self, state):
        if state is True:
            self.plainTextEditVerifyInput.setReadOnly(True)
            self.plainTextEditVerifyInput.setPlainText('')
            self.lineEditVerFilePath.setEnabled(True)
            self.lineEditVerSigPath.setEnabled(True)
            self.toolButtonChooseVerFile.setEnabled(True)
            self.pushButtonResetVerFile.setEnabled(True)
            self.toolButtonChooseVerSig.setEnabled(True)
            self.pushButtonResetVerSig.setEnabled(True)
            self.file_to_verify = None
            self.sig_file_to_verify = None


    def verify_signature(self):
        try: 
            message_text = unicode(self.plainTextEditVerifyInput.toPlainText()).encode('utf-8')
            if message_text and self.radioButtonVerifyMessage.isChecked():
                data, sig = Messaging.msg_signature_decode(message_text)
            elif self.radioButtonVerifyFileSig.isChecked() and self.file_to_verify and self.sig_file_to_verify :
                data, fn = self.read_file(self.file_to_verify)
                sig_data, sn = self.read_file(self.sig_file_to_verify)
                sig = Messaging.file_signature_decode(sig_data)
            else:
                self.show_status_msg('Paste message or choose file and signature to verify')
                return
            self.verifying(data, sig)
            self.set_defaults()
        except Messaging.ECCryptException, (instance): 
            self.show_status_error_msg(instance.parameter)
        except FormatKeys.ECCryptException, (instance):
            self.show_status_error_msg(instance.parameter)
        except Parsing.ECCryptException, (instance):
            self.show_status_error_msg(instance.parameter)


    def verifying(self, data, sig):
        sig_type = ord(sig[0:1])
        if sig_type is 7:
            status, info = Messaging.verify7sig(data, sig)
            self.label_ver_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_verify = None
            self.sig_file_to_verify = None
        elif sig_type is 14:
            status, info = Messaging.verify14sig(data, sig)
            self.label_ver_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_verify = None
            self.sig_file_to_verify = None
        elif sig_type is 21:
            status, info = Messaging.verify21sig(data, sig)
            self.label_ver_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_verify = None
            self.sig_file_to_verify = None
        elif sig_type is 28:
            status, info = Messaging.verify28sig(data, sig)
            self.label_ver_info.setText(_translate("ECcrypt", info, None))
            self.show_status_green_msg(status)
            self.file_to_verify = None
            self.sig_file_to_verify = None
        else: 
            self.show_status_error_msg('Not an EC-Crypt signature!')
            self.file_to_verify = None
            self.sig_file_to_verify = None


    def generate_new_masterkey(self):
        new_key_id = FormatKeys.generate_new_master_key()
        self.show_status_msg('Generated new key {}, edit alias for usability'.format(new_key_id))
        self.master_key_list = FormatKeys.retrieve_masterkey_id_list()
        self.update_master_boxes()
        self.reset_masterkeys_manage_table()


    def set_display_masterkey_id(self, index):
        self.chosen_display_masterkey_id = unicode(index[0:8])


    def show_masterkey(self):
        if self.chosen_display_masterkey_id and not 'Choose M' in self.chosen_display_masterkey_id:
            master_pubkey = FormatKeys.show_master_key(self.chosen_display_masterkey_id)
            self.master_key_list = FormatKeys.retrieve_masterkey_id_list()
            self.show_status_msg('Public key for {}'.format(self.chosen_display_masterkey_id))
            self.lineDisplayMasterPublic.setText(master_pubkey)
        else:
            self.lineDisplayMasterPublic.setText('')


    def masterkey_edit_alias(self, index):
        if self.tableWidgetManageMasterkeys.item(index.row(), 2) is not None:
            alias = self.tableWidgetManageMasterkeys.item(index.row(), 2)
            alias_text = unicode(alias.text())
            id = self.tableWidgetManageMasterkeys.item(index.row(), 1)
            id_text = str(id.text())
            if alias_text:
                if not alias_text in FormatKeys.retrieve_master_alias(id_text):
                    FormatKeys.edit_master_key(id_text, alias_text)
                    self.reset_masterkeys_manage_table()
            elif not alias_text:
                FormatKeys.edit_master_key(id_text, '(none)')
                self.reset_masterkeys_manage_table()


    def choose_masterkeys_to_delete(self, index):
        if index.checkState() == QtCore.Qt.Checked:
            id = self.tableWidgetManageMasterkeys.item(index.row(), 1)
            id_text = str(id.text())
            self.delete_masterkey_list.append(id_text)
        elif index.checkState() == QtCore.Qt.Unchecked:
            id = self.tableWidgetManageMasterkeys.item(index.row(), 1)
            id_text = str(id.text())
            try:
                self.delete_masterkey_list.remove(id_text)
            except:
                pass


    def del_masterkey(self):
        if self.delete_masterkey_list:
            choice = QtGui.QMessageBox.question(self, 'Warning!',
                                                'Are you sure you want to delete selected MasterKey(s)? ' +\
                                                'There is no way to reverse this operation: keys will be removed forever',
                                                QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
            if choice == QtGui.QMessageBox.Yes:
                FormatKeys.delete_master_key(self.delete_masterkey_list)
                self.show_status_msg('Key(s) deleted')
                self.master_key_list = FormatKeys.retrieve_masterkey_id_list()
                self.update_master_boxes()
                self.reset_masterkeys_manage_table()
        elif not self.delete_masterkey_list:
            self.show_status_msg('Choose Master Key to delete')


    def add_new_contactkey(self):
        new_contact_key_paste = self.lineEditAddContact.text()
        new_key = unicode(new_contact_key_paste)
        if not new_key:
            self.show_status_msg('Paste contact key')
        elif new_key:
            validation = Crypto.check_pubkey(new_key)
            if validation is True:
                new_key_raw = FormatKeys.fmt_pub(new_key, 'readable2raw')
                new_key_id = FormatKeys.form_key_id(new_key_raw)
                if FormatKeys.check_contact_identity(new_key_id) is True:
                    self.show_status_msg('This key is already in key ring')
                    self.lineEditAddContact.setText('')
                elif FormatKeys.check_contact_identity(new_key_id) is False:
                    FormatKeys.add_new_contact_key(new_key_id, new_key)
                    self.show_status_msg('New contact added: {}, edit alias for usability'.format(new_key_id))
                    self.lineEditAddContact.setText('')
                    self.update_contact_boxes()
            elif validation is False:
                self.show_status_msg('Invalid contact key!')


    def return_contact_edit_index(self, index):
        self.chosen_contact_edit_index = unicode(index[0:8])


    def contact_edit_alias(self, index):
        if self.tableWidgetManageContacts.item(index.row(), 2) is not None:
            alias = self.tableWidgetManageContacts.item(index.row(), 2)
            alias_text = unicode(alias.text())
            id = self.tableWidgetManageContacts.item(index.row(), 1)
            id_text = str(id.text())
            if alias_text:
                if not alias_text in FormatKeys.retrieve_contact_alias(id_text):
                    FormatKeys.edit_contact_key(id_text, alias_text)
                    self.update_contact_boxes()
            elif not alias_text:
                FormatKeys.edit_contact_key(id_text, '(none)')
                self.update_contact_boxes()


    def show_contactkey(self):
        if self.chosen_contact_edit_index and not 'Choose c' in self.chosen_contact_edit_index:
            contact_pubkey = FormatKeys.show_contact_key(self.chosen_contact_edit_index)
            self.contact_id_list = FormatKeys.retrieve_contactkey_id_list()
            self.show_status_msg('Public key for {}'.format(self.chosen_contact_edit_index))
            self.lineDisplayContactPublic.setText(contact_pubkey)
        else:
            self.lineDisplayContactPublic.setText('')


    def choose_contacts_to_delete(self, index):
        if index.checkState() == QtCore.Qt.Checked:
            id = self.tableWidgetManageContacts.item(index.row(), 1)
            id_text = str(id.text())
            self.delete_contact_list.append(id_text)
        elif index.checkState() == QtCore.Qt.Unchecked:
            id = self.tableWidgetManageContacts.item(index.row(), 1)
            id_text = str(id.text())
            try:
                self.delete_contact_list.remove(id_text)
            except:
                pass


    def del_contactkey(self):
        if self.delete_contact_list:
            choice = QtGui.QMessageBox.question(self, 'Warning!',
                                                'Are you sure you want to delete selected key(s)?',
                                                QtGui.QMessageBox.Yes | QtGui.QMessageBox.No)
            if choice == QtGui.QMessageBox.Yes:
                FormatKeys.delete_contact_key(self.delete_contact_list)
                self.show_status_msg('Key(s) deleted')
                self.update_contact_boxes()
        elif not self.delete_contact_list:
            self.show_status_msg('Choose Master Key to delete')


    def update_master_boxes(self):
        self.choosePrivkey.clear() 
        self.choosePrivkey.addItem(_fromUtf8('Choose Master Key'))
        self.choosePrivkey.insertItems(1, self.master_key_list)
        self.choosePrivkey.setCurrentIndex(0)
        self.chooseMasterkeyToDisplay.clear() 
        self.chooseMasterkeyToDisplay.addItem(_fromUtf8('Choose Master Key to display'))
        self.chooseMasterkeyToDisplay.insertItems(1, self.master_key_list)
        self.chooseMasterkeyToDisplay.setCurrentIndex(0)
        self.chooseSigningKey.clear()
        self.chooseSigningKey.addItem(_fromUtf8('Choose Master Key'))
        self.chooseSigningKey.insertItems(1, self.master_key_list)
        self.chooseSigningKey.setCurrentIndex(0)


    def update_contact_boxes(self):
        self.reset_enc_table()
        self.reset_contact_manage_table()
        self.chooseContactToDisplay.clear() 
        self.chooseContactToDisplay.addItem(_fromUtf8('Choose contact key to display'))
        self.chooseContactToDisplay.insertItems(1, self.contact_id_list)
        self.chooseContactToDisplay.setCurrentIndex(0)


    def show_status_msg(self, message):
        MessageToShowInStatusBar = QtCore.QString(message)
        self.statusbar.setStyleSheet("QStatusBar{background:rgba(0,0,0,0);color:black;}") 
        self.statusbar.showMessage(MessageToShowInStatusBar)


    def show_status_green_msg(self, message):
        MessageToShowInStatusBar = QtCore.QString(message)
        self.statusbar.setStyleSheet("QStatusBar{background:rgba(128,255,128,255);color:black;font-weight:bold;}") 
        self.statusbar.showMessage(MessageToShowInStatusBar)


    def show_status_error_msg(self, message):
        MessageToShowInStatusBar = QtCore.QString(message)
        self.statusbar.setStyleSheet("QStatusBar{background:rgba(255,128,128,255);color:black;font-weight:bold;}") 
        self.statusbar.showMessage(MessageToShowInStatusBar)



if __name__ == '__main__':
    app = QtGui.QApplication(sys.argv)
    ex = Ui_ECcrypt()
    ex.show()
    sys.exit(app.exec_())   

