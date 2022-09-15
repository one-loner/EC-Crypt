# Documentation


EC-crypt is a secure, file-based messaging protocol. It can be extended into network by special tools, although such tools are not yet implemented. This document describes the basic principles of protocol and encryption scheme. For networking extension capabilities see document «Network Draft».  

Algorithms used:

1. ECDH (curve P-256) 
2. ECDSA (curve P-256)
3. AES-256 (CBC mode)
4. SHA-512

Libraries used in python implementation:

1. OpenSSL (crypto library)
2. PyElliptic (OpenSSL wrapper)
3. PyQt (GUI)

EC-crypt design goals: 

1. Simplicity
2. Short public keys
3. Allow users to exchange of small or medium-sized files
4. Communication should be based on file exchange
5. Protocol should use popular algorithms and parameters for re-implementation simplicity
6. Protocol should be flexible and extendible


## Message protocol


ec-crypt protocol is designed for private message exchange. To communicate, users must generate keypairs and exchange public keys with each other. All keys are unique and have a special identifier - key ID. It is advised to validate IDs personally after public key exchange. After that, users can exchange encrypted messages by any channels (see Network Draft). 

Encrypted ec-crypt message is composed of 6 main blocks: 

* Key ID of receiving party
* Static Public key of sending party
* Session public key for encrypted data
* Text message
* Attachment
* Signature of the whole message


Key ID allows to check for whom message is encrypted for. One-way function forms the ID, so public key of the receiving party is not revealed to third parties unless they already know it.

Static Public key of is associated with sender's identity. It is included in message to allow to check signature if sender public key is not yet known.

Session public key delivers AES secret for text and attachment. It is never used twice and generated for every message.

Text message is unicode (UTF-8) message encrypted by session secret. 

Attachment is any file encrypted by session secret. When message has no attachment, simply set to "NONE".

Signature block is ECDSA-signed SHA512 hash of the whole message and is used to authenticate sending party and check message integrity. Signature is checked first and if it is invalid, message is considered corrupted. 

After encryption, beginning and end of each block  is marked by respective begin/end tag and then all blocks concatenated together. Final message is written in a single file. 

Visual representation of tagged message:

    start_key_id + (Key ID) + end_key_id +  
    start_sender_pubkey + (Sender pubkey) + end_sender_pubkey + 
    start_session_key + (Session pubkey) + end_session_key + 
    start_txt + (Encrypted text) + end_txt + 
    start_attach + (Encrypted attachment) + end_attach + 
    start_signature + (Signature) + end_signature

Block scheme: 

    +---------------------------------+
    | Receiver's Key ID               |
    +---------------------------------+
    +---------------------------------+
    | Sender's Static Public Key      |
    +---------------------------------+
    +---------------------------------+
    | Session Public Key              |
    +---------------------------------+
    +---------------------------------+
    |                                 |
    | Text Message                    |
    |                                 |
    +---------------------------------+
    +---------------------------------+
    |                                 |
    |                                 |
    |                                 |
    | Attachment File                 |
    |                                 |
    |                                 |
    |                                 |
    +---------------------------------+
    +---------------------------------+
    | ECDSA Signature                 |
    +---------------------------------+

Key ID is in ASCII encoding, all other blocks are raw byte data. 


## Encryption scheme

EC-crypt uses widely-deployed ephemeral-static ECDH scheme for data encryption and ECDSA for authentication. 

Overview:

1. If Alice wants to send a message to Bob, she generates fresh private/public key (called session key) and computes a shared secret of this key and Bob key. This shared secret is used to encrypt her payload - text and attachment. She includes public part of session key in message and signes it with another key - the static one, which she gave to Bob earlier. Public part of her static key is included too. 
2. Bob, upon receiving a message, checks the signature and sees, that it is from Alice. Then Bob takes session key in message and private part of his own static key and computes shared secret. Yielded result is the same shared secret that Alice had used to encrypt payload. Now Bob decrypts message and attachment. 
3. In some cases, Eve can intercept message. If Eve tries to change static/session keys or payload in message, such change will break the signature and Bob will know. If Eve tries to change signature and keys, decryption will fail. 

Parameters: 

1. ECDH/ECDSA keys are 256-bit long. 
2. All keys defined on P-256 curve, also known as prime256v1 or secp256r1.
3. Shared secret is derived with SHA512-hash.
4. Data encrypted with AES 256 bit in CBC mode.
5. ECDSA signing is applied to SHA512-hash.

These parameters were chosen for a decent security/performance trade-off. Another advantage  is that they are commonly used in cryptographic libraries of many languages, which makes implementation in other programming languages much more convinient. 

Overall design has some specific security features. After encryption, message cannot be recovered by its creator, only the receiving party can decrypt it. It is because session key is never used twice and not even stored on file system. Thus, compromised key allows attacker only to make new messages, and old messages will remain secured. Attachment file name and extension is not revealed to the observer, as it is hidden in encrypted text message. 


## Addresses


Public keys in ec-crypt can act as address system. They are relatively short - 70 bytes; 32 bytes for X and Y points, 2-byte curve NID and 4-byte key size. Public keys are encoded in Base58 for better user experience. Base58-encoded key is relatively short - 95 characters long.

For convinience, each key has its own short ID. This identifier is formed by first 12 characters of hexadeximal SHA512-hash of decoded public key. These 12 characters splitted by 4 with an underscore character. 

Example of Public key: 

    58eEYiU3qoBMNmx8K2kPcMfsSZGtmJDPWd15R46eawxsS5dGbjWqmkv5KnrnUVdxiHz1QFEd5fWpbgKThBkiWpsJE2b8RRn

Key ID: 7D12_10B1_D59F_2A40

Each key can be named locally. Name is stored in "label" option.  


## Key ring

All keys are stored in files called keyrings. Private user keys are called Master Keys, and stored in file master_keyring.dat Corresponder keys are called Contacts and stored in file contact_keyring.dat

Storing format is a simple INI-style configuration format: 

    [section1] 
    option1 = value1
    option2 = value2

    [section2] 
    option1 = value1
    option2 = value2

where sections are key IDs, options are private key (if present), public key and label. Values are Base58-encoded keys. 

In Master key ring private keys are stored with their public part, as required by crypto library and are stored for computational simplicity. 

Both files are UTF-8 without BOM. 


## Extra Features


List of unimplemented features and proposals: 

1. Static keys can be generated in a deterministic manner, by hashing password or file and using 32 bytes of hash as private key. It is possible even not to store private key, but recreate it each time from password. 
2. User can encrypt messages for his own key.
3. Because of 1 and 2, one can create private group channel with password or key access. 
4. Various data can be hidden in text message - automated timestamps, network addresses, other keys, etc.
5. Message protocol can be extended with backward compatibility if 6 basic blocks are present in message. Any number of additional blocks can be added, e.g. signed public announcements, additional attachments, multiple static keys. 
6. Multiple messages can be chained together by adding each message as attachment. 
7. Key ring files can be extended with any additional option - owner location, network address, e-mail, etc.
