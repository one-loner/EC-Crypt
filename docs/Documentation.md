# Documentation


EC-crypt is a tool for secure communication. This document describes protocol specification and encryption scheme. 

Algorithms used in EC-crypt:

1. ECDH (curve P-256) 
2. ECDSA (curve P-256)
3. AES-256 (CBC mode)
4. SHA-256
5. SHA-512

Libraries used in python implementation:

1. OpenSSL (cryptographic library)
2. PyElliptic (OpenSSL wrapper)
3. PyQt (GUI)
4. Construct (data parser)

EC-crypt design goals: 

1. Simplicity and ease of use
2. Short public keys
3. Ability to exchange of small or medium-sized files
4. Protocol should use well-defined common algorithms and parameters for re-implementation simplicity


## Message protocol


To communicate, users must generate keypairs and exchange public keys with each other. All keys are unique and have a special identifier - key ID. It is advised to validate IDs personally after public key exchange. After that, users can exchange encrypted messages by any channels, sign open text and files. 

Currently, there are 5 message types and 4 signature types, each signified by a 8-bit magic number. 
Message magic numbers are multiples of 12, signature magic numbers are multiples of 7. 
Magic numbers chosen to have computational advantage and to fit in 8-bit unsigned integer. 

All data is Big Endian. Data strings are prefixed with their length, on which parsing is based. It also makes parsing message in constant time. 


### Message type 12

Message type 12 is a default message type 
* It does not hide IDs of sender or receiving parties
* It does not have attachment file

Example scheme of a typical message for 2 recipients:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |          8-bit number of recipients             |
    +-------------------------------------------------+
    |        (8b len) + ID of first recipient         |
    +-------------------------------------------------+
    |       (8b len) + ID of second recipient         |
    +-------------------------------------------------+
    | (8b len) + token encrypted for first recipient  |
    +-------------------------------------------------+
    | (8b len) + token encrypted for second recipient |
    +-------------------------------------------------+
    |          (8b len) + ephemeral ECDH key          |
    +-------------------------------------------------+
    |          (8b len) + sender public key           |
    +-------------------------------------------------+
    |           (32b len) + encrypted text            |
    +-------------------------------------------------+
    |      (8b len) + ECDSA signature of data above   |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Message type 24

Message type 24 is a default message type with attachment included
* It does not hide IDs of sender or receiving parties
* It does have attachment file

Example scheme of a typical message for 2 recipients:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |          8-bit number of recipients             |
    +-------------------------------------------------+
    |        (8b len) + ID of first recipient         |
    +-------------------------------------------------+
    |       (8b len) + ID of second recipient         |
    +-------------------------------------------------+
    | (8b len) + token encrypted for first recipient  |
    +-------------------------------------------------+
    | (8b len) + token encrypted for second recipient |
    +-------------------------------------------------+
    |          (8b len) + ephemeral ECDH key          |
    +-------------------------------------------------+
    |          (8b len) + sender public key           |
    +-------------------------------------------------+
    |           (32b len) + encrypted text            |
    +-------------------------------------------------+
    |           (32b len) + encrypted attachment      |
    +-------------------------------------------------+
    |      (8b len) + ECDSA signature of data above   |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Message type 36

Message type 36 is an Incognito message type
* It does hide ID of only the sender
* It does not have attachment file

Example scheme of a typical message for 2 recipients:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |          8-bit number of recipients             |
    +-------------------------------------------------+
    |        (8b len) + ID of first recipient         |
    +-------------------------------------------------+
    |       (8b len) + ID of second recipient         |
    +-------------------------------------------------+
    | (8b len) + token encrypted for first recipient  |
    +-------------------------------------------------+
    | (8b len) + token encrypted for second recipient |
    +-------------------------------------------------+
    |          (8b len) + ephemeral ECDH key          |
    +-------------------------------------------------+
    |           (32b len) + encrypted text            |
    +-------------------------------------------------+
    |           (32b len) + encrypted attachment      |
    +-------------------------------------------------+
    |      (8b len) + ECDSA signature of data above   |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Message type 48

Message type 48 is an Incognito message type with attachment
* It does hide ID of only the sender, receiving parties are revealed
* It does have attachment file

Example scheme of a typical message for 2 recipients:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |          8-bit number of recipients             |
    +-------------------------------------------------+
    |        (8b len) + ID of first recipient         |
    +-------------------------------------------------+
    |       (8b len) + ID of second recipient         |
    +-------------------------------------------------+
    | (8b len) + token encrypted for first recipient  |
    +-------------------------------------------------+
    | (8b len) + token encrypted for second recipient |
    +-------------------------------------------------+
    |          (8b len) + ephemeral ECDH key          |
    +-------------------------------------------------+
    |           (32b len) + encrypted text            |
    +-------------------------------------------------+
    |           (32b len) + encrypted attachment      |
    +-------------------------------------------------+
    |      (8b len) + ECDSA signature of data above   |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Message type 60

Message type 60 is a Hidden ID message type
* It does hide IDs of both sender and receiving parties
* Contains any other message type within
* Does not hide number of recipients

Example scheme of a typical message for 2 recipients:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |          8-bit number of recipients             |
    +-------------------------------------------------+
    | (8b len) + token encrypted for first recipient  |
    +-------------------------------------------------+
    | (8b len) + token encrypted for second recipient |
    +-------------------------------------------------+
    |          (8b len) + ephemeral ECDH key          |
    +-------------------------------------------------+
    |           (32b len) + encrypted payload         |
    +-------------------------------------------------+
    |      (8b len) + ECDSA signature of data above   |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Signature type 7

Signature type 7 is a default text signature
* It does not have timestamp
* Added to the text with designated header (clearsign)

Scheme of signature data:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |           (8b len) + signing party key          |
    +-------------------------------------------------+
    | (8b len) + ECDSA signature of text + data above |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Signature type 14

Signature type 14 is a text signature with timestamp
* It does have timestamp
* Added to the text with designated header (clearsign)

Scheme of signature data:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |               32-bit timestamp                  |
    +-------------------------------------------------+
    |           (8b len) + signing party key          |
    +-------------------------------------------------+
    | (8b len) + ECDSA signature of text + data above |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Signature type 21

Signature type 21 is a default file signature
* It does not have timestamp
* Written to a separate file

Scheme of signature data:


    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |           (8b len) + signing party key          |
    +-------------------------------------------------+
    | (8b len) + ECDSA signature of file + data above |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


### Signature type 28

Signature type 21 is a file signature with timestamp
* It does not have timestamp
* Written to a separate file

Scheme of signature data:

    +-------------------------------------------------+
    |              8-bit message type                 |
    +-------------------------------------------------+
    |               32-bit timestamp                  |
    +-------------------------------------------------+
    |           (8b len) + signing party key          |
    +-------------------------------------------------+
    | (8b len) + ECDSA signature of file + data above |
    +-------------------------------------------------+

where (8b len) or (32b len) is a string length integer. 


## Encryption scheme

Overview:
Alice wants to encrypt message (MSG) for Bob and Eve. To do so, following operations are performed by Alice: 

1. Alice generates 512-bit encryption token (token). This token is a key material for encrypting (MSG) and attachment if it is present
2. Alice encrypts message with (token) as a key, getting (ENCRYPTED_MSG)
3. Alice generates 256-bit ephemeral ECDH key (EPH)
4. Alice computes shared secrets between Bobs public key and (EPH), and between Eves key and (EPH), getting (BOB_SECRET) and (EVE_SECRET)
5. Alice encrypts (token) with (BOB_SECRET) and (EVE_SECRET), getting (TOKEN_FOR_BOB) and (TOKEN_FOR_EVE)
6. Alice constructs pre-signed message including type, number of recipients, (TOKEN_FOR_BOB), (TOKEN_FOR_EVE), Alice public key, (ENCRYPTED_MSG)
7. Alice signs construction with her key for tamper resistance and authenticity 

For Incognito and Hidden ID message types, construction is signed by ephemeral keys.

Parameters: 

1. ECDH/ECDSA keys are 256 bit long
2. All keys defined on P-256 curve, a.k.a. prime256v1 or secp256r1
3. Shared secret is derived with SHA-512 hash
4. Data encrypted with AES 256 bit in CBC mode
5. ECDSA signing is applied to SHA-256 hash

These parameters were chosen for a decent security/performance trade-off. Another advantage is that they are commonly used in cryptographic libraries of many languages, which makes implementation in other programming languages much more convenient. 

Keep in mind that compromised static key will allow attacker to forge new messages and read old messages. Attachment file name and/or extension are not revealed to the observer - they are hidden in encrypted text message. 


## Keys


EC-crypt public keys in binary form are short - 33 bytes; 32 bytes for X points, 1 byte for Y point sign. For human-readable public key format, keys are encoded in Base58 and prefixed with "ECCRYPT", becoming 51-52 characters long.

For convenience, each key has its own short ID. This identifier is formed by Base32-encoded 5 bytes of SHA-512 hash of X and Y points of a public key.

Example of Public key: 

    ECCRYPT26s8EkSaqcrZ46LeAivwweEUp8pPvNqyiohUegt6W4f1o

Key ID: YQTCK2UT

Each key can be named locally. Name is stored in "alias" option.  


## Key ring

All keys are stored in ini-style configuration files. Private user keys are called Master Keys, and are stored in file master_keyring.dat Public keys of others are called Contacts and stored in file contact_keyring.dat

Storing format: 

    [section1] 
    option1 = value1
    option2 = value2

    [section2] 
    option1 = value1
    option2 = value2

where sections are key IDs, options are private/public key and label. Key values are Base58-encoded. 

Both files are UTF-8 without BOM. 
