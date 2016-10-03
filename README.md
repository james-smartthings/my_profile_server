# my_profile_server

Environmental Variables Used:

- DEV_PROFILE_CLIENT_GOOGLE_OAUTH_CLIENT_ID = Your credentials should be obtained from the Google Developer Console (https://console.developers.google.com).
- DEV_PROFILE_CLIENT_GOOGLE_OAUTH_CLIENT_SECRET = Your credentials should be obtained from the Google Developer Console (https://console.developers.google.com).
- DEV_PROFILE_CLIENT_HASH_KEY = Used to authenticate the cookie value using HMAC. It is recommended to use a key with 32 or 64 bytes.
- DEV_PROFILE_CLIENT_BLOCK_KEY = Used to encrypt the cookie value -- set it to nil to not use encryption. If set, the length must correspond to the block size of the encryption algorithm. For AES, used by default, valid lengths are 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
