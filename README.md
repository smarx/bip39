This is a simple implementation of mnemonic seed phrase generation and recovery as described in [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

This code is meant to be education and **is not hardened for production use**. It has not been audited or thoroughly tested, and most error handling has been omitted.

For simplicity's sake, this code directly uses the first 32 bytes of the seed as a private key. (It doesn't do BIP32 or the like.) This is another reason not to actually use this code aside from its intended purpose: explaining how BIP39 works.
