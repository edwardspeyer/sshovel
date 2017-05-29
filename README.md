sshovel
-------

Encrypt files with `ssh-agent`, bury your secrets.

```
$ sshovel message.txt message.txt.enc
sshovel: encrypting with ssh-key '/tmp/key' and scrypt
sshovel: waiting for scrypt...

$ sshovel message.txt.enc | mocking-spongebob
sshovel: decrypting with /tmp/key and scrypt
sshovel: waiting for scrypt...
hElLo, WoRld!
```

Warning!
--------

sshovel is a proof of concept
and almost certainly a good example of why rolling your own cryptography,
without review, is a bad idea!

Features
--------

- Pure Python 2.7!
- No dependencies!
- ...except for scrypt(1), but you can use openssl(1) instead!
- Single file script!
- Easy to read!
- Self-testing!
- Whimsical name!


Description
-----------

sshovel assumes you are a running an ssh-agent loaded with at least one key.
It will get a list of keys from the agent and pick the first one,
or the one whose comment field matches the `--key` option,
and then asks the ssh-agent to sign some random data with that key.

The signature is used as a passphrase
for the scrypt(1) symmetric encryption tool.
(You can also use openssl's command line tool if scrypt isn't available.)

sshovel inspects the input data to see if it is already encrypted.
If it is, then it will attempt decryption, otherwise encryption is the default.
You can omit arguments to read from `stdin` / write to `stdout`.
You can also use `-`.

```
# date | sshovel | sshovel - file && cat file
Mon May 29 03:04:26 LOL 2017
```

Details
-------

The encrypted file contains the following data:
- sshovel's magic number and version;
- the underlying tool used to encrypt the input file, either "scrypt" or "openssl";
- the public ssh key and the key's comment field;
- the random data whose signature was used as the scrypt/openssl passphrase; and
- the original file, encrypted with scrypt/openssl, and then formatted as Base64.

```
# echo 'Hello, world!' | sshovel
sshovel: reading from stdin
sshovel: encrypting with ssh-key '/tmp/key' and scrypt
sshovel: waiting for scrypt...
-----BEGIN HAZ.CAT/SSHOVEL-----
Version: 1
Encryptor: scrypt
Key: AAAAB3NzaC1yc2EAAAADAQABAAAAgQDVGqi5Lio1Lak+hOH1+LkfIIgfXQ==
Comment: L3RtcC9rZXk=
Nonce: 2a92696986b83ebbeedfbfe6032cf7405f013c8a

c2NyeXB0ABMAAAAIAAAAASCHZ/QwzOzvZDqhboRTeNvypws0iRUS95PaC8kfPEdOtZa9ISVIeXkI
tECUoc67NPONdbcTWxj7o6dCS3B4EEqCs4cZYF+HJKHr+Ci0yiyApBczlfnwtpZbdJrEFqPJqto+
pPU62semvOn8zPvzMoqpS+5cO1KB7cphTbQyrw==
-----END HAZ.CAT/SSHOVEL-----
```

Decrypting involves asking the ssh-agent to sign the random data again,
with the key listed in the encrypted file.
If this is successful then the original scrypt passphrase can be regenerated
and the body decrypted.

The ssh-agent functions that sshovel uses are:

- *[REQUEST_IDENTITIES()][IETF44]*
  
  Get a list of public-keys in the agent.
  
- *[SIGN_REQUEST(public-key, data)][IETF45]*

  Sign `data` with the private key corresponding to `public-key`.

[IETF44]: https://tools.ietf.org/id/draft-miller-ssh-agent-00.html#rfc.section.4.4
[IETF45]: https://tools.ietf.org/id/draft-miller-ssh-agent-00.html#rfc.section.4.5

Another approach I looked at was using the
public and private parts of a key pair to perform public key cryptography.
This has all the usual advantages: being able to encrypt a file for someone else,
and being able to encrypt files for yourself without having to interact with either ssh-agent
or the hardware security module containing the private key.
However, this approach requires having the private key available as a file --
the ssh-agent approach doesn't expose the private key, and if using an HSM,
then you don't have access to the key at all.
This is more restrictive than sshovel's approach.


References
----------

- [SSH Agent Protocol -- Damien Miller, IETF][IETF]:
  the ssh-agent protocol draft RFC.
- [ssh-crypt: encrypt secrets with the SSH Agent][sshcrypt]:
  a similar tool to sshovel, written in golang by @leighmcculloch.
- [Yubico: Using PIV for SSH through PKCS11][Yubico]:
  how to set up a Yubikey with an ssh key-pair.
- [Stanford IT: Yubikey PIV for SSH][Stanford]:
  requiring a physical presence test for the Yubikey ssh key.
- [Twisted Conch: an SSHv2 implementation written in Python][twisted]:
  a good source of documentation on SSH internals.
- [Stack Overflow: Creating a rsa public key from its modulus and exponent][SORSA]
- [Convert an ssh-keygen public key into OpenSSL PEM format][SOPEM]


[IETF]: https://tools.ietf.org/id/draft-miller-ssh-agent-00.html
[sshcrypt]: https://github.com/leighmcculloch/sshcrypt
[Yubico]: https://developers.yubico.com/PIV/Guides/SSH_with_PIV_and_PKCS11.html
[Stanford]: https://itarch.stanford.edu/archives/2016/general/yubikey-piv-for-ssh-on-macs
[twisted]: http://twistedmatrix.com/documents/8.2.0/api/twisted.conch.ssh.keys.Key.html#blob
[SORSA]: https://stackoverflow.com/questions/11541192
[SOPEM]: https://unix.stackexchange.com/a/358709/233034
