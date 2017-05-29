# sshovel
Encrypt files with ssh-agent, bury your secrets

```
$ sshovel message.txt message.txt.enc
sshovel: encrypting with ssh-key '/tmp/key' and scrypt
sshovel: waiting for scrypt...

$ sshovel message.txt.enc | mocking-spongebob
sshovel: decrypting with /tmp/key and scrypt
sshovel: waiting for scrypt...
hElLo, WoRld!
```
