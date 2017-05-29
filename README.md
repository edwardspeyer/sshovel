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

Features
--------

- Pure Python 2.7!
- No dependencies!
- ...except for scrypt(1), but you can use openssl(1) instead!
- Single file script!
- Easy to read!
- Self-testing!


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


License
-------

MIT License

Copyright (c) 2017 Edward Speyer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

TODO:
----

- Handle agent errors!  agent.sign() may refuse none if we are missing the key,
  or if the agent prompts us with a dialog that we dismiss.  We should look up
  keys to see if the agent has them, before using them to sign data?
"""

from collections import namedtuple
import StringIO
import argparse
import atexit
import base64
import fcntl
import hashlib
import os
import os.path
import pty
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest


class UserException(Exception):
    """
    Exception for alerting the user with messages (and not full stack traces.)
    """
    pass


def log(message):
    script = os.path.basename(sys.argv[0])
    message = "{}: {}\n".format(script, message)
    sys.stderr.write(message)


class Packer(object):
    """
    Pack and unpack length prefixed binary data, as defined by the SSH
    standards.
    """

    @staticmethod
    def byte(a_byte):
        return struct.pack('>B', a_byte)

    @staticmethod
    def long(a_long):
        return struct.pack('>L', a_long)

    @staticmethod
    def string(a_string):
        length = len(a_string)
        template = '>L{}s'.format(length)
        return struct.pack(template, length, a_string)

    @classmethod
    def from_socket(cls, a_socket):
        return cls(a_socket.recv, a_socket.sendall)

    @classmethod
    def from_file(cls, a_file):
        return cls(a_file.read, a_file.write)

    def __init__(self, read_fn, write_fn):
        self.read_fn = read_fn
        self.write_fn = write_fn

    def write(self, *values):
        body = ''.join(values)
        length = len(body)
        self.write_fn(self.long(length))
        self.write_fn(body)

    def read_byte(self):
        return self.unpack(1, '>B')

    def read_long(self):
        return self.unpack(4, '>L')

    def read_string(self):
        length = self.read_long()
        template = '{}s'.format(length)
        return self.unpack(length, template)

    def unpack(self, length, template):
        some_bytes = self.read_fn(length)
        return struct.unpack(template, some_bytes)[0]


class PackerTest(unittest.TestCase):
    def test_read_then_write(self):
        message = "Hello, world!"
        sio = StringIO.StringIO()
        pack = Packer.from_file(sio)
        pack.write(pack.byte(99), pack.string(message))
        sio.seek(0)
        self.assertEqual(pack.read_long(), 18, "total pack length")
        self.assertEqual(pack.read_byte(), 99, "packed byte")
        self.assertEqual(pack.read_string(), message, "packed string")


class SSHAgentConnection(object):
    """
    Interface to a running ssh-agent(1)
    """

    Key = namedtuple('Key', 'blob comment')

    # https://tools.ietf.org/id/draft-miller-ssh-agent-00.html
    AGENTC_REQUEST_IDENTITIES = 11
    AGENT_IDENTITIES_ANSWER = 12
    AGENTC_SIGN_REQUEST = 13
    AGENT_SIGN_RESPONSE = 14
    AGENT_RSA_SHA2_256 = 2
    AGENT_RSA_SHA2_512 = 4
    AGENT_FAILURE = 5

    def __init__(self, socket_path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        sock.connect(socket_path)
        self.packer = Packer.from_socket(sock)

    def identities(self):
        self.packer.write(
            self.packer.byte(SSHAgentConnection.AGENTC_REQUEST_IDENTITIES))
        _ = self.packer.read_long()  # length
        response = self.packer.read_byte()
        assert response == SSHAgentConnection.AGENT_IDENTITIES_ANSWER
        num_keys = self.packer.read_long()
        result = []
        for _ in range(num_keys):
            blob = self.packer.read_string()
            comment = self.packer.read_string()
            key = SSHAgentConnection.Key(blob, comment)
            result.append(key)
        return result

    def sign(self, key_blob, message, flags=0):
        self.packer.write(
            self.packer.byte(SSHAgentConnection.AGENTC_SIGN_REQUEST),
            self.packer.string(key_blob),
            self.packer.string(message),
            self.packer.long(flags)
        )
        _ = self.packer.read_long()  # length
        response = self.packer.read_byte()
        if response == SSHAgentConnection.AGENT_FAILURE:
            return None
        assert response == SSHAgentConnection.AGENT_SIGN_RESPONSE
        signature = self.packer.read_string()
        return signature


class SSHTestFixture(object):
    """
    Set up a real ssh-agent(1) and load it with a test key, and provide a way
    to kill the agent.
    """

    TEST_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD0OCPZ50akyXxhyFz/JdCTZISvHJ+nFOnXMHKQzF3Q3fAbXGVM
jEU2Wer+owj6s4wxuNmd6g3XAyyomCSRoxE6txNpQ10Yay4ZUMhO3XDr3zN5WBhd
6dqDjNLsrfu5mjy9aWFZDpBYnmRnOQBeLGxNQE6shbwOAzsixirmiUyXBQIDAQAB
AoGAZwCallgGIpBcZn10Q6S2UMQPdi/TYkveyITFfS7Ezsgccd3JV7y9oEvSYi1v
JxW9Jmd5WTITPkE3f7ATlF07cT5EZaHPMHm02GJegopN1AW2caoN2N+FHpe2cnOW
0vLtV+dQ0j5QnCWOfPpM70wYqEwvO+tC9uIaIOCBVTdyF20CQQD7IxTeZjiirZ0M
SlSPZmNRlFBRUkHjc4I7A5weV5L5YR/LWN2W/RL0j+v60L18Uld0pGcDuYX1Fg42
oUYEazaLAkEA+PLEMtU7vh3d9PtyDyIG7prcAJnUljwybRgZoVQNMsMxxONbSoAb
B9tw8irock7zjkPYsqvjSAxcfV1I+J6qrwJBAJaFQEzMF8XpKOfk5SnNxFlw+3LC
Spt47+VPFJNbCcxOWjAW4zlMFcBfQqDh27BX6fMPVm71E0UCIyK7JqwfVmECQAJ8
8qcLaIhy5ff/11j9XxJda9t5rh0+Rsa+Wes52tPqDYJJP21UMHD4qX1SHnaeAWMn
nG/UtfXPYdFC8GrDszMCQHNHjkRPhgnFKZBIqg6CjWE0wVWdZRWwLrP7a2YQsX4A
aZkvLueqxAr5SzU9sTiL6tBQAEaESEHOTm11g+IRmFA=
-----END RSA PRIVATE KEY-----
"""

    def __init__(self):
        self.start_agent()
        self.load_keys()

    def start_agent(self):
        output = subprocess.check_output('ssh-agent')
        self.socket_path = re.search('SSH_AUTH_SOCK=(.+?);', output).group(1)
        pid_str = re.search(r'SSH_AGENT_PID=(\d+)', output).group(1)
        self.agent_pid = int(pid_str)

    def load_keys(self):
        key_name = 'a_test_ssh_key'
        key_file = tempfile.NamedTemporaryFile(
            dir='/tmp',
            prefix=key_name + '.')
        key_file.write(self.TEST_KEY)
        key_file.flush()
        self._ssh_add(key_file.name)

    def delete_keys(self):
        self._ssh_add('-D')

    def _ssh_add(self, *args):
        command = ['ssh-add']
        command.extend(args)
        env = dict(os.environ)
        env['SSH_AUTH_SOCK'] = self.socket_path
        subprocess.check_call(command, env=env, stderr=subprocess.PIPE)

    def stop(self):
        os.kill(self.agent_pid, signal.SIGKILL)


class SSHAgentConnectionTest(unittest.TestCase):
    def setUp(self):
        self.ssh_fixture = SSHTestFixture()

    def test_identities(self):
        ssh = SSHAgentConnection(self.ssh_fixture.socket_path)
        keys = ssh.identities()
        self.assertEqual(len(keys), 1, "number of keys loaded in agent")

    def test_sign(self):
        ssh = SSHAgentConnection(self.ssh_fixture.socket_path)
        key = ssh.identities()[0]
        message = "Hello, world!"
        expected_digest = "791c659db0f314126ff0226beaa25aa6b8c4f00e"
        for _ in range(0, 3):
            signature = ssh.sign(key.blob, message)
            actual_digest = hashlib.sha1(signature).hexdigest()
            self.assertEqual(expected_digest, actual_digest)

    def tearDown(self):
        self.ssh_fixture.stop()


class Encryptor(object):
    """
    Interface / superclass for encryptors, plus some tools for finding
    subclasses.
    """

    def encrypt(self, in_file, out_file, passphrase):
        pass

    def decrypt(self, in_file, out_file, passphrase):
        pass

    def name(self):
        return Encryptor.name_of(self.__class__)

    @staticmethod
    def name_of(a_cls):
        return a_cls.__name__.lower()

    @staticmethod
    def all_encryptor_names():
        return [
            Encryptor.name_of(cls)
            for cls in Encryptor.__subclasses__()]

    @staticmethod
    def instance_of(name):
        for cls in Encryptor.__subclasses__():
            if Encryptor.name_of(cls) == name.lower():
                return cls()
        raise UserException("unknown encryptor '{}'".format(name))


class OpenSSL(Encryptor):
    def encrypt(self, in_file, out_file, passphrase):
        self._openssl('-e', in_file, out_file, passphrase)

    def decrypt(self, in_file, out_file, passphrase):
        self._openssl('-d', in_file, out_file, passphrase)

    @staticmethod
    def _openssl(command, in_file, out_file, passphrase):
        tmp = tempfile.NamedTemporaryFile()
        tmp.write(passphrase)
        tmp.flush()
        command = [
            'openssl', 'aes-256-cbc',
            command,
            '-a', '-salt',
            '-kfile', tmp.name,
            '-in', in_file,
            '-out', out_file]
        subprocess.check_call(command)


class Scrypt(Encryptor):
    """
    Interface to the scrypt(1) command line tool.
    """

    def __init__(self, encrypt_options=[], decrypt_options=[]):
        self.encrypt_options = encrypt_options
        self.decrypt_options = decrypt_options

    def encrypt(self, in_file, out_file, passphrase):
        pid, fd = self._fork('enc', self.encrypt_options, in_file, out_file)
        self._send_passphrase(fd, passphrase)
        self._send_passphrase(fd, passphrase)
        log("waiting for scrypt...")
        self._wait(pid, fd)

    def decrypt(self, in_file, out_file, passphrase):
        pid, fd = self._fork('dec', self.decrypt_options, in_file, out_file)
        self._send_passphrase(fd, passphrase)
        log("waiting for scrypt...")
        self._wait(pid, fd)

    @staticmethod
    def _fork(command, options, in_file, out_file):
        args = [command]
        args.extend(options)
        args.append(in_file)
        args.append(out_file)
        pid, fd = pty.fork()
        if pid == 0:
            os.execlp('scrypt', 'scrypt', *args)
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
        return pid, fd

    def _send_passphrase(self, fd, passphrase):
        self._expect(fd, 1, "passphrase: ")
        os.write(fd, passphrase)
        os.write(fd, "\n")
        os.fsync(fd)
        self._expect(fd, 1, "\r\n")

    @staticmethod
    def _read(fd, timeout):
        return Scrypt._expect(fd, timeout, None)

    @staticmethod
    def _expect(fd, timeout, phrase):
        start_time = time.time()
        buf = []
        while 1:
            try:
                byte = os.read(fd, 1)
                if byte == '':  # EOF
                    if phrase is None:
                        break
                    else:
                        msg = "EOF after reading: " + ''.join(buf)
                        raise UserException(msg)
                buf.append(byte)
            except OSError:
                duration = time.time() - start_time
                if duration > timeout:
                    msg = "timed out waiting for '{}'".format(phrase)
                    raise UserException(msg)
                time.sleep(0.1)
            if phrase is not None and ''.join(buf).endswith(phrase):
                break
        return ''.join(buf)

    @staticmethod
    def _wait(pid, fd):
        tail = Scrypt._read(fd, 3)
        pid, status = os.waitpid(pid, 0)
        status = status >> 8
        if status != 0:
            raise UserException(
                "command exited with status %d and output '%s'" %
                (status, tail))


class TestFiles(object):
    """
    Some test files, the first of which contains a known message.  Useful when
    testing encrypt(f0, f1) and decrypt(f1, f2).
    """

    def __init__(self, message):
        self.f0 = tempfile.NamedTemporaryFile()
        self.f1 = tempfile.NamedTemporaryFile()
        self.f2 = tempfile.NamedTemporaryFile()
        self.f0.write(message)
        self.f0.flush()


def assert_encryptor(test, encryptor):
    message = 'Hello, world!'
    passphrase = 'PASSPHRASE'
    files = TestFiles(message)
    encryptor.encrypt(files.f0.name, files.f1.name, passphrase)
    encryptor.decrypt(files.f1.name, files.f2.name, passphrase)
    test.assertEqual(
        message,
        files.f2.read(),
        encryptor.__class__.__name__)


class OpenSSLTest(unittest.TestCase):
    def test_encryptor(self):
        assert_encryptor(self, OpenSSL())


class ScryptTest(unittest.TestCase):
    def test_encryptor(self):
        assert_encryptor(self, Scrypt(['-t', '0.1'], []))


class SSHEncryptor(object):
    """
    Wrapper around an Encryptor that uses an ssh-agent(1) to generate the
    encryptor's passphrase.
    """

    MAGIC = "HAZ.CAT/SSHOVEL"
    VERSION = 1

    def encrypt(self, in_file, out_file, ssh, key, encryptor):
        nonce = hashlib.sha1(os.urandom(64)).hexdigest()
        signature = ssh.sign(key.blob, nonce)
        passphrase = hashlib.sha1(signature).hexdigest()
        tmp_file = self.tmp_for(out_file)
        encryptor.encrypt(in_file, tmp_file, passphrase)
        with open(out_file, 'w') as out_io:
            out_io.write(self._begin_line())
            self._write_header(out_io, 'Version', self.VERSION)
            self._write_header(out_io, 'Encryptor', encryptor.name())
            self._write_header(out_io, 'Key', base64.b64encode(key.blob))
            self._write_header(
                out_io,
                'Comment',
                base64.b64encode(key.comment))
            self._write_header(out_io, 'Nonce', nonce)
            out_io.write("\r\n")
            with open(tmp_file, 'r') as tmp_io:
                base64.encode(tmp_io, out_io)
            out_io.write("-----END {}-----\r\n".format(self.MAGIC))

    def decrypt(self, in_file, out_file, ssh):
        b64_tmp = tempfile.NamedTemporaryFile()
        key_blob = None
        key_comment = None
        nonce = None
        encryptor_name = None
        with open(in_file, 'r') as in_io:
            if not self._read_magic(in_io):
                raise UserException(
                    "unrecognized format; did not find magic number '{}'"
                    .format(self.MAGIC))
            version = self._read_header(in_io, 'Version')
            encryptor_name = self._read_header(in_io, 'Encryptor')
            key_blob = base64.b64decode(self._read_header(in_io, 'Key'))
            key_comment = base64.b64decode(self._read_header(in_io, 'Comment'))
            nonce = self._read_header(in_io, 'Nonce')
            for line in in_io:
                # Ignore the ----END line:
                if line[0] == '-':
                    break
                b64_tmp.write(line.rstrip())
        b64_tmp.flush()
        b64_tmp.seek(0)
        enc_tmp = tempfile.NamedTemporaryFile()
        base64.decode(b64_tmp, enc_tmp)
        enc_tmp.flush()
        enc_tmp.seek(0)
        log('decrypting with {} and {}'.format(key_comment, encryptor_name))
        signature = ssh.sign(key_blob, nonce)
        if signature is None:
            raise UserException(
                "file is encrypted with a key we don't have: {}".format(
                    key_comment))
        passphrase = hashlib.sha1(signature).hexdigest()
        encryptor = Encryptor.instance_of(encryptor_name)
        encryptor.decrypt(enc_tmp.name, out_file, passphrase)

    def is_file_encrypted(self, in_file):
        with open(in_file, 'r') as f:
            return self._read_magic(f)

    def _read_magic(self, f):
        expected = self._begin_line()
        actual = f.read(len(expected))
        return actual == expected

    def _read_header(self, f, key):
        line = f.readline().rstrip()
        actual_key, value = line.split(': ')
        if actual_key != key:
            raise UserException(
                "did not find expected key {} in line: {}"
                .format(key, line))
        return value

    def _write_header(self, f, key, value):
        f.write('{}: {}\r\n'.format(key, value))

    @staticmethod
    def tmp_for(path):
        basename = os.path.basename(path)
        fd, tmp_file = tempfile.mkstemp(prefix='.'+basename)
        os.close(fd)
        atexit.register(lambda: os.remove(tmp_file))
        return tmp_file

    def _begin_line(self):
        return '-----BEGIN {}-----\r\n'.format(self.MAGIC)

    def _end_line(self):
        return '-----END {}-----\r\n'.format(self.MAGIC)


class SSHEncryptorTest(unittest.TestCase):
    def setUp(self):
        self.ssh_fixture = SSHTestFixture()

    def test_encrypt_then_decrypt(self):
        message = "Hello, secret world!"
        files = TestFiles(message)
        ssh = SSHAgentConnection(self.ssh_fixture.socket_path)
        key = ssh.identities()[0]
        encryptor = OpenSSL()
        SSHEncryptor().encrypt(
            files.f0.name, files.f1.name, ssh, key, encryptor)
        SSHEncryptor().decrypt(files.f1.name, files.f2.name, ssh)
        self.assertEqual(message, files.f2.read())

    def test_missing_key(self):
        message = "Hello, secret world!"
        files = TestFiles(message)
        ssh = SSHAgentConnection(self.ssh_fixture.socket_path)
        key = ssh.identities()[0]
        encryptor = OpenSSL()
        SSHEncryptor().encrypt(
            files.f0.name, files.f1.name, ssh, key, encryptor)
        self.ssh_fixture.delete_keys()
        ex = None
        try:
            SSHEncryptor().decrypt(files.f1.name, files.f2.name, ssh)
        except UserException as ex:
            pass
        self.assertIsNotNone(ex)
        self.assertTrue("key we don't have" in str(ex))

    def tearDown(self):
        self.ssh_fixture.stop()


class Main(object):
    def __init__(self, args):
        args = self.parse_args(args)
        try:
            self._main(args)
        except UserException as ex:
            log(ex.message)
            sys.exit(1)

    def _main(self, args):
        if args.test is not None:
            unittest_args = [__file__]
            unittest_args.extend(args.test)
            unittest.main(argv=unittest_args)

        encryptor = Encryptor.instance_of(args.encryptor)
        ssh = self.find_agent()
        keys = ssh.identities()
        if not keys:
            raise UserException("ssh agent has no keys")

        key = keys[0]
        if args.key:
            key = self.match_key(keys, args.key)

        in_file = args.in_file.name
        in_tmp = None
        if in_file == '<stdin>':
            log('reading from stdin')
            in_tmp = tempfile.NamedTemporaryFile()
            shutil.copyfileobj(args.in_file, in_tmp)
            in_tmp.flush()
            in_file = in_tmp.name

        out_file = args.out_file.name
        out_tmp = None
        if out_file == '<stdout>':
            out_tmp = tempfile.NamedTemporaryFile()
            out_file = out_tmp.name

        ssh_encryptor = SSHEncryptor()

        if ssh_encryptor.is_file_encrypted(in_file):
            ssh_encryptor.decrypt(in_file, out_file, ssh)
        else:
            log("encrypting{} with ssh-key '{}' and {}".format(
                (args.out_file == '-' and ' to stdout' or ''),
                key.comment,
                args.encryptor))
            ssh_encryptor.encrypt(in_file, out_file, ssh, key, encryptor)

        if out_tmp is not None:
            out_tmp.seek(0)
            shutil.copyfileobj(out_tmp, sys.stdout)
            sys.stdout.flush()

    def parse_args(self, args):
        epilogue = u"""\
examples:

  - Default is to use scrypt(1) to encrypt:

      $ shovel message.txt message.txt.enc


  - If the input is encrypted, then the default action is to decrypt:

      $ shovel message.txt.enc
      Hello, world!


  - Use a specific agent key (only needed for encrypt):

      $ shovel --key my_other_key
\u00A0
"""
        parser = argparse.ArgumentParser(
            usage='%(prog)s [--with TOOL] [IN] [OUT]',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description='Encrypt files with ssh-agent, bury your secrets',
            epilog=epilogue)
        parser.add_argument(
            '--key',
            metavar='MATCH',
            help='use the ssh key whose comment matches MATCH')
        parser.add_argument(
            '--with',
            dest='encryptor',
            default='scrypt',
            metavar='TOOL',
            choices=Encryptor.all_encryptor_names(),
            help='encrypt with "scrypt" (default) or "openssl"')
        parser.add_argument(
            '--test',
            nargs='*',
            metavar='ARGS',
            help='run the test suite')
        parser.add_argument(
            'in_file',
            nargs='?',
            type=argparse.FileType('r'),
            default=sys.stdin,
            metavar='IN',
            help='optional path, or "-" for stdin, which is the default')
        parser.add_argument(
            'out_file',
            nargs='?',
            type=argparse.FileType('w'),
            default=sys.stdout,
            metavar='OUT',
            help='as above, with stdout as the default')
        return parser.parse_args(args)

    def find_agent(self):
        socket_path = os.environ.get('SSH_AUTH_SOCK')
        if socket_path == "":
            raise UserException("SSH_AUTH_SOCK is empty or unset")
        return SSHAgentConnection(socket_path)

    def match_key(self, keys, pattern):
        matches = []
        for candidate in keys:
            if pattern in candidate.comment:
                matches.append(candidate)
        if len(matches) == 1:
            return matches[0]
        elif not matches:
            raise UserException(
                "no ssh key matched '{}'; known keys: {}"
                .format(pattern, [k.comment for k in keys]))
        elif len(matches) > 2:
            raise UserException(
                "more than one key matched '{}': {}"
                .format(pattern, [k.comment for k in matches]))


class MainTest(unittest.TestCase):
    message = "SUPER SECRET FILE CONTENTS"

    def setUp(self):
        self.files = TestFiles(self.message)
        self.ssh_fixture = SSHTestFixture()
        os.environ['SSH_AUTH_SOCK'] = self.ssh_fixture.socket_path

    def test_encrypt(self):
        Main(['--with', 'openssl', self.files.f0.name, self.files.f1.name])
        Main([self.files.f1.name, self.files.f2.name])
        self.assertEqual(self.message, self.files.f2.read())

    def tearDown(self):
        self.ssh_fixture.stop()


Main(sys.argv[1:])
