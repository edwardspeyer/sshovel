#!/usr/bin/env python

import hashlib
from collections import namedtuple
import fcntl
import os
import os.path
import pty
import shutil
import socket
import struct
import sys
import time

def log(message):
    script = os.path.basename(sys.argv[0])
    message = "{}: {}\n".format(script, message)
    sys.stderr.write(message)


class Scrypt():
    def encrypt(self, in_file, out_file, passphrase):
        pid, fd = self.fork('enc', in_file, out_file)
        self.send_passphrase(fd, passphrase)
        self.send_passphrase(fd, passphrase)
        log("encrypting with scrypt...")
        os.waitpid(pid, 0)
        log("done!")

    def decrypt(self, in_file, out_file, passphrase):
        pid, fd = self.fork('dec', in_file, out_file)
        self.send_passphrase(fd, passphrase)
        log("decrypting with scrypt...")
        os.waitpid(pid, 0)
        log("done!")

    def fork(self, command, in_file, out_file):
        pid, fd = pty.fork()
        if pid == 0:
            os.execlp('scrypt', 'scrypt', command, in_file, out_file)
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
        return pid, fd

    def send_passphrase(self, fd, passphrase):
        self.expect(fd, "passphrase: ", 1)
        os.write(fd, passphrase)
        os.write(fd, "\n")
        os.fsync(fd)
        self.expect(fd, "\r\n", 1)

    def expect(self, fd, phrase, timeout):
        start_time = time.time()
        buf = []
        while 1:
            try:
                c = os.read(fd, 1)
                if c == '':
                    raise Exception("EOF after reading: " + ''.join(buf))
                buf.append(c)
            except OSError:
                duration = time.time() - start_time
                if duration > timeout:
                    msg = "timed out waiting for '{}'".format(phrase)
                    raise Exception(msg)
                time.sleep(0.1)
            if ''.join(buf).endswith(phrase):
                return


class Pack():
    def __init__(self, read, write):
        self._read = read
        self._write = write

    @staticmethod
    def byte(b):
        return struct.pack('>B', b)

    @staticmethod
    def long(v):
        return struct.pack('>L', v)

    @staticmethod
    def string(s):
        length = len(s)
        format = '>L{}s'.format(length)
        return struct.pack(format, length, s)

    def write(self, *values):
        body = ''.join(values)
        length = len(body)
        self._write(self.long(length))
        self._write(body)

    def read_byte(self):
        return self.unpack(1, '>B')

    def read_long(self):
        return self.unpack(4, '>L')

    def read_string(self):
        length = self.read_long()
        format = '{}s'.format(length)
        return self.unpack(length, format)

    def unpack(self, length, format):
        bytes = self._read(length)
        return struct.unpack(format, bytes)[0]


class SSH():
    Key = namedtuple('Key', 'blob comment')

    # https://tools.ietf.org/id/draft-miller-ssh-agent-00.html
    AGENTC_REQUEST_IDENTITIES = 11
    AGENT_IDENTITIES_ANSWER = 12
    AGENTC_SIGN_REQUEST = 13
    AGENT_SIGN_RESPONSE = 14
    AGENT_RSA_SHA2_256 = 2
    AGENT_RSA_SHA2_512 = 4

    def __init__(self):
        path = os.environ.get('SSH_AUTH_SOCK')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        sock.connect(path)
        self.pack = Pack(sock.recv, sock.sendall)

    def identities(self):
        p = self.pack
        p.write(p.byte(SSH.AGENTC_REQUEST_IDENTITIES))
        length = p.read_long()
        response = p.read_byte()
        assert response == SSH.AGENT_IDENTITIES_ANSWER
        num_keys = p.read_long()
        result = []
        for _ in range(num_keys):
            blob = p.read_string()
            comment = p.read_string()
            key = SSH.Key(blob, comment)
            result.append(key)
        return result

    def sign(self, key, message, flags=0):
        p = self.pack
        p.write(
            p.byte(SSH.AGENTC_SIGN_REQUEST),
            p.string(key.blob),
            p.string(message),
            p.long(flags)
        )
        len = p.read_long()
        response = p.read_byte()
        assert response == SSH.AGENT_SIGN_RESPONSE
        signature = p.read_string()
        return signature


class SSHScrypt():
    MAGIC = "https://haz.cat/ssh-crypt"
    
    def encrypt(self, in_file, out_file, ssh, key):
        nonce = os.urandom(128)
        signature = ssh.sign(key, nonce)
        passphrase = hashlib.sha1(signature).hexdigest()
        tmp_file = self.tmp_for(out_file)
        Scrypt().encrypt(in_file, tmp_file, passphrase)
        with open(out_file, 'w') as out_io:
            out_io.write(Pack.string(SSHScrypt.MAGIC))
            out_io.write(Pack.string(nonce))
            with open(tmp_file) as tmp_io:
                shutil.copyfileobj(tmp_io, out_io)

    def decrypt(self, in_file, out_file, ssh, key):
        passphrase = None
        tmp_file = self.tmp_for(out_file)
        with open(in_file) as in_io:
            p = Pack(in_io.read, in_io.write)
            magic = p.read_string()
            nonce = p.read_string()
            signature = ssh.sign(key, nonce)
            passphrase = hashlib.sha1(signature).hexdigest()
            with open(tmp_file, 'w') as tmp_io:
                shutil.copyfileobj(in_io, tmp_io)
        Scrypt().decrypt(tmp_file, out_file, passphrase)

    @staticmethod
    def tmp_for(file):
        dir = os.path.dirname(file)
        if dir == '':
            dir = '.'
        basename = os.path.basename(file)
        return '{}/.{}.ssh-scrypt'.format(dir, basename)

"""
import StringIO
s = StringIO.StringIO()

p = Pack(s.read, s.write)
p.write(p.byte(23), p.string("Hello!"))

s.seek(0)

print(p.read_long())
print(p.read_byte())
print(p.read_string())
"""

"""
Scrypt().enc('in', 'out', 'PASSPHRASE')
Scrypt().dec('out', 'in2', 'PASSPHRASE')
"""

ssh = SSH()
key = ssh.identities()[0]
SSHScrypt().encrypt('in', 'out', ssh, key)
SSHScrypt().decrypt('out', 'in2', ssh, key)
