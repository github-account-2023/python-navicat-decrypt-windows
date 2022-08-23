#!/usr/bin/env python3
import platform
import sys
import winreg
import time
from Crypto.Hash import SHA1
from Crypto.Cipher import Blowfish
from Crypto.Util import strxor

if platform.system().lower() != 'windows':
    print('Windows only!')
    exit(-1)


class Navicat11:

    def __init__(self, Key=b'3DC5CA39'):
        self._Key = SHA1.new(Key).digest()
        self._Cipher = Blowfish.new(self._Key, Blowfish.MODE_ECB)
        self._IV = self._Cipher.encrypt(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF')

    # def EncryptString(self, s: str):
    #     if type(s) != str:
    #         raise TypeError('Parameters must be a str.')
    #     else:
    #         plaintext = s.encode('ascii')
    #         ciphertext = b''
    #         cv = self._IV
    #         full_round, left_length = divmod(len(plaintext), 8)

    #         for i in range(0, full_round * 8, 8):
    #             t = strxor.strxor(plaintext[i:i + 8], cv)
    #             t = self._Cipher.encrypt(t)
    #             cv = strxor.strxor(cv, t)
    #             ciphertext += t

    #         if left_length != 0:
    #             cv = self._Cipher.encrypt(cv)
    #             ciphertext += strxor.strxor(
    #                 plaintext[8 * full_round:], cv[:left_length])

    #         return ciphertext.hex().upper()

    def DecryptString(self, s: str):
        if type(s) != str:
            raise TypeError('Parameters must be str!')
        else:
            plaintext = b''
            ciphertext = bytes.fromhex(s)
            cv = self._IV
            full_round, left_length = divmod(len(ciphertext), 8)

            for i in range(0, full_round * 8, 8):
                t = self._Cipher.decrypt(ciphertext[i:i + 8])
                t = strxor.strxor(t, cv)
                plaintext += t
                cv = strxor.strxor(cv, ciphertext[i:i + 8])

            if left_length != 0:
                cv = self._Cipher.encrypt(cv)
                plaintext += strxor.strxor(
                    ciphertext[8 * full_round:], cv[:left_length])

            return plaintext.decode('ascii')


navicat11 = Navicat11()
ServersTypes = {
    'MySQL Servers': 'Software\\PremiumSoft\\Navicat\\Servers',
    'MariaDB Servers': 'Software\\PremiumSoft\\NavicatMARIADB\\Servers',
    'MongoDB Servers': 'Software\\PremiumSoft\\NavicatMONGODB\\Servers',
    'MSSQL Servers': 'Software\\PremiumSoft\\NavicatMSSQL\\Servers',
    'OracleSQL Servers': 'Software\\PremiumSoft\\NavicatOra\\Servers',
    'PostgreSQL Servers': 'Software\\PremiumSoft\\NavicatPG\\Servers',
}

for ServersTypeName, ServersRegistryPath in ServersTypes.items():
    print('+==================================================+')
    print('|%s|' % ServersTypeName.center(50))
    print('+==================================================+')

    try:
        ServersRegistryKey = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, ServersRegistryPath)
    except OSError:
        print('')
        print('No servers found'.center(50))
        print('')
        continue

    i = 0
    try:
        while True:
            print('')
            ServerName = winreg.EnumKey(ServersRegistryKey, i)
            ServerRegistryKey = winreg.OpenKey(ServersRegistryKey, ServerName)

            try:
                ServerHost = winreg.QueryValueEx(ServerRegistryKey, 'Host')[0]
                ServerPort = winreg.QueryValueEx(ServerRegistryKey, 'Port')[0]
                if ServersTypeName == 'OracleSQL Server':
                    ServerInitialDb = winreg.QueryValueEx(
                        ServerRegistryKey, 'InitialDatabase')[0]
                else:
                    ServerInitialDb = None
                ServerUsername = winreg.QueryValueEx(
                    ServerRegistryKey, 'Username')[0]
                ServerPassword = winreg.QueryValueEx(
                    ServerRegistryKey, 'Pwd')[0]
                if len(ServerPassword) != 0:
                    ServerPassword = navicat11.DecryptString(
                        ServerPassword)

                ServerUseSsh = winreg.QueryValueEx(
                    ServerRegistryKey, 'UseSSH')[0]
                if ServerUseSsh != 0:
                    ServerSshHost = winreg.QueryValueEx(
                        ServerRegistryKey, 'SSH_Host')[0]
                    ServerSshPort = winreg.QueryValueEx(
                        ServerRegistryKey, 'SSH_Port')[0]
                    ServerSshUsername = winreg.QueryValueEx(
                        ServerRegistryKey, 'SSH_Username')[0]
                    ServerSshPassword = winreg.QueryValueEx(
                        ServerRegistryKey, 'SSH_Password')[0]
                    if len(ServerSshPassword) != 0:
                        ServerSshPassword = navicat11.DecryptString(
                            ServerSshPassword)
                else:
                    ServerSshHost = None
                    ServerSshPort = None
                    ServerSshUsername = None
                    ServerSshPassword = None

                print(ServerName.center(50, '-'))
                print('%-18s' % 'Host:', ServerHost)
                print('%-18s' % 'Port:', ServerPort)
                if ServerInitialDb != None:
                    print('%-18s' % 'InitialDatabase:', ServerInitialDb)
                print('%-18s' % 'Username:', ServerUsername)
                print('%-18s' % 'Password:', ServerPassword)
                if ServerUseSsh:
                    print('%-18s' % 'SSH Host:', ServerSshHost)
                    print('%-18s' % 'SSH Port:', ServerSshPort)
                    print('%-18s' % 'SSH Username:', ServerSshUsername)
                    print('%-18s' % 'SSH Password:', ServerSshPassword)
                print(ServerName.center(50, '-'))
            except:
                print('[-] Failed to get info for server "%s". Maybe it is corrupted.' %
                      ServerName, file=sys.stderr)

            winreg.CloseKey(ServerRegistryKey)
            i += 1
    except OSError:
        if i == 0:
            print('No servers is found.')
            print('')
        continue

try:
    time.sleep(600)
except:
    pass
