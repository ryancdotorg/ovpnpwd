#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0+

import sys
import getpass
import argparse

from base64 import b64encode as b64e, b64decode as b64d

# optional import, only needed if using 2FA
try:
    from pyotp import TOTP
except ImportError:
    TOTP = None

from twisted.python import log

from twisted.protocols.basic import LineReceiver

from twisted.internet import reactor
from twisted.internet.stdio import StandardIO
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import clientFromString

from twisted.application.internet import ClientService

# The following config needs to be added to OpenVPN's config file
"""
management /run/ovpn-XXXX.s unix
management-hold
management-query-passwords
management-client-user YOUR_USER_ID
management-client-group YOUR_USER_ID

auth-user-pass
auth-retry interact
"""

def gettext(prompt, echo):
    result = None
    if echo:
        result = input(prompt)
    else:
        result = getpass.getpass(prompt)

    return result.rstrip("\r\n")

class OvpnMgmt(LineReceiver):
    from os import linesep as delimiter

    def __init__(self, shm):
        shm['ovpnMgmt'] = self
        self.shm = shm

    def connectionMade(self):
        self.sendLine("log on")
        pass

    def connectionLost(self, reason):
        self.shm['ovpnMgmt'] = None
        log.msg("lost connection: %s" % reason)

    def sendAuthUi(self, line):
        if self.shm['authUi']:
            self.shm['authUi'].sendLine(line)

    def authedOkay(self, failures=None):
        if failures is None or self.shm['authFailures'] == failures:
            self.shm['authFailures'] = 0
            self.sendLine("forget-passwords")

    def lineReceived(self, line):
        shm = self.shm
        line = line.rstrip("\r")
        self.sendAuthUi(line)

        if line[0] == ">":
            (msgType, msgData) = line[1:].split(":", 1)
            if msgType == "HOLD" and shm['hold'] == 0:
                self.sendLine("hold release")
            elif msgType == "PASSWORD":
                if msgData.startswith("Need 'Auth' username/password"):
                    if "SC:" in msgData:
                        if shm['totp'] is None:
                            log.msg("TOTP required but unavailable, exiting")
                            reactor.stop()
                        else:
                            password = "SCRV1:%s:%s" % (
                                b64e(shm['pass']), b64e(shm['totp'].now())
                            )
                    else:
                        password = shm['pass']

                    if shm['authFailures'] < 2:
                        self.sendLine('username Auth %s' % shm['user'])
                        self.sendLine('password Auth %s' % password)
                        # periodic reauthentication may not give an auth token,
                        # so if we don't get notified of a failure within 60
                        # seconds, assume success
                        reactor.callLater(60, self.authedOkay, shm['authFailures'])
                    else:
                        log.msg("authentication failed too many times, exiting")
                        reactor.stop()
                elif msgData[0:27] == "Verification Failed: 'Auth'":
                    shm['authFailures'] += 1
                elif msgData[0:11] == "Auth-Token:":
                    self.authedOkay()

class AuthUi(LineReceiver):
    from os import linesep as delimiter

    def __init__(self, shm):
        shm['authUi'] = self
        self.shm = shm

    def sendOvpnMgmt(self, line):
        if self.shm['ovpnMgmt']:
            self.shm['ovpnMgmt'].sendLine(line)

    def connectionMade(self):
        self.shm['authFailures'] = 0
        self.shm['connect']()

    def lineReceived(self, line):
        shm = self.shm
        line = line.rstrip("\r\n")

        if line == "down":
            shm['hold'] = 1
            self.sendOvpnMgmt("hold on")
            self.sendOvpnMgmt("signal SIGUSR1")
        elif line == "up":
            shm['hold'] = 0
            self.sendOvpnMgmt("hold release")
        else:
            self.sendOvpnMgmt(line)

class OvpnMgmtClientFactory(Factory):
    def __init__(self, shm):
        self.shm = shm

    def buildProtocol(self, addr):
        log.msg("connected")
        #self.resetDelay()
        return OvpnMgmt(self.shm)

def main():
    parser = argparse.ArgumentParser(description='Automated authentication for daemonized OpenVPN clients')
    parser.add_argument('--totp', dest='totp', action='store_true', help='prompt for TOTP secret')
    parser.add_argument('--user', dest='user', action='store', default=None, help='username')
    parser.add_argument('socket', metavar='SOCK', help='management socket path')
    args = parser.parse_args()
    sockPath = args.socket

    shm = {
        'ovpnMgmt': None,
        'authUi': None,
        'user': args.user,
        'pass': None,
        'totp': None,
        'hold': 0
    }

    # Prompt for credentials on startup
    while shm['user'] is None or shm['user'] == "":
        shm['user'] = gettext("Username: ", True)

    while shm['pass'] is None or shm['pass'] == "":
        shm['pass'] = gettext("Password: ", False)

        # handle totp secret provided with password
        if shm['pass'][0:9] == 'TOTP-2FA:':
            if TOTP is None:
                # trigger explicit totp prompt, which will fail and abort
                args.totp = True
                break

            try:
                parts = shm['pass'].split(':')
                shm['pass'] = b64d(parts[1])
                shm['totp'] = TOTP(b64d(parts[2]))
                parts = None
            except:
                print("Invalid 2FA data")
                shm['totp'] = None
                parts = None

    # prompt for totp secret if requested
    if args.totp:
        if TOTP is None:
            print("Please install pyotp for TOTP 2FA supported")
            sys.exit(1)

        while shm['totp'] is None or shm['totp'] == "":
            try:
                shm['totp'] = TOTP(gettext("TOTP: ", False))
            except TypeError:
                print("Invalid TOTP secret")
                shm['totp'] = None

        print("\033[31mWARNING: Automated re-authentication is obvious in logs. Circumvention of corporate\033[0m")
        print("\033[31msecurity policies may result in disciplinary action up to and including termination.\033[0m")

    log.startLogging(sys.stdout)
    log.msg("started")

    endpoint = clientFromString(reactor, "unix:path="+sockPath)
    factory = OvpnMgmtClientFactory(shm)
    ovpnMgmtSvc = ClientService(endpoint, factory)
    shm['connect'] = lambda: ovpnMgmtSvc.startService()
    StandardIO(AuthUi(shm))
    reactor.run()

if __name__ == '__main__':
    main()
