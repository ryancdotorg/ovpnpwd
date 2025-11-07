# ovpnpwd.py

## Description

ovpnpwd.py is a Python script that interfaces with OpenVPN’s management
interface to automate authentication with a username, password, and TOTP code.
This may be useful if you use an OpenVPN server that enforces a session
timeout.

**You should not use this software.**

If you use this to connect to your employer’s OpenVPN server, you may face
disciplinary action up to and including termination.

In order to avoid this script being a complete security nightmare, it
deliberately provides no way to use a stored password or TOTP secret.

## Usage

Honestly, if you can’t figure out on your own how to get this working, you
*really* shouldn’t be using it.

## Help

You can file an issue on GitHub, however I may not respond, and it may be used
as evidence against you. This software is being provided without warranty in
the hopes that it may be useful and/or make the world a more interesting place.

## Security

**You should not use this software.**

This software has not been independently audited and may contain bugs. Its
design goal is to circumvent access controls. Your password and TOTP secret
are stored in memory in cleartext. It will be blatantly obvious to anyone who
looks at the server logs that you are using some sort of automation to
authenticate.

## Author(s)

* [Ryan Castellucci](https://rya.nc/about.html)
  ([@ryancdotorg](https://github.com/ryancdotorg))

## License

It’s CC0, do what you want, don’t blame the author(s) when it gets you fired.

## Dedication

This software is released in honor of a friend who I used to work with. They
know who they are, and what they did.
