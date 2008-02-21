
CPSExtendedAuth replaces Zope's CookieCrumbler. It can be used with CPS >= 3.4
out-of-the-box. Since no modifications of the user folder are performed, all
CPSUserFolder features are available by default (group management, role
blocking, directory backends, ...)

CPSExtendedAuth authenticates users against a chosen source (at the moment
the possible sources are : CPSDirectories, Kerberos 5, RSA ClearTrust) and
stores the authentication information in the request just before it gets
published.

The password is transmitted only during the authentication phase. A special
authentication is then used afterwards to know that the user has been
authenticated.

The authentication is stored on the server in RAM. It contains information about:

- the browser id (a.k.a ZopeId)
- the name of the remote host.

the user's session expires when the RAM cache is cleaned up (see the RAM cache
manager's 'Cleanup interval' option).

