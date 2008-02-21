
from zope.interface import Interface

class ICpsExtendedAuth(Interface):
    """Identifies authenticated users during traversal and simulates the HTTP
    auth headers.
    """

    def expireSession(request):
        """Expire the session of the user owning the given request.
        """
