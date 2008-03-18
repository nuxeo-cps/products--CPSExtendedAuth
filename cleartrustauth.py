##############################################################################
#
# Copyright (c) 2005-2008 Nuxeo and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""A module for using RSA ClearTrust authentication.

$Id$
"""
import logging

from zope.interface import implements
from AccessControl import ClassSecurityInfo
from Acquisition import aq_inner, aq_parent
from Globals import InitializeClass, HTMLFile
from OFS.Folder import Folder
from ZPublisher import BeforeTraverse

from Products.Sessions.BrowserIdManager import getNewBrowserId
from Products.CMFCore.utils import getToolByName

from baseauth import BaseAuth
from interfaces import ICpsExtendedAuth

LOG_KEY = 'CPSExtendedAuth.cleartrustauth'

# This header used to be present and might be present in some configurations
#CLEARTRUST_HEADER_UID = 'ct-remote-user'
CLEARTRUST_HEADER_UID = 'HTTP_CT_REMOTE_USER'
CLEARTRUST_COOKIE_SESSION_A = 'ACTSESSION'
CLEARTRUST_COOKIE_SESSION = 'CTSESSION'

class CleartrustAuth(BaseAuth):
    """Authenticates users against RSA ClearTrust through the checking
    of the HTTP headers without exposing the password in a cookie or in RAM.
    """
    meta_type = 'CPS Cleartrust Auth'

    implements(ICpsExtendedAuth)

    security = ClassSecurityInfo()

    def __call__(self, container, request):
        """Update the request with _auth information.
        """
        log_key = LOG_KEY + '.__call__'
        logger = logging.getLogger(log_key)
        logger.debug("...")
        logger.debug("request._auth = %s" % request._auth)

        # Authorizing other authentications, for example BasicAuthentication
        # from the Zope admin accessing CPS through the ZMI.
        if request._auth is not None:
            logger.debug("Another authentication has already been performed")
            return

        # Authenticating user through the classic acl_users authentication if
        # a name and a password are provided.
        name = request.get(self.name_req_variable)
        password = request.get(self.pw_req_variable)
        #logger.debug("name = %s" % name)
        #logger.debug("password = %s" % password)
        if name is not None and password is not None:
            return BaseAuth.__call__(self, container, request)

        # Now below is treated the RSA ClearTrust mechanism
        ct_session_a = request.cookies.get(CLEARTRUST_COOKIE_SESSION_A)
        ct_session = request.cookies.get(CLEARTRUST_COOKIE_SESSION)
        logger.debug("request.environ = %s" % request.environ)
        logger.debug("ct_session_a = %s" % ct_session_a)
        logger.debug("ct_session = %s" % ct_session)
        if ct_session is None:
            logger.debug("No ClearTrust session: not authorizing")
            return

        if ct_session_a == '%20':
            logger.debug("User has logout from ClearTrust: not authorizing")
            self.expireSession(request)
            return

        ct_uid = request.environ.get(CLEARTRUST_HEADER_UID)
        logger.debug("ct_uid = %s" % ct_uid)
        create_session = False
        if ct_uid is not None:
            # The user has just been authenticated by ClearTrust
            create_session = True
        logger.debug("create_session = %s" % create_session)
        keyset = self._computeCacheKey(request, create_session)

        if not self.ZCacheable_isCachingEnabled():
            logger.error("The cache must be enabled.")
            return

        logger.debug("keyset = %s" % keyset)
        ac = self.ZCacheable_get(keywords=keyset)
        logger.debug("ac = %s" % ac)
        portal = getToolByName(self, 'portal_url').getPortalObject()
        logger.debug("in cache = %s" % portal.extended_authentication_ramcache.getCacheReport())
        if ac is not None:
            logger.debug("Got \"%s\" from the cache." % ac)
            request._auth = ac
            return

        # If the user has a session id, attempt to obtain an authorization string
        # from another mean.
        if keyset['id'] is not None:
            ac = self.getAuthorization(keyset)
            if ac is not None:
                logger.debug("Got an authorization string %s." % ac)

                # store the string in the local cache again
                self.ZCacheable_set(ac, keywords=keyset)
                logger.debug("Added %s to the cache." % ac)

                request._auth = ac
                return

        if ct_uid is None:
            logger.debug("No ClearTrust uid: not authorizing")
            return

        aclu = getToolByName(self, 'acl_users')
        ac = '%s %s' % (aclu.getTrustedAuthString(), ct_uid)
        logger.debug("Put \"%s\" in the cache." % ac)
        self.ZCacheable_set(ac, keywords=keyset)
        self.storeAuthorization(keyset, ac)
        request._auth = ac


    security.declarePublic('expireSession')
    def expireSession(self, request):
        log_key = LOG_KEY + '.expireSession'
        logger = logging.getLogger(log_key)
        logger.debug("...")
        BaseAuth.expireSession(self, request)
        request.RESPONSE.setCookie(CLEARTRUST_COOKIE_SESSION_A, '%20')
        request.RESPONSE.setCookie(CLEARTRUST_COOKIE_SESSION, '%20')
        logger.debug("DONE")

 
InitializeClass(CleartrustAuth)
