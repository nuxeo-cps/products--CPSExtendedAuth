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
"""
$Id$
"""
import logging

from zope.interface import implements
from AccessControl import ClassSecurityInfo
from Acquisition import aq_inner, aq_parent
from Globals import InitializeClass, HTMLFile
from OFS.Folder import Folder
from OFS.Cache import Cacheable
from ZPublisher import BeforeTraverse

from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.Sessions.BrowserIdManager import getNewBrowserId
from Products.CMFCore.utils import getToolByName

from interfaces import ICpsExtendedAuth

SESSION_ID_VAR = '_cpsauth_id'

logger = logging.getLogger('CPSExtendedAuth.baseauth')

class BaseAuth(Folder, Cacheable):
    """Authenticates users against the User Folder without exposing the
    password in a cookie or in RAM.

    Authentication can be made against any given mechanism in super class
    inheriting from this class without exposing the password in a cookie
    or in RAM.
    """
    meta_type = 'CPS Extended Auth'

    implements(ICpsExtendedAuth)

    name_req_variable = '__ac_name'
    pw_req_variable = '__ac_password'

    manage_options = (
        Folder.manage_options +
        Cacheable.manage_options
    )

    security = ClassSecurityInfo()

    def __call__(self, container, request):
        """Update the request with _auth information.
        """
        # Is the request authenticating?
        password = request.get(self.pw_req_variable)
        create_session = False
        if password is not None:
            self._delRequestVar(request, self.pw_req_variable)
            create_session = True
        keyset = self._computeCacheKey(request, create_session)

        if not self.ZCacheable_isCachingEnabled():
            logger.error("The cache must be enabled.")
            return

        ac = self.ZCacheable_get(keywords=keyset)
        if ac is not None:
            logger.debug("Got %s from the cache." % ac)
            request._auth = ac
            return

        # If the user has a session id, attempt to obtain an authorization string
        # (e.g. from a remote server)
        if keyset['id'] is not None:
            ac = self.getAuthorization(keyset)
            if ac is not None:
                logger.debug("Got an authorization string %s." % ac)

                # store the string in the local cache again
                self.ZCacheable_set(ac, keywords=keyset)
                logger.debug("Added %s to the cache." % ac)

                request._auth = ac
                return

        # authenticate the user
        uid, name = self._getUserInfo(request)
        if name is None or password is None:
            return

        if self._checkAuthentication(name, password, request):
            aclu = getToolByName(self, 'acl_users')
            ac = '%s %s' % (aclu.getTrustedAuthString(), uid)
            self.ZCacheable_set(ac, keywords=keyset)
            self.storeAuthorization(keyset, ac)
            request._auth = ac
        else:
            request.RESPONSE.expireCookie(SESSION_ID_VAR)

    # Public API

    security.declarePublic('expireSession')
    def expireSession(self, request):
        keyset = self._computeCacheKey(request, create=False)
        # Clearing cache entry value. A better thing would have been to
        # invalidate the cache entry itself, but the Cacheable API
        # doesn't seem to allow this.
        self.ZCacheable_set(None, keywords=keyset)
        # This is a call to the potential SSO API
        self.expireAuthorization(keyset)
        request.RESPONSE.expireCookie(SESSION_ID_VAR)
        logger.debug("Expire session %s", keyset)

    # Extensions

    def getAuthorization(self, keyset):
        """To override: implement an authentication server, Single-Sign-On, etc.
        """
        return None

    def storeAuthorization(self, keyset, ac):
        """To override: implement an authentication server, Single-Sign-On, etc.
        """
        return

    def expireAuthorization(self, keyset):
        """To override: implement an authentication server, Single-Sign-On, etc.
        """
        return

    # Private API

    def _getUserInfo(self, request):
        """Retrieve user information from the request (typically request.form)
        """
        name = request.get(self.name_req_variable)
        if name is None:
            return None, None
        self._delRequestVar(request, self.name_req_variable)
        uid = name
        if '/' in name:
            uid = name.split('/')[0]
        return uid, name

    def _checkAuthentication(self, name, password, request):
        """Check that the authentication is correct.

        This is the method to override to deal with different sources
        and kinds of authentication.
        """
        # For the base implementation the password is checked
        # against acl_users.
        aclu = getToolByName(self, 'acl_users')
        res = aclu.authenticate(name, password, request)
        authentication_ok = res is not None
        return authentication_ok

    def _computeCacheKey(self, request, create=False):
        """Compute the cache key set based on host info and session id."""
        sessionId = self._getSessionId(request, create)
        host = request.get('HTTP_X_FORWARDED_FOR')
        if not host:
            host = request.get('REMOTE_ADDR')
        site = self._getAndCacheSiteUrl(request)
        return {
            'id': sessionId,
            'host': host,
            'site': site,
            }

    def _getSessionId(self, request, create=False):
        sessionId = request.cookies.get(SESSION_ID_VAR)
        if create and sessionId is None:
            sessionId = self._createNewSessionId()
            request.RESPONSE.setCookie(SESSION_ID_VAR, sessionId)
        return sessionId

    def _createNewSessionId(self):
        # use the session manager's browser id
        return getNewBrowserId()

    def _getAndCacheSiteUrl(self, request):
        CACHE_SITE_ID = '_extended_auth_site'
        site = request.get(CACHE_SITE_ID)
        if site is None:
            utool = getToolByName(self, 'portal_url')
            site = utool.getPortalObject().absolute_url()
            request[CACHE_SITE_ID] = site
        return site

    def _delRequestVar(self, request, name):
        try: del request.other[name]
        except: pass
        try: del request.form[name]
        except: pass
        try: del request.cookies[name]
        except: pass
        try: del request.environ[name]
        except: pass

InitializeClass(BaseAuth)


manage_addExtendedAuthForm = PageTemplateFile('zmi/addExtendedAuth', globals(),
                                              __name__='addExtendedAuth')

def manage_addExtendedAuth(self, id, auth_type, REQUEST=None):
    """
    """
    if auth_type == 'base':
        ob = BaseAuth()
    elif auth_type == 'krb5':
        from krb5auth import Krb5Auth
        ob = Krb5Auth()
    elif auth_type == 'cleartrust':
        from cleartrustauth import CleartrustAuth
        ob = CleartrustAuth()
    ob.id = id
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST)


def registerHook(ob, event):
    handle = ob.meta_type + '/' + ob.getId()
    container = aq_inner(aq_parent(ob))
    nc = BeforeTraverse.NameCaller(ob.getId())
    BeforeTraverse.registerBeforeTraverse(container, nc, handle)
    logger.debug("Registered BeforeTraverse hook")

def unregisterHook(ob, event):
    handle = ob.meta_type + '/' + ob.getId()
    container = aq_inner(aq_parent(ob))
    BeforeTraverse.unregisterBeforeTraverse(container, handle)
    logger.debug("Unregistered BeforeTraverse hook")

