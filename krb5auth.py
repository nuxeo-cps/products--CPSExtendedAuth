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

from AccessControl import ClassSecurityInfo
from Acquisition import aq_inner, aq_parent
from Globals import InitializeClass, HTMLFile
from OFS.Cache import Cacheable
from ZPublisher import BeforeTraverse

from Products.CMFCore.utils import getToolByName

from Products.Sessions.BrowserIdManager import getNewBrowserId

from baseauth import BaseAuth

logger = logging.getLogger('CPSExtendedAuth.Krb5Auth')

try:
    import krb5
except ImportError:
    logger.error("Could not import krb5.")
    HAS_KRB5 = False
else:
    HAS_KRB5 = True

class Krb5Auth(BaseAuth):
    """Authenticates users against krb5 without exposing the password in a
    cookie or in RAM.
    """
    meta_type = 'CPS Krb5 Auth'

    security = ClassSecurityInfo()

    # Overriding the parent class method
    def _checkAuthentication(self, name, password, request):
        """Check that the password is correct."""
        if krb5.auth(name, password):
            return False
        return True

InitializeClass(Krb5Auth)
