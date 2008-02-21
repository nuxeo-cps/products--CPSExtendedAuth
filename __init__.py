# (C) Copyright 2008 Nuxeo SAS <http://nuxeo.com>
# Authors:
# M.-A. Darche <madarche@nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$

from Products.GenericSetup import EXTENSION
from Products.GenericSetup import profile_registry
from Products.CMFCore.DirectoryView import registerDirectory

from Products.CPSCore.interfaces import ICPSSite

from baseauth import BaseAuth
from baseauth import manage_addExtendedAuthForm
from baseauth import manage_addExtendedAuth

registerDirectory('skins', globals())

def initialize(registrar):

    registrar.registerClass(BaseAuth,
        constructors=(manage_addExtendedAuthForm,
                      manage_addExtendedAuth,
                      ),
        icon='extended_auth.png',
    )

    profile_registry.registerProfile('default',
        "CPS authentication without Cookie Crumbler",
        "extended authentication setup without using the CMF Cookie Crumbler",
        'profiles/default',
        'CPSExtendedAuth',
        EXTENSION,
        for_=ICPSSite)

    profile_registry.registerProfile('krb5',
        "CPS authentication using Kerberos 5",
        "extended authentication setup Kerberos 5 based",
        'profiles/krb5',
        'CPSExtendedAuth',
        EXTENSION,
        for_=ICPSSite)

    profile_registry.registerProfile('cleartrust',
        "CPS authentication using RSA Cleartrust",
        "extended authentication setup RSA Cleartrust based",
        'profiles/cleartrust',
        'CPSExtendedAuth',
        EXTENSION,
        for_=ICPSSite)

