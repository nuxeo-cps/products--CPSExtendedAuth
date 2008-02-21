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
"""Tool I/O XML Adapter.
"""

import logging

from Acquisition import aq_base
from zope.component import adapts
from zope.interface import implements
import Products
from ZODB.loglevels import BLATHER as VERBOSE
from Products.CMFCore.utils import getToolByName
from Products.GenericSetup.utils import exportObjects
from Products.GenericSetup.utils import importObjects
from Products.GenericSetup.utils import XMLAdapterBase
from Products.GenericSetup.utils import ObjectManagerHelpers
from Products.GenericSetup.utils import PropertyManagerHelpers
from Products.CPSDocument.exportimport import exportCPSObjects
from Products.CPSDocument.exportimport import importCPSObjects
from Products.CPSDocument.exportimport import CPSObjectManagerHelpers
from Products.CPSUtil.cachemanagersetup import CacheableHelpers

from Products.GenericSetup.interfaces import INode
from Products.GenericSetup.interfaces import IBody
from Products.GenericSetup.interfaces import ISetupEnviron
from Products.CPSExtendedAuth.interfaces import ICpsExtendedAuth

NAME = 'extended_auth'

TOOL = 'extended_authentication'

def exportExtendedAuthTool(context):
    """Export portlet tool and portlets a set of XML files.
    """
    site = context.getSite()
    tool = getToolByName(site, TOOL, None)
    if tool is None:
        logger = context.getLogger(NAME)
        logger.info("Nothing to export.")
        return
    exportObjects(tool, '', context)

def importExtendedAuthTool(context):
    """Import portlet tool and portlets from XML files.
    """
    logger = logging.getLogger('importExtendedAuthTool')
    site = context.getSite()
    tool = getToolByName(site, TOOL)
    logger.debug("tool = %s" % tool)
    importObjects(tool, '', context)
    logger.debug("done")

class ExtendedAuthToolXMLAdapter(XMLAdapterBase, CPSObjectManagerHelpers,
                                 PropertyManagerHelpers, CacheableHelpers):
    """XML importer and exporter for portlet tool.
    """

    adapts(ICpsExtendedAuth, ISetupEnviron)
    implements(IBody)

    _LOGGER_ID = NAME
    name = NAME

    def _exportNode(self):
        """Export the object as a DOM node.
        """
        node = self._getObjectNode('object')
        node.appendChild(self._extractProperties())
        node.appendChild(self._extractObjects())
        child = self._extractCacheableManagerAssociation()
        if child is not None:
            node.appendChild(child)
        self._logger.info("Tool %s exported." % TOOL)
        return node

    def _importNode(self, node):
        """Import the object from the DOM node.
        """
        self._logger.info("LLLLLLLLLL ----")
        if self.environ.shouldPurge():
            self._purgeProperties()
            self._purgeObjects()
            self._purgeCacheableManagerAssociation()
        self._initProperties(node)
        self._initObjects(node)
        self._initCacheableManagerAssociation(node)
        self._logger.info("Tool %s imported." % TOOL)

     # Is this setting really necessary?
#    node = property(_exportNode, _importNode)

