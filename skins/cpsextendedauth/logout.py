## Script (Python) "logout"
##title=Logout handler
##parameters=
#
# $Id$

from logging import getLogger
from Products.CMFCore.utils import getToolByName

logger = getLogger('CPSExtendedAuth.logout')
logger.debug("...")

# notify the event service that the user has logged out
user = context.portal_membership.getAuthenticatedMember()
if user:
    from Products.CPSCore.EventServiceTool import getPublicEventService
    evtool = getPublicEventService(context)
    evtool.notifyEvent('user_logout', user, {})

REQUEST = context.REQUEST

if REQUEST.has_key('portal_skin'):
    context.portal_skins.clearSkinCookie()

# Expire the user session
auth_tool = getToolByName(context, 'extended_authentication', None)
logger.debug("auth_tool = %s" % auth_tool)
if auth_tool is not None:
    auth_tool.expireSession(REQUEST)

# Remove the session id cookie
mgr = REQUEST.SESSION.getBrowserIdManager()
mgr.flushBrowserIdCookie()

return REQUEST.RESPONSE.redirect(REQUEST.URL1+'/logged_out')
