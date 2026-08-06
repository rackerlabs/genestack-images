"""
Zaqar Billing WSGI Middleware

A PasteDeploy-compatible WSGI filter that emits oslo.messaging notifications
for every API request, enabling per-request billing via Ceilometer/Gnocchi.

Usage in paste pipeline (via helm overrides):
    [filter:billing]
    paste.filter_factory = billing_middleware:filter_factory

This file is installed into site-packages at image build time so it's
importable without any PYTHONPATH manipulation.
"""
import logging
import time
import threading

LOG = logging.getLogger(__name__)

_notifier = None
_notifier_lock = threading.Lock()


def _get_notifier():
    """Lazy-init the oslo.messaging notifier (singleton, thread-safe)."""
    global _notifier
    if _notifier is not None:
        return _notifier

    with _notifier_lock:
        if _notifier is not None:
            return _notifier
        try:
            from oslo_config import cfg
            import oslo_messaging

            # Create a fresh ConfigOpts and load from the zaqar config file
            # to pick up transport_url without conflicting with the running
            # zaqar-server's global CONF.
            conf = cfg.ConfigOpts()
            conf(['--config-file', '/etc/zaqar/zaqar.conf'])

            transport = oslo_messaging.get_notification_transport(conf)
            _notifier = oslo_messaging.Notifier(
                transport,
                publisher_id='zaqar.billing',
                driver='messagingv2',
                topics=['notifications']
            )
            LOG.info("BillingMiddleware: notifier initialized")
        except Exception as e:
            LOG.error("BillingMiddleware: failed to create notifier: %s", e, exc_info=True)
    return _notifier


def _detect_resource_type(path):
    """Derive a resource type from the request path."""
    if '/messages' in path:
        return 'message'
    if '/claims' in path:
        return 'claim'
    if '/subscriptions' in path:
        return 'subscription'
    if '/queues' in path:
        return 'queue'
    return 'unknown'


class BillingMiddleware(object):
    """WSGI middleware that emits billing notifications for every request."""

    def __init__(self, app):
        self.app = app
        LOG.info("BillingMiddleware: wrapping Zaqar WSGI app")

    def __call__(self, environ, start_response):
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        project_id = environ.get('HTTP_X_PROJECT_ID') or environ.get('HTTP_X_TENANT_ID', '')
        user_id = environ.get('HTTP_X_USER_ID', '')

        response_status = [None]
        start_time = time.time()

        def custom_start_response(status, headers, exc_info=None):
            response_status[0] = status
            return start_response(status, headers, exc_info)

        response = self.app(environ, custom_start_response)

        # Fire-and-forget notification after the response is produced
        try:
            duration = time.time() - start_time
            status_code = 0
            if response_status[0]:
                try:
                    status_code = int(response_status[0].split(' ', 1)[0])
                except (ValueError, IndexError):
                    pass

            notifier = _get_notifier()
            if notifier is not None:
                payload = {
                    'project_id': project_id,
                    'user_id': user_id,
                    'method': method,
                    'path': path,
                    'status_code': status_code,
                    'duration': round(duration, 4),
                    'action': method.lower(),
                    'resource_type': _detect_resource_type(path),
                }
                notifier.info({}, 'zaqar.billing.request', payload)
        except Exception as e:
            LOG.error("BillingMiddleware: notification error: %s", e, exc_info=True)

        return response


def filter_factory(global_conf, **local_conf):
    """PasteDeploy filter factory entry point."""
    def billing_filter(app):
        return BillingMiddleware(app)
    return billing_filter
