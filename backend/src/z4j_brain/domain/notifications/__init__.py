"""Notification engine - the Flower-killer feature.

Submodules:

- :mod:`channels` - delivery implementations (webhook, email, slack, telegram)
- :mod:`service` - rule evaluation + dispatch orchestration
"""

from z4j_brain.domain.notifications.service import NotificationService

__all__ = ["NotificationService"]
