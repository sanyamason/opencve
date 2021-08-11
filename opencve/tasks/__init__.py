from datetime import timedelta

from celery import chain
from celery.schedules import crontab

from opencve.extensions import cel
from opencve.tasks.changes import handle_changes
from opencve.tasks.events import handle_events


# Celery Beat configuration
CELERYBEAT_SCHEDULE = {
    "cve-updates-15-mn": {
        "task": "UPDATE_CVES",
        "schedule": timedelta(minutes=15),
    },
    "send-reports-daily": {
        "task": "HANDLE_REPORTS",
        "schedule": crontab(minute=0, hour=0),
    },
}


@cel.task(bind=True, name="UPDATE_CVES")
def update_cves(self):
    return chain(handle_events.si(), handle_changes.si())()
