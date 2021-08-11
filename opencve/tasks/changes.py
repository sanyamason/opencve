from sqlalchemy import func
from celery.utils.log import get_task_logger

from opencve.extensions import cel, db
from opencve.models.changes import Change
from opencve.models.integrations import Integration
from opencve.models.reports import Report

logger = get_task_logger(__name__)


def filter_events(integration, events):
    return [
        e for e in events if e.type.code in integration.alert_filters["event_types"]
    ]


@cel.task(name="HANDLE_CHANGES")
def handle_changes():
    cel.app.app_context().push()

    # Retrieve the list of changes (at least 1 event not reviewed)
    changes = Change.query.filter_by(reviewed=False).all()
    if not changes:
        logger.info("No CVE changed, exit.")
        return

    # Check each change, get its events and create alerts
    logger.info("Checking {} changed CVE(s)...".format(len(changes)))

    # Keep track of changes per integrations
    notifications = {}

    for change in changes:
        users = {}
        cve = change.cve
        events = change.events

        # Save the subscribers for each vendor of the CVE
        users = cve.suscribed_users

        # No users concerned
        if not users:
            logger.info(f"[{cve.cve_id}] no users to alert")
            change.reviewed = True
            db.session.commit()
            continue

        # Check the integrations of each user to see if we have to alert them or not
        logger.info(
            f"[{cve.cve_id}] {len(users)} subscribed users found".format(len(users))
        )

        for user in users.keys():

            # Fetch the user's daily report
            report = (
                Report.query.filter(
                    func.date(Report.created_at) == change.created_at.date()
                )
                .filter(Report.user == user)
                .first()
            )

            if not report:
                report = Report(user=user, details={})
                db.session.add(report)

            # Append the change in the daily report
            report.changes.append(change)
            db.session.commit()

            logger.info(
                f"[{cve.cve_id}][{user.username}] change added to report {report.public_link}"
            )

            # Notify the user
            for integration in user.integrations:

                # Check the CVSSv3 score
                if cve.cvss3 and cve.cvss3 < integration.alert_filters["cvss"]:
                    continue

                # Check the events type
                remaining_events = filter_events(integration, list(events))
                if not remaining_events:
                    continue

                # Associate the change with the integration
                integration_id = str(integration.id)
                if not integration_id in notifications:
                    notifications[integration_id] = {}

                notifications[integration_id][cve.cve_id] = {}
                for event in change.events:
                    notifications[integration_id][cve.cve_id][
                        event.type.code
                    ] = event.details

                logger.info(
                    f"[{cve.cve_id}][{user.username}] change added in integration '{integration.name}'"
                )

        # We can review the change
        change.reviewed = True
        db.session.commit()

    # Launch the notification tasks
    logger.info(
        f"Sending NOTIFY_CHANGES task(s) for {len(notifications)} integration(s)..."
    )
    for integration_id, data in notifications.items():
        notify_changes.delay(integration_id, data)


@cel.task(name="NOTIFY_CHANGES")
def notify_changes(integration_id, changes):
    cel.app.app_context().push()

    # If the user removed his integration before notification was called
    integration = Integration.query.filter_by(id=integration_id).first()
    if not integration:
        logger.warning(f"Integration {integration_id} does not exist anymore, exit.")
        return

    # Notify the changes
    logger.info(
        f"[{integration.name}] calling integration with {len(changes)} changed CVE(s)..."
    )
    isok, message = integration.notify_changes(changes)

    if isok:
        logger.info(f"[{integration.name}] integration successfully called")
    else:
        logger.error(f"[{integration.name}] error calling the integration:")
        logger.error(f"[{integration.name}] {message}")
