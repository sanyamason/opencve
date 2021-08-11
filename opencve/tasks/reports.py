from datetime import date

from celery.utils.log import get_task_logger
from sqlalchemy import Date, cast


from opencve.constants import PRODUCT_SEPARATOR
from opencve.context import _humanize_filter
from opencve.extensions import cel
from opencve.models.integrations import Integration
from opencve.models.reports import Report


logger = get_task_logger(__name__)


def get_report_summary(report):
    """
    Sort the changes by vendors and products then extract their max score.
    """
    user = report.user
    user_vendors = user.flat_vendors + user.flat_products
    summary = {}

    for change in report.changes:
        cve = change.cve

        # Only keep subscribed vendors and products
        vendors = [v for v in cve.vendors if v in user_vendors]

        for vendor in vendors:
            vendor = vendor.replace(PRODUCT_SEPARATOR, "_")
            if vendor not in summary:
                summary[vendor] = {
                    "name": _humanize_filter(vendor),
                    "changes": {},
                    "max": 0,
                }

            # Extract change information
            summary[vendor]["changes"][cve.cve_id] = {
                "summary": cve.summary,
                "score": cve.cvss3 if cve.cvss3 else None,
                "events": [e.type.code for e in change.events],
            }

            # Update the max score of this vendor
            if cve.cvss3 and cve.cvss3 > summary[vendor]["max"]:
                summary[vendor]["max"] = cve.cvss3

    return summary


@cel.task(name="HANDLE_REPORTS")
def handle_reports():
    cel.app.app_context().push()

    # Get the daily reports
    reports = Report.query.filter(cast(Report.created_at, Date) == date.today()).all()
    logger.info(f"Checking {len(reports)} daily report(s) to send...")

    for report in reports:
        user = report.user

        # Only call integrations with enabled report
        integrations = [i for i in user.integrations if i.report]
        if not integrations:
            continue

        for integration in integrations:
            notify_report.delay(integration.id, report.id)


@cel.task(name="NOTIFY_REPORT")
def notify_report(integration_id, report_id):
    cel.app.app_context().push()

    # If the user removed his integration before notification was called
    integration = Integration.query.filter_by(id=integration_id).first()
    if not integration:
        logger.warning(f"Integration {integration_id} does not exist anymore, exit.")
        return

    report = Report.query.filter_by(id=report_id).first()
    logger.info(
        f"[{integration.name}] calling integration with for report {report.public_link}"
    )

    # Notify the report
    summary = get_report_summary(report)
    isok, message = integration.send_report(summary)

    if isok:
        logger.info(f"[{integration.name}] integration successfully called")
    else:
        logger.error(f"[{integration.name}] error calling the integration:")
        logger.error(f"[{integration.name}] {message}")
