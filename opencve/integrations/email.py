from opencve.integrations import BaseIntegration


class EmailIntegration(BaseIntegration):
    def test_integration(self):
        raise NotImplementedError

    def notify_changes(self):
        raise NotImplementedError

    def send_report(self):
        raise NotImplementedError
