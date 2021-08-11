class BaseIntegration(object):
    TEST_MESSAGE = "This is a test from OpenCVE integration"

    def __init__(self, config):
        self.config = config

    def get_name(self):
        return self.__class__.__name__

    def test_integration(self):
        raise NotImplementedError

    def notify_changes(self):
        raise NotImplementedError

    def send_report(self):
        raise NotImplementedError
