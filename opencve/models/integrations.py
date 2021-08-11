import importlib

from sqlalchemy.schema import UniqueConstraint
from sqlalchemy_utils import JSONType, UUIDType

from opencve.extensions import db
from opencve.models import BaseModel
from opencve.models.users import get_default_filters


class Integration(BaseModel):
    __tablename__ = "integrations"

    name = db.Column(db.String(), nullable=False)
    type = db.Column(db.String(), nullable=False)
    configuration = db.Column(JSONType(), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    report = db.Column(db.Boolean, default=False)
    alert_filters = db.Column(JSONType, default=get_default_filters)
    _integration = None

    # Relationships
    user_id = db.Column(UUIDType(binary=False), db.ForeignKey("users.id"))
    user = db.relationship("User", back_populates="integrations")

    __table_args__ = (
        UniqueConstraint("name", "user_id", name="ix_integration_name_userid"),
    )

    def __repr__(self):
        return "<Integration {}>".format(self.name)

    @property
    def integration(self):
        if not self._integration:
            self._integration = getattr(
                importlib.import_module(f"opencve.integrations.{self.type}"),
                f"{self.type.capitalize()}Integration",
            )(self.configuration)
        return self._integration

    def test_integration(self):
        return self.integration.test_integration()

    def notify_changes(self, changes):
        return self.integration.notify_changes(changes)

    def send_report(self, report):
        return self.integration.send_report(report)
