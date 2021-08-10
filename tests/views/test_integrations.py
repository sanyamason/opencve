from opencve.models import integrations
import pytest
from flask import request

from opencve.constants import INTEGRATIONS_LIST
from opencve.extensions import db
from opencve.models.integrations import Integration
from opencve.models.users import User


def test_redirect_auth(client):
    response = client.get("/account/integrations")
    assert response.status_code == 302

    with client:
        response = client.get("/account/integrations", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/login"


def test_no_integrations(client, login):
    response = client.get("/account/integrations")
    assert response.status_code == 200
    assert b"You have no integration yet." in response.data


def test_list_integrations(app, client, login):
    old = app.config["INTEGRATIONS_PER_PAGE"]
    app.config["INTEGRATIONS_PER_PAGE"] = 2

    user = User.query.first()
    for i in range(3):
        tag = Integration(
            name=f"integration{i}",
            type="email",
            configuration={},
            enabled=True,
            report=True,
            alert_filters={},
            user=user,
        )
        db.session.add(tag)
    db.session.commit()

    response = client.get("/account/integrations")
    assert response.status_code == 200
    assert b"integration0" in response.data
    assert b"integration1" in response.data
    assert not b"integration2" in response.data
    response = client.get("/account/integrations?page=2")
    assert b"integration2" in response.data
    response = client.get("/account/integrations?page=3")
    assert response.status_code == 404

    app.config["INTEGRATIONS_PER_PAGE"] = old


def test_add_integration_redirection(client, login):
    response = client.get("/account/integrations/add")
    assert response.status_code == 302
    response = client.get("/account/integrations/add?type=foobar")
    assert response.status_code == 302
    response = client.post("/account/integrations/add", data={})
    assert response.status_code == 302
    response = client.post("/account/integrations/add?type=foobar", data={})
    assert response.status_code == 302

    for type in INTEGRATIONS_LIST:
        response = client.get(f"/account/integrations/add?type={type}")
        assert response.status_code == 200


def test_add_integration_default_fields(client, login):
    client.post("/account/integrations/add?type=email", data={"name": "my integration"})
    integration = Integration.query.first()
    assert integration.name == "my integration"
    assert integration.type == "email"
    assert integration.enabled == False
    assert integration.report == False
    assert integration.alert_filters == {"cvss": 0, "event_types": []}
    assert integration.configuration == {}


def test_add_integration_custom_fields(client, login):
    client.post(
        "/account/integrations/add?type=email",
        data={
            "name": "my integration",
            "enabled": "y",
            "report": "y",
            "alert_filters-new_cve": "y",
            "alert_filters-cvss": "y",
            "alert_filters-cpes": "y",
            "alert_filters-summary": "y",
            "alert_filters-cwes": "y",
            "alert_filters-references": "y",
            "alert_filters-cvss_score": "5",
        },
    )
    integration = Integration.query.first()
    assert integration.name == "my integration"
    assert integration.type == "email"
    assert integration.enabled == True
    assert integration.report == True
    assert integration.alert_filters["cvss"] == 5
    assert sorted(integration.alert_filters["event_types"]) == [
        "cpes",
        "cvss",
        "cwes",
        "new_cve",
        "references",
        "summary",
    ]
    assert integration.configuration == {}


def test_add_existing_integration(client, login):
    name = "my integration"
    response = client.post(
        "/account/integrations/add?type=email",
        data={"name": name},
        follow_redirects=True,
    )
    assert b"has been successfully added" in response.data

    response = client.post(
        "/account/integrations/add?type=email",
        data={"name": name},
        follow_redirects=True,
    )
    assert b"already exists" in response.data
    assert Integration.query.count() == 1


def test_edit_integration_not_found(client, login):
    response = client.get("/account/integrations/foobar")
    assert response.status_code == 404


def test_edit_integration_get(client, login, create_integration, make_soup):
    def _is_checked(name):
        return soup.find(attrs={"name": name}).has_attr("checked")

    create_integration("my integration 1")
    response = client.get("/account/integrations/my%20integration%201")
    assert response.status_code == 200
    soup = make_soup(response.data)
    assert soup.find(attrs={"name": "name"})["value"] == "my integration 1"
    assert _is_checked("report")
    assert _is_checked("enabled")
    assert not _is_checked("alert_filters-new_cve")
    assert not _is_checked("alert_filters-cvss")
    assert not _is_checked("alert_filters-cpes")
    assert not _is_checked("alert_filters-summary")
    assert not _is_checked("alert_filters-cwes")
    assert not _is_checked("alert_filters-references")
    assert (
        soup.find(attrs={"name": "alert_filters-cvss_score"}).select_one(
            "option:checked"
        )["value"]
        == "0"
    )

    create_integration(
        "my integration 2",
        report=False,
        enabled=False,
        alert_filters={
            "cvss": 8,
            "event_types": ["new_cve", "cvss", "cpes", "summary", "cwes", "references"],
        },
    )
    response = client.get("/account/integrations/my%20integration%202")
    assert response.status_code == 200
    soup = make_soup(response.data)
    assert soup.find(attrs={"name": "name"})["value"] == "my integration 2"
    assert not _is_checked("report")
    assert not _is_checked("enabled")
    assert _is_checked("alert_filters-new_cve")
    assert _is_checked("alert_filters-cvss")
    assert _is_checked("alert_filters-cpes")
    assert _is_checked("alert_filters-summary")
    assert _is_checked("alert_filters-cwes")
    assert _is_checked("alert_filters-references")
    assert (
        soup.find(attrs={"name": "alert_filters-cvss_score"}).select_one(
            "option:checked"
        )["value"]
        == "8"
    )


def test_edit_integration_post(client, login, create_integration):
    create_integration("my integration")
    integration = Integration.query.first()
    assert integration.name == "my integration"
    assert integration.type == "email"
    assert integration.enabled == True
    assert integration.report == True
    assert integration.alert_filters["cvss"] == 0
    assert integration.alert_filters["event_types"] == []

    client.post(
        "/account/integrations/my%20integration",
        data={
            "name": "my integration",
            "alert_filters-new_cve": "y",
            "alert_filters-cvss": "y",
            "alert_filters-cpes": "y",
            "alert_filters-summary": "y",
            "alert_filters-cwes": "y",
            "alert_filters-references": "y",
            "alert_filters-cvss_score": "5",
        },
    )

    integration2 = Integration.query.first()
    assert integration2.name == "my integration"
    assert integration2.type == "email"
    assert integration2.enabled == False
    assert integration2.report == False
    assert integration2.alert_filters["cvss"] == 5
    assert sorted(integration2.alert_filters["event_types"]) == [
        "cpes",
        "cvss",
        "cwes",
        "new_cve",
        "references",
        "summary",
    ]


def test_edit_existing_integration(client, login, create_integration):
    create_integration("my integration 1")
    create_integration("my integration 2")

    response = client.post(
        "/account/integrations/my%20integration%201",
        data={"name": "my integration 2"},
        follow_redirects=True,
    )
    assert b"already exists" in response.data
    integration = Integration.query.first()
    assert integration.name == "my integration 1"


def test_delete_integration_not_found(client, login):
    response = client.get("/account/integrations/foobar/delete")
    assert response.status_code == 404

    response = client.post("/account/integrations/foobar/delete", data={})
    assert response.status_code == 404


def test_delete_integration(client, login, create_integration, create_user):
    create_integration("my integration")
    user = create_user("user1")
    create_integration("my integration", username="user1")

    assert Integration.query.count() == 2
    response = client.post(
        "/account/integrations/my%20integration/delete", data={}, follow_redirects=True
    )
    assert b"has been deleted" in response.data
    assert Integration.query.count() == 1
    assert Integration.query.filter_by(user_id=user.id).first().name == "my integration"


###
# Tests related to the integrations list.
###


def test_add_integration_forms(client, login):
    response = client.get("/account/integrations/add?type=email")
    assert b'<input class="form-control" id="name" name="name"' in response.data

    response = client.get("/account/integrations/add?type=slack")
    assert b'<input class="form-control" id="name" name="name"' in response.data

    response = client.get("/account/integrations/add?type=webhook")
    assert b'<input class="form-control" id="name" name="name"' in response.data
    assert b'<input class="form-control" id="url" name="url"' in response.data


@pytest.mark.parametrize(
    "type,fields",
    [
        ("email", ["name"]),
        ("slack", ["name", "url"]),
        ("webhook", ["name", "url"]),
    ],
)
def test_create_integrations_required_conf(client, login, type, fields):
    response = client.post(
        f"/account/integrations/add?type={type}",
        data={},
    )
    for field in fields:
        assert f"{field.capitalize()} is required" in response.data.decode("utf-8")


@pytest.mark.parametrize(
    "type,payload,conf",
    [
        ("email", {}, {}),
        ("slack", {"url": "http://127.0.0.1"}, {"url": "http://127.0.0.1"}),
        (
            "webhook",
            {
                "url": "http://127.0.0.1",
                "headers-1-name": "foo",
                "headers-1-value": "bar",
            },
            {"url": "http://127.0.0.1", "headers": [{"name": "foo", "value": "bar"}]},
        ),
    ],
)
def test_create_integrations_with_conf(client, login, type, payload, conf):
    name = f"my {type} integration"
    client.post(
        f"/account/integrations/add?type={type}",
        data={
            "name": name,
            **payload,
        },
    )
    integration = Integration.query.filter_by(name=name).first()
    assert integration.name == name
    assert integration.type == type
    assert integration.configuration == conf
