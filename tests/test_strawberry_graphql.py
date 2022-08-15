import json
from datetime import timedelta
from typing import List

import pytest
import strawberry
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import path
from django.utils import timezone
from strawberry.django.views import GraphQLView

from oauth2_provider.contrib.strawberry_graphql.permissions import TokenHasScope
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.settings import oauth2_settings
from tests import presets


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


class TokenHasReadScope(TokenHasScope):
    def get_scopes(self) -> List[str]:
        return [oauth2_settings.READ_SCOPE]


class TokenHasWriteScope(TokenHasScope):
    def get_scopes(self) -> List[str]:
        return [oauth2_settings.WRITE_SCOPE]


@strawberry.type
class Book:
    title: str
    author: str


def get_books():
    return [
        Book(
            title="The Great Gatsby",
            author="F. Scott Fitzgerald",
        ),
    ]


@strawberry.type
class Query:
    books: List[Book] = strawberry.field(resolver=get_books, permission_classes=[TokenHasReadScope])


schema = strawberry.Schema(query=Query)


urlpatterns = [path("graphql", GraphQLView.as_view(schema=schema), name="graphql")]

AUTHENTICATION_BACKENDS = [
    "oauth2_provider.contrib.strawberry_graphql.authentication.StrawberryOauth2Backend",
    "django.contrib.auth.backends.ModelBackend",
]
MIDDLEWARE = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "oauth2_provider.middleware.OAuth2TokenMiddleware",
)


@override_settings(
    ROOT_URLCONF=__name__, AUTHENTICATION_BACKENDS=AUTHENTICATION_BACKENDS, MIDDLEWARE=MIDDLEWARE
)
@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(presets.STRAWBERRY_GRAPHQL_SCOPES)
class TestOAuth2AuthenticationStrawberry(TestCase):
    def setUp(self):
        self.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        self.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        self.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.com http://example.org",
            user=self.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )

        self.access_token = AccessToken.objects.create(
            user=self.test_user,
            scope="read write",
            expires=timezone.now() + timedelta(seconds=300),
            token="secret-access-token-key",
            application=self.application,
        )

    @staticmethod
    def _create_authorization_header(token):
        return "Bearer {0}".format(token)

    def test_authentication_allow(self):
        auth = self._create_authorization_header(self.access_token.token)
        data = {"query": "query{books {title}}"}
        response: JsonResponse = self.client.post(
            "/graphql", HTTP_AUTHORIZATION=auth, data=data, content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        response_content = json.loads(response.content)
        self.assertNotIn("errors", response_content)
