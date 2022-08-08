import logging
from abc import ABC
from typing import Any, Awaitable, List, Union

from django.contrib.auth.models import AbstractUser
from strawberry import BasePermission
from strawberry.types import Info

from ...settings import oauth2_settings


log = logging.getLogger("oauth2_provider")


class BaseStrawBerryPermission(BasePermission, ABC):
    @staticmethod
    def get_request_from_context(info: Info):
        return info.context["request"]


class TokenHasScope(BaseStrawBerryPermission):
    """
    The request is authenticated as a user and the token used has the right scope
    """

    def get_scopes(self) -> List[str]:
        raise NotImplementedError("Permission classes should override get_scopes method")

    def has_permission(self, source: Any, info: Info, **kwargs) -> Union[bool, Awaitable[bool]]:
        request = self.get_request_from_context(info)
        user = request.user

        return self._user_has_permission(user)

    def _user_has_permission(self, user):

        if hasattr(user, "used_oauth_token"):  # OAuth 2
            token = user.used_oauth_token

            if not token:
                return False

            required_scopes = self.get_scopes()
            log.debug("Required scopes to access resource: {0}".format(required_scopes))

            if token.is_valid(required_scopes):
                return True

            # Provide information about required scope?
            include_required_scope = (
                oauth2_settings.ERROR_RESPONSE_WITH_SCOPES
                and required_scopes
                and not token.is_expired()
                and not token.allow_scopes(required_scopes)
            )

            if include_required_scope:
                self.message = f"The scopes {required_scopes} are required to access this resource"

            return False

        assert False, (
            "TokenHasScope requires the"
            "`oauth2_provider.contrib.strawberry_graphql.authentication.StrawberryOauth2Backend`"
            " authentication class to be used."
        )


class IsAuthenticatedOrTokenHasScope(TokenHasScope, ABC):
    def has_permission(self, source: Any, info: Info, **kwargs) -> Union[bool, Awaitable[bool]]:
        request = self.get_request_from_context(info)
        user: AbstractUser = request.user
        is_authenticated = user.is_authenticated

        if is_authenticated:
            if hasattr(user, "backend"):
                if user.backend == "oauth2_provider.backends.OAuth2Backend":
                    assert False, (
                        "IsAuthenticatedOrTokenHasScope requires the"
                        "`oauth2_provider.contrib.strawberry_graphql.authentication.StrawberryOauth2Backend` "
                        "authentication class to be used."
                    )
                elif (
                    user.backend
                    == "oauth2_provider.contrib.strawberry_graphql.authentication.StrawberryOauth2Backend"
                ):
                    is_authenticated = super()._user_has_permission(user)

        return is_authenticated
