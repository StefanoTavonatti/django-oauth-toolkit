import logging
from abc import ABC
from typing import Any, Awaitable, List, Optional, Union

from django.contrib.auth.models import AbstractUser
from strawberry import BasePermission
from strawberry.types import Info

from ...settings import oauth2_settings


log = logging.getLogger("oauth2_provider")


class BaseTokenPermission(ABC):
    """
    Base class for a strawberry token authentication, this class contains the methods for retrieving the
    request from the context and for checking the token scopes. This class is not extending the strawberry.
    BasePermission on purpose, this will allow to more easily integrate this class
    with the various strawberry-django integration.
    """

    @staticmethod
    def get_request_from_context(info: Info):
        return info.context["request"]

    def get_scopes(self) -> List[str]:
        raise NotImplementedError("Permission classes should override get_scopes method")

    def _user_has_permission(self, user) -> (bool, Optional[str]):

        if hasattr(user, "used_oauth_token"):  # OAuth 2
            token = user.used_oauth_token

            if not token:
                return False, None

            required_scopes = self.get_scopes()
            log.debug("Required scopes to access resource: {0}".format(required_scopes))

            if token.is_valid(required_scopes):
                return True, None

            # Provide information about required scope?
            include_required_scope = (
                oauth2_settings.ERROR_RESPONSE_WITH_SCOPES
                and required_scopes
                and not token.is_expired()
                and not token.allow_scopes(required_scopes)
            )

            if include_required_scope:
                message = (f"The scopes {required_scopes} are required to access this resource",)
            else:
                message = None

            return False, message

        assert False, (
            "TokenHasScope requires the"
            "`oauth2_provider.contrib.strawberry_graphql.authentication.StrawberryOauth2Backend`"
            " authentication backend to be used."
        )


class TokenHasScope(BasePermission, BaseTokenPermission, ABC):
    """
    The request is authenticated as a user and the token used has the right scope
    """

    def has_permission(self, source: Any, info: Info, **kwargs) -> Union[bool, Awaitable[bool]]:
        request = self.get_request_from_context(info)
        user = request.user

        has_permission, message = super()._user_has_permission(user)
        self.message = message
        return has_permission


class IsAuthenticatedOrTokenHasScope(BasePermission, BaseTokenPermission, ABC):
    """
    The user is authenticated using some backend or the token has the right scope
    This only returns True if the user is authenticated, but not using a token
    or using a token, and the token has the correct scope.

    This is usefull when combined with the DjangoModelPermissions to allow people browse
    the browsable api's if they log in using the a non token bassed middleware,
    and let them access the api's using a rest client with a token
    """

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
                        "authentication backend to be used."
                    )
                elif (
                    user.backend
                    == "oauth2_provider.contrib.strawberry_graphql.authentication.StrawberryOauth2Backend"
                ):
                    is_authenticated, message = super()._user_has_permission(user)
                    self.message = message

        return is_authenticated
