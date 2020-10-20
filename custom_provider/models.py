import datetime
from urllib.parse import urlparse, parse_qsl

from cassandra.cqlengine import columns
from django.conf import settings
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django_cassandra_engine import models
from oauth2_provider.generators import generate_client_secret, generate_client_id
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.validators import RedirectURIValidator, WildcardSet


class AbstractAppApplication(models.DjangoCassandraModel):
    """
        An Application instance represents a Client on the Authorization server.
        Usually an Application is created manually by client's developers after
        logging in on an Authorization Server.

        Fields:

        * :attr:`client_id` The client identifier issued to the client during the
                            registration process as described in :rfc:`2.2`
        * :attr:`user` ref to a Django user
        * :attr:`redirect_uris` The list of allowed redirect uri. The string
                                consists of valid URLs separated by space
        * :attr:`client_type` Client type as described in :rfc:`2.1`
        * :attr:`authorization_grant_type` Authorization flows available to the
                                           Application
        * :attr:`client_secret` Confidential secret issued to the client during
                                the registration process as described in :rfc:`2.2`
        * :attr:`name` Friendly name for the Application
        """
    CLIENT_CONFIDENTIAL = "confidential"
    CLIENT_PUBLIC = "public"
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _("Confidential")),
        (CLIENT_PUBLIC, _("Public")),
    )

    GRANT_AUTHORIZATION_CODE = "authorization-code"
    GRANT_IMPLICIT = "implicit"
    GRANT_PASSWORD = "password"
    GRANT_CLIENT_CREDENTIALS = "client-credentials"
    GRANT_TYPES = (
        (GRANT_AUTHORIZATION_CODE, _("Authorization code")),
        (GRANT_IMPLICIT, _("Implicit")),
        (GRANT_PASSWORD, _("Resource owner password-based")),
        (GRANT_CLIENT_CREDENTIALS, _("Client credentials")),
    )

    id = columns.UUID(primary_key=True)
    client_id = columns.Text(
        max_length=100, unique=True, default=generate_client_id, db_index=True
    )
    user = columns.UUID(
        settings.AUTH_USER_MODEL,
        related_name="%(app_label)s_%(class)s",
        null=True, blank=True, on_delete=models.CASCADE
    )

    redirect_uris = columns.Text(
        blank=True, help_text=_("Allowed URIs list, space separated"),
    )
    client_type = columns.Text(max_length=32, choices=CLIENT_TYPES)
    authorization_grant_type = columns.Text(
        max_length=32, choices=GRANT_TYPES
    )
    client_secret = columns.Text(
        max_length=255, blank=True, default=generate_client_secret, db_index=True
    )
    name = columns.Text(max_length=255, blank=True)
    skip_authorization = columns.Boolean(default=False)

    created = columns.DateTime(default=datetime.datetime.now)
    updated = columns.DateTime(default=datetime.datetime.now)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name or self.client_id

    @property
    def default_redirect_uri(self):
        """
        Returns the default redirect_uri extracting the first item from
        the :attr:`redirect_uris` string
        """
        if self.redirect_uris:
            return self.redirect_uris.split().pop(0)

        assert False, (
            "If you are using implicit, authorization_code"
            "or all-in-one grant_type, you must define "
            "redirect_uris field in your Application model"
        )

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string

        :param uri: Url to check
        """
        parsed_uri = urlparse(uri)
        uqs_set = set(parse_qsl(parsed_uri.query))
        for allowed_uri in self.redirect_uris.split():
            parsed_allowed_uri = urlparse(allowed_uri)

            if (parsed_allowed_uri.scheme == parsed_uri.scheme and
                    parsed_allowed_uri.netloc == parsed_uri.netloc and
                    parsed_allowed_uri.path == parsed_uri.path):

                aqs_set = set(parse_qsl(parsed_allowed_uri.query))

                if aqs_set.issubset(uqs_set):
                    return True

        return False

    def clean(self):
        from django.core.exceptions import ValidationError

        grant_types = (
            self.GRANT_AUTHORIZATION_CODE,
            self.GRANT_IMPLICIT,
        )

        redirect_uris = self.redirect_uris.strip().split()
        allowed_schemes = set(s.lower() for s in self.get_allowed_schemes())

        if redirect_uris:
            validator = RedirectURIValidator(WildcardSet())
            for uri in redirect_uris:
                validator(uri)
                scheme = urlparse(uri).scheme
                if scheme not in allowed_schemes:
                    raise ValidationError(_(
                        "Unauthorized redirect scheme: {scheme}"
                    ).format(scheme=scheme))

        elif self.authorization_grant_type in grant_types:
            raise ValidationError(_(
                "redirect_uris cannot be empty with grant_type {grant_type}"
            ).format(grant_type=self.authorization_grant_type))

    def get_absolute_url(self):
        return reverse("oauth2_provider:detail", args=[str(self.id)])

    def get_allowed_schemes(self):
        """
        Returns the list of redirect schemes allowed by the Application.
        By default, returns `ALLOWED_REDIRECT_URI_SCHEMES`.
        """
        return oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES

    def allows_grant_type(self, *grant_types):
        return self.authorization_grant_type in grant_types

    def is_usable(self, request):
        """
        Determines whether the application can be used.

        :param request: The oauthlib.common.Request being processed.
        """
        return True
