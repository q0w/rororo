from collections import deque
from functools import partial
from typing import Any, cast, Dict, Iterator, List, Optional, Tuple

import pyrsistent
from email_validator import EmailNotValidError, validate_email
from isodate import parse_datetime
from jsonschema.exceptions import FormatError
from more_itertools import peekable
from openapi_core.casting.schemas.exceptions import CastError as CoreCastError
from openapi_core.exceptions import OpenAPIError as CoreOpenAPIError
from openapi_core.spec.paths import SpecPath
from openapi_core.templating.datatypes import TemplateResult
from openapi_core.templating.paths.exceptions import (
    OperationNotFound,
    PathNotFound,
    ServerNotFound,
)
from openapi_core.templating.paths.finders import PathFinder
from openapi_core.unmarshalling.schemas.enums import UnmarshalContext
from openapi_core.unmarshalling.schemas.exceptions import InvalidSchemaValue
from openapi_core.unmarshalling.schemas.factories import (
    SchemaUnmarshallersFactory,
)
from openapi_core.unmarshalling.schemas.formatters import Formatter
from openapi_core.unmarshalling.schemas.unmarshallers import (
    ArrayUnmarshaller,
    ObjectUnmarshaller,
)
from openapi_core.validation.request.datatypes import (
    OpenAPIRequest,
    RequestParameters,
)
from openapi_core.validation.request.validators import (
    RequestValidator as CoreRequestValidator,
)
from openapi_core.validation.response.datatypes import OpenAPIResponse
from openapi_core.validation.response.validators import (
    ResponseValidator as CoreResponseValidator,
)
from openapi_core.validation.validators import (
    BaseValidator as CoreBaseValidator,
)
from openapi_schema_validator._format import oas30_format_checker

from ..annotations import DictStrAny, MappingStrAny
from .annotations import ValidateEmailKwargsDict
from .data import OpenAPIParameters, to_openapi_parameters
from .exceptions import CastError, ValidationError
from .security import validate_security
from .utils import get_base_url


DATE_TIME_FORMATTER = Formatter.from_callables(
    partial(oas30_format_checker.check, format="date-time"),
    parse_datetime,
)
PathTuple = Tuple[
    DictStrAny, DictStrAny, DictStrAny, TemplateResult, TemplateResult
]


class EmailFormatter(Formatter):
    """Formatter to support email strings.

    Use `email-validator <https://pypi.org/project/email-validator>`_ library
    to ensure that given string is a valid email.
    """

    kwargs: ValidateEmailKwargsDict

    def __init__(self, kwargs: ValidateEmailKwargsDict = None) -> None:
        self.kwargs: ValidateEmailKwargsDict = kwargs or {}

    def validate(self, value: str) -> bool:
        try:
            validate_email(value, **self.kwargs)
        except EmailNotValidError as err:
            raise FormatError(f"{value!r} is not an 'email'", cause=err)
        return True


class BaseValidator(CoreBaseValidator):
    def _cast(self, param_or_media_type: Any, value: Any) -> Any:
        try:
            return super()._cast(param_or_media_type, value)
        except CoreCastError as err:
            # Pass param or media type name to cast error
            raise CastError(
                name=param_or_media_type["name"],
                value=err.value,
                type=err.type,
            )

    def _unmarshal(
        self, param_or_media_type: Any, value: Any, context: UnmarshalContext
    ) -> Any:
        # @todo: use super()._unmarshal
        if "schema" not in param_or_media_type:
            return value

        from openapi_core.unmarshalling.schemas.factories import (
            SchemaUnmarshallersFactory,
        )

        spec_resolver = (
            self.spec.accessor.dereferencer.resolver_manager.resolver
        )
        unmarshallers_factory = SchemaUnmarshallersFactory(
            spec_resolver,
            self.format_checker,
            self.custom_formatters,
            context=context,
        )
        schema = param_or_media_type / "schema"
        unmarshaller = unmarshallers_factory.create(schema)
        try:
            return unmarshaller(value)
        except InvalidSchemaValue as err:
            # Modify invalid schema validation errors to include parameter name
            if isinstance(param_or_media_type, SpecPath):
                param_name = param_or_media_type.get("name")
                if param_name:
                    for schema_error in err.schema_errors:
                        schema_error.path = schema_error.relative_path = deque(
                            [param_name]
                        )

            raise err


class RequestValidator(BaseValidator, CoreRequestValidator):
    def _get_parameters(
        self, request: OpenAPIRequest, params: MappingStrAny
    ) -> Tuple[RequestParameters, List[CoreOpenAPIError]]:
        """
        Distinct parameters errors from body errors to supply proper validation
        error response.
        """
        parameters, errors = super()._get_parameters(request, params)
        if errors:
            raise ValidationError.from_request_errors(
                errors, base_loc=["parameters"]
            )
        return parameters, errors

    def _unmarshal(  # type: ignore
        self, param_or_media_type: Any, value: Any
    ) -> Any:
        return super()._unmarshal(
            param_or_media_type, value, context=UnmarshalContext.REQUEST
        )


class ResponseValidator(BaseValidator, CoreResponseValidator):
    def _unmarshal(  # type: ignore
        self, param_or_media_type: Any, value: Any
    ) -> Any:
        return super()._unmarshal(
            param_or_media_type, value, context=UnmarshalContext.RESPONSE
        )


def get_custom_formatters(
    *, validate_email_kwargs: ValidateEmailKwargsDict = None
) -> Dict[str, Formatter]:
    return {"email": EmailFormatter(validate_email_kwargs)}


def validate_core_request(
    spec: SpecPath,
    core_request: OpenAPIRequest,
    *,
    validate_email_kwargs: ValidateEmailKwargsDict = None,
) -> Tuple[MappingStrAny, OpenAPIParameters, Any]:
    """
    Instead of validating request parameters & body in two calls, validate them
    at once with passing custom formatters.
    """
    custom_formatters = get_custom_formatters(
        validate_email_kwargs=validate_email_kwargs
    )

    validator = RequestValidator(
        spec,
        custom_formatters=custom_formatters,
        base_url=get_base_url(core_request),
    )
    result = validator.validate(core_request)

    if result.errors:
        raise ValidationError.from_request_errors(result.errors)

    return (
        result.security,
        to_openapi_parameters(result.parameters),
        pyrsistent.freeze(result.body),
    )


def validate_core_response(
    spec: SpecPath,
    core_request: OpenAPIRequest,
    core_response: OpenAPIResponse,
    *,
    validate_email_kwargs: ValidateEmailKwargsDict = None,
) -> Any:
    """Pass custom formatters for validating response data."""
    custom_formatters = get_custom_formatters(
        validate_email_kwargs=validate_email_kwargs
    )

    validator = ResponseValidator(
        spec,
        custom_formatters=custom_formatters,
        base_url=get_base_url(core_request),
    )
    result = validator.validate(core_request, core_response)

    if result.errors:
        raise ValidationError.from_response_errors(result.errors)

    return result.data
