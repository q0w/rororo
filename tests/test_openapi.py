import io
import zipfile
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp_middlewares import cors_middleware, error_middleware
from yarl import URL

from rororo import (
    BaseSettings,
    get_openapi_schema,
    get_openapi_spec,
    openapi_context,
    OperationTableDef,
    setup_openapi,
    setup_settings,
)
from rororo.openapi import get_validated_data
from rororo.openapi.exceptions import ConfigurationError, OperationError
from rororo.openapi.mappings import enforce_dicts


ROOT_PATH = Path(__file__).parent

INVALID_OPENAPI_JSON_PATH = ROOT_PATH / "invalid-openapi.json"
INVALID_OPENAPI_YAML_PATH = ROOT_PATH / "invalid-openapi.yaml"
OPENAPI_JSON_PATH = ROOT_PATH / "openapi.json"
OPENAPI_YAML_PATH = ROOT_PATH / "openapi.yaml"
TEST_NESTED_OBJECT = {
    "uid": "6fccda1b-0873-4c8a-bceb-a2acfe5851da",
    "type": "nested-object",
    "data": {
        "data_item": {"key": "value1", "any_data": {}},
        "data_items": [
            {"key": "value2", "any_data": {"two": 2}},
            {"key": "value3", "any_data": {"three": 3}},
        ],
        "str_items": ["1", "2", "3"],
    },
    "any_data": {"key1": "value1", "key2": "value2", "list": [1, 2, 3]},
}

operations = OperationTableDef()
invalid_operations = OperationTableDef()


def has_middleware(app, middleware):
    for item in app.middlewares:
        if item.__module__ == middleware.__module__:
            return True
    return False


@invalid_operations.register("does-not-exist")
async def does_not_exist(request: web.Request) -> web.Response:
    return web.Response(text="Hello, world!")


@operations.register
async def hello_world(request: web.Request) -> web.Response:
    with openapi_context(request) as context:
        name = context.parameters.query.get("name") or "world"
        email = context.parameters.query.get("email") or "world@example.com"
        return web.json_response(
            {"message": f"Hello, {name}!", "email": email}
        )


@operations.register
async def retrieve_any_object_from_request_body(
    request: web.Request,
) -> web.Response:
    return web.json_response(enforce_dicts(get_validated_data(request)))


@operations.register
async def retrieve_array_from_request_body(
    request: web.Request,
) -> web.Response:
    with openapi_context(request) as context:
        return web.json_response(context.data)


@operations.register
async def retrieve_empty(request: web.Request) -> web.Response:
    return web.Response(status=204)


@operations.register
async def retrieve_invalid_response(request: web.Request) -> web.Response:
    return web.json_response({})


@operations.register
async def retrieve_nested_object_from_request_body(
    request: web.Request,
) -> web.Response:
    with openapi_context(request) as context:
        return web.json_response(
            {**enforce_dicts(context.data), "uid": str(context.data["uid"])},
            headers={
                "X-Content-Data-Type": str(type(context.data)),
                "X-UID-Data-Type": str(type(context.data["uid"])),
            },
        )


@operations.register
async def retrieve_zip(request: web.Request) -> web.Response:
    output = io.BytesIO()

    with zipfile.ZipFile(output, "w") as handler:
        handler.writestr("hello.txt", "Hello, world!")

    output.seek(0)
    return web.Response(
        body=output,
        content_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=hello.zip"},
    )


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_any_object_request_body(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(), schema_path, operations, server_url=URL("/api/")
    )

    client = await aiohttp_client(app)
    response = await client.post("/api/any-object", json=TEST_NESTED_OBJECT)
    assert response.status == 200
    assert await response.json() == TEST_NESTED_OBJECT


@pytest.mark.parametrize(
    "data, expected_status, expected_response",
    (
        (
            {},
            422,
            {
                "detail": [
                    {
                        "loc": ["body"],
                        "message": "{} is not of type array",  # noqa: P103
                    }
                ]
            },
        ),
        (
            [],
            422,
            {"detail": [{"loc": ["body"], "message": "[] is too short"}]},
        ),
        (
            [""],
            422,
            {"detail": [{"loc": ["body", 0], "message": "'' is too short"}]},
        ),
        (["Hello", "world!"], 200, ["Hello", "world!"]),
    ),
)
async def test_array_request_body(
    aiohttp_client, data, expected_status, expected_response
):
    app = setup_openapi(
        web.Application(),
        OPENAPI_YAML_PATH,
        operations,
        server_url=URL("/api"),
    )

    client = await aiohttp_client(app)
    response = await client.post("/api/array", json=data)
    assert response.status == expected_status
    assert await response.json() == expected_response


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_email_format(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(), schema_path, operations, server_url="/api/"
    )

    client = await aiohttp_client(app)
    response = await client.get(
        "/api/hello", params={"email": "email@example.com"}
    )
    assert response.status == 200
    assert (await response.json())["email"] == "email@example.com"


def test_get_openapi_schema_no_schema():
    with pytest.raises(ConfigurationError):
        get_openapi_schema(web.Application())


def test_get_openapi_spec_no_spec():
    with pytest.raises(ConfigurationError):
        get_openapi_spec(web.Application())


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_multiple_request_errors(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(), schema_path, operations, server_url="/api/"
    )

    client = await aiohttp_client(app)
    response = await client.get("/api/hello?name=&email=")
    assert response.status == 422
    assert await response.json() == {
        "detail": [
            {
                "loc": ["parameters", "name"],
                "message": "Empty parameter value",
            },
            {
                "loc": ["parameters", "email"],
                "message": "Empty parameter value",
            },
        ]
    }


@pytest.mark.parametrize(
    "schema_path, query_string, expected_message",
    (
        (OPENAPI_JSON_PATH, None, "Hello, world!"),
        (OPENAPI_JSON_PATH, "?name=Name", "Hello, Name!"),
        (str(OPENAPI_JSON_PATH), None, "Hello, world!"),
        (str(OPENAPI_JSON_PATH), "?name=Name", "Hello, Name!"),
        (OPENAPI_YAML_PATH, None, "Hello, world!"),
        (OPENAPI_YAML_PATH, "?name=Name", "Hello, Name!"),
        (str(OPENAPI_YAML_PATH), None, "Hello, world!"),
        (str(OPENAPI_YAML_PATH), "?name=Name", "Hello, Name!"),
    ),
)
async def test_openapi(
    aiohttp_client, schema_path, query_string, expected_message
):
    app = setup_openapi(
        web.Application(), schema_path, operations, server_url="/api"
    )

    client = await aiohttp_client(app)
    url = "/api/hello"

    response = await client.get(
        f"{url}{query_string}" if query_string is not None else url
    )
    assert response.status == 200
    assert (await response.json())["message"] == expected_message


@pytest.mark.parametrize("is_enabled", (False, True))
async def test_openapi_validate_response(aiohttp_client, is_enabled):
    app = web.Application()
    setup_openapi(
        app,
        OPENAPI_YAML_PATH,
        operations,
        server_url="/api",
        is_validate_response=is_enabled,
    )

    client = await aiohttp_client(app)
    response = await client.get("/api/hello")
    assert response.status == 200
    assert await response.json() == {
        "message": "Hello, world!",
        "email": "world@example.com",
    }


@pytest.mark.parametrize(
    "has_openapi_schema_handler, url, expected_status",
    (
        (True, "/api/openapi.json", 200),
        (False, "/api/openapi.yaml", 404),
        (True, "/api/openapi.yaml", 200),
        (False, "/api/openapi.yaml", 404),
        (True, "/api/openapi.txt", 500),
        (False, "/api/openapi.txt", 404),
    ),
)
async def test_openapi_schema_handler(
    aiohttp_client, has_openapi_schema_handler, url, expected_status
):
    app = web.Application()
    setup_openapi(
        app,
        OPENAPI_YAML_PATH,
        operations,
        server_url=URL("/api"),
        has_openapi_schema_handler=has_openapi_schema_handler,
    )

    client = await aiohttp_client(app)
    response = await client.get(url)
    assert response.status == expected_status


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_request_body_nested_obejct(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(), schema_path, operations, server_url="/api/"
    )

    client = await aiohttp_client(app)
    response = await client.post("/api/nested-object", json=TEST_NESTED_OBJECT)
    assert response.status == 200
    assert response.headers["X-Content-Data-Type"] == "<class 'mappingproxy'>"
    assert response.headers["X-UID-Data-Type"] == "<class 'uuid.UUID'>"
    assert await response.json() == TEST_NESTED_OBJECT


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
def test_setup_openapi_invalid_operation(schema_path):
    with pytest.raises(OperationError):
        setup_openapi(
            web.Application(),
            schema_path,
            invalid_operations,
            server_url="/api",
        )


def test_setup_openapi_invalid_path():
    with pytest.raises(ConfigurationError):
        setup_openapi(
            web.Application(), ROOT_PATH / "does-not-exist.yaml", operations
        )


def test_setup_openapi_invalid_file():
    with pytest.raises(ConfigurationError):
        setup_openapi(web.Application(), ROOT_PATH / "settings.py", operations)


@pytest.mark.parametrize(
    "schema_path", (INVALID_OPENAPI_JSON_PATH, INVALID_OPENAPI_YAML_PATH)
)
def test_setup_openapi_invalid_spec(schema_path):
    with pytest.raises(ConfigurationError):
        setup_openapi(web.Application(), schema_path, operations)


@pytest.mark.parametrize(
    "schema_path, level, url, expected_status",
    (
        (OPENAPI_JSON_PATH, "test", "/api/hello", 200),
        (OPENAPI_JSON_PATH, "test", "/dev-api/hello", 404),
        (OPENAPI_YAML_PATH, "test", "/api/hello", 200),
        (OPENAPI_YAML_PATH, "test", "/dev-api/hello", 404),
        (OPENAPI_JSON_PATH, "dev", "/api/hello", 404),
        (OPENAPI_JSON_PATH, "dev", "/dev-api/hello", 200),
        (OPENAPI_YAML_PATH, "dev", "/api/hello", 404),
        (OPENAPI_YAML_PATH, "dev", "/dev-api/hello", 200),
    ),
)
async def test_setup_openapi_server_url_from_settings(
    monkeypatch, aiohttp_client, schema_path, level, url, expected_status
):
    monkeypatch.setenv("LEVEL", level)

    app = setup_openapi(
        setup_settings(web.Application(), BaseSettings()),
        schema_path,
        operations,
    )

    client = await aiohttp_client(app)
    response = await client.get(url)
    assert response.status == expected_status


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
def test_setup_openapi_server_url_invalid_level(monkeypatch, schema_path):
    monkeypatch.setenv("LEVEL", "prod")

    with pytest.raises(ConfigurationError):
        setup_openapi(
            setup_settings(web.Application(), BaseSettings()),
            schema_path,
            operations,
        )


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
def test_setup_openapi_server_url_does_not_set(schema_path):
    with pytest.raises(ConfigurationError):
        setup_openapi(web.Application(), schema_path, operations)


@pytest.mark.parametrize(
    "schema_path, is_enabled, kwargs",
    (
        (OPENAPI_JSON_PATH, False, None),
        (OPENAPI_YAML_PATH, False, None),
        (OPENAPI_JSON_PATH, True, {"allow_all": True}),
        (OPENAPI_YAML_PATH, True, {"origins": (URL("http://localhost:8000"))}),
    ),
)
def test_setup_openapi_use_cors_middleware(schema_path, is_enabled, kwargs):
    app = setup_openapi(
        web.Application(),
        schema_path,
        operations,
        server_url="/api/",
        use_cors_middleware=is_enabled,
        cors_middleware_kwargs=kwargs,
    )
    assert has_middleware(app, cors_middleware) is is_enabled


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
def test_setup_openapi_use_invalid_cors_middleware_kwargs(schema_path):
    with pytest.raises(ConfigurationError):
        setup_openapi(
            web.Application(),
            schema_path,
            operations,
            server_url="/api/",
            use_cors_middleware=True,
            cors_middleware_kwargs={"does_not_exist": True},
        )


@pytest.mark.parametrize(
    "schema_path, is_enabled",
    (
        (OPENAPI_JSON_PATH, False),
        (OPENAPI_YAML_PATH, False),
        (OPENAPI_JSON_PATH, True),
        (OPENAPI_YAML_PATH, True),
    ),
)
def test_setup_openapi_use_error_middleware(schema_path, is_enabled):
    app = setup_openapi(
        web.Application(),
        schema_path,
        operations,
        server_url="/api/",
        use_error_middleware=is_enabled,
    )
    assert has_middleware(app, error_middleware) is is_enabled


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_validate_binary_response(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(),
        schema_path,
        operations,
        server_url="/api",
        is_validate_response=True,
    )

    client = await aiohttp_client(app)
    response = await client.get("/api/download.zip")
    assert response.status == 200
    assert response.content_type == "application/zip"

    content = io.BytesIO(await response.read())
    with zipfile.ZipFile(content) as handler:
        with handler.open("hello.txt") as item:
            assert item.read() == b"Hello, world!"


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_validate_empty_response(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(),
        schema_path,
        operations,
        server_url="/api",
        is_validate_response=True,
    )

    client = await aiohttp_client(app)
    response = await client.get("/api/empty")
    assert response.status == 204


@pytest.mark.parametrize(
    "schema_path, is_validate_response, expected_status",
    (
        (OPENAPI_JSON_PATH, False, 200),
        (OPENAPI_JSON_PATH, True, 422),
        (OPENAPI_YAML_PATH, False, 200),
        (OPENAPI_JSON_PATH, True, 422),
    ),
)
async def test_validate_response(
    aiohttp_client, schema_path, is_validate_response, expected_status
):
    app = setup_openapi(
        web.Application(),
        schema_path,
        operations,
        server_url="/api",
        is_validate_response=is_validate_response,
    )

    client = await aiohttp_client(app)
    response = await client.get("/api/invalid-response")
    assert response.status == expected_status


@pytest.mark.parametrize("schema_path", (OPENAPI_JSON_PATH, OPENAPI_YAML_PATH))
async def test_validate_response_error(aiohttp_client, schema_path):
    app = setup_openapi(
        web.Application(),
        schema_path,
        operations,
        server_url="/api",
        is_validate_response=True,
    )

    client = await aiohttp_client(app)
    response = await client.get("/api/invalid-response")
    assert response.status == 422
    assert await response.json() == {
        "detail": [{"loc": ["response", "uid"], "message": "Field required"}]
    }
