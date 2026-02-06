from packages.shared.shared.parsers import parse_openapi, parse_postman_collection


def test_parse_openapi():
    content = """
openapi: 3.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: ok
"""
    endpoints = parse_openapi(content)
    assert len(endpoints) == 1
    assert endpoints[0].method == "GET"
    assert endpoints[0].path == "/users"


def test_parse_postman_collection():
    content = """
{
  "item": [
    {
      "name": "Example",
      "request": {
        "method": "GET",
        "url": {
          "raw": "https://api.example.com/users"
        }
      }
    }
  ]
}
"""
    endpoints = parse_postman_collection(content)
    assert len(endpoints) == 1
    assert endpoints[0].path == "/users"
