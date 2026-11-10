# libauth

libauth is the C library with which the services of Percepthor authenticate their HTTP requests: a route of a
[cerver](https://github.com/ermiry/cerver) service sends the token of each request to the auth service with what the
route requires (a valid token, an action, a role, the token of a service or the permissions over a resource), and when
the auth service accepts it, the values it answered are kept as the custom data of the request.

## Compatibility

| libauth | cerver | Dependencies |
|---|---|---|
| 0.5 | 2.0b-64 or newer (the `http` line) | libcurl, pthread |

The breaking changes of each version are in [incompatibilities.md](incompatibilities.md).

## Build and install

cerver has to be installed first (`/usr/local/lib/libcerver.so` and `/usr/local/include/cerver`).

``` bash
make clean
make TYPE=production -j8
sudo make TYPE=production install
```

`TYPE` is `development` (the default, with debug logs), `test`, `beta` or `production`. The library is installed in
`/usr/local/lib/libauth.so` and its headers in `/usr/local/include/auth`. See [docs/build.md](docs/build.md) for the
other options: the sanitizers, the tests, the fuzzers and the gate.

## Usage

``` c
#include <cerver/http/http.h>
#include <cerver/http/route.h>

#include <auth/auth.h>
#include <auth/routes.h>
#include <auth/service.h>

// the service, its name and the address of the auth service
AuthService *auth_service = auth_service_create (
	"507f1f77bcf86cd799439010", "tickets", "http://auth:5000/api/auth/check"
);

http_cerver_set_custom_data (http_cerver, auth_service);

// a route that needs the action "tickets.create" of the role of the token
HttpRoute *route = http_route_create (REQUEST_METHOD_POST, "tickets", tickets_create_handler);
http_route_set_auth (route, HTTP_ROUTE_AUTH_TYPE_CUSTOM);
http_route_set_authentication_handler (route, percepthor_custom_authentication_handler);
http_route_set_custom_data (route, auth_route_create_action ("tickets.create"));
http_route_set_delete_custom_data (route, auth_route_delete);

// in the handler, the values that the auth service answered
const PercepthorAuth *auth = (const PercepthorAuth *) http_request_get_custom_data (request);
const char *user = percepthor_auth_get_token_user (auth);
```

The same works for a group or an endpoint of the routes tree (`http_group_set_authentication_handler ()`,
`http_endpoint_set_custom_data ()`). The documentation of each part is in [docs](docs/README.md), and every public
function has its documentation in its header.

## Tests

The tests run in Docker, against a cerver compiled from its sources:

``` bash
CERVER_DIR=/path/to/cerver bash test/build.sh
docker run --rm itpercepthor/libauth:test bash test/run.sh
bash test/gate.sh
```

See [test/README.md](test/README.md).
