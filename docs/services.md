# Services

`#include <auth/service.h>`

The `AuthService` is the service that sends the requests to the auth service. It is the custom data of the HTTP cerver
of the service, so the authentication handlers read it from every request:

``` c
AuthService *auth_service = auth_service_create (
	"507f1f77bcf86cd799439010",				// the id of the service, only needed by its service routes
	"tickets",								// the name, the source of every request
	"http://auth:5000/api/auth/check"		// the address of the auth service
);

http_cerver_set_custom_data (http_cerver, auth_service);
http_cerver_set_delete_custom_data (http_cerver, auth_service_delete);
```

| Function | |
|---|---|
| `auth_service_create (id, name, address)` | Creates it, a value longer than its buffer is truncated |
| `auth_service_new ()` | An empty one |
| `auth_service_delete (auth_service)` | Releases it |
| `auth_service_print (auth_service)` | Prints its values |

A service route of an `AuthService` without its id is rejected without calling the auth service, which would always
answer 400.
