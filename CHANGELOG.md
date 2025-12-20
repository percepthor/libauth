## General
- Released libauth 0.5, built against cerver 2.0b-64: the breaking changes from 0.4.4 are in incompatibilities.md
- Reading the custom data of the routes & of the cerver with the getters of cerver 2.0
- Exporting only the AUTH_EXPORT & AUTH_PUBLIC functions, the library is compiled with -fvisibility=hidden
- Exporting auth_service_new () & auth_service_delete ()
- Added the documentation of every public function, struct, enum & define in the headers, and docs/

## Requests
- The answer of the auth service grows from 1 KB up to AUTH_RESPONSE_MAX_SIZE (64 KB), it was limited to 1 KB
- The body of a request fits the largest single permissions route even when every byte is escaped (4 KB)
- The X-Forwarded-For header fits a link local IPv6 address with its zone
- Sending the address of the client (X-Forwarded-For) & the id of the request (X-Request-Id) to the auth service
- Serializing the body with the JSON of cerver, so a value can not add fields to the request
- Never sending a header or a body that was truncated, and failing a request whose headers could not be created
- Timeouts for the connection & the request to the auth service, and the global init of curl done once

## Auth
- A token type outside of PercepthorTokenType is read as none
- Releasing the permissions & the actions that could not be inserted, and failing a permissions auth without its list
- The getters & the print functions accept NULL
- The single authentication sends the permissions action of its route, and rejects an answer that it can not read
- A service route of an AuthService without its id is rejected without calling the auth service

## Tests
- Added the unit tests of every module, the integration tests against a stub of the auth service & the fuzzers
- Checking that libauth.so exports exactly the public functions of its headers
- Running the gate with gcc 16.2, the address, undefined & thread sanitizers, g++ & the fuzzers
