#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <pthread.h>

#include <cerver/cerver.h>
#include <cerver/network.h>

#include <cerver/http/headers.h>
#include <cerver/http/http.h>
#include <cerver/http/request.h>
#include <cerver/http/response.h>
#include <cerver/http/route.h>
#include <cerver/http/status.h>
#include <cerver/http/tree.h>

#include <cerver/http/json/json.h>

#include <auth/auth.h>
#include <auth/permissions.h>
#include <auth/requests.h>
#include <auth/routes.h>
#include <auth/service.h>

#include "test.h"

// a web cerver whose routes authenticate with libauth, against a stub of the auth service
// that answers what each case needs; the stub is a group of the same cerver (before cerver
// 2.0b-60 only one HTTP cerver could run in a process), and a client talks to it with raw sockets

// bugs this suite fixed:
// - an integer mask answered by the auth service crashed the cerver, atoll (NULL)
// - a cerver without its AuthService, or a route without its AuthRoute, crashed it
// - an answer that was not json leaked its PercepthorAuth
// - the single authentication accepted a request whose answer it could not read
// - the single authentication sent the empty action of the route instead of its permissions action
// - a quote in the resource of a single authentication turned it into a check without permissions
// - a role route without an action always failed: it sent an empty action
// - a service route of an AuthService without its id was sent without the service, always a 400
// - an answer of the auth service larger than 1 KB, like the permissions of many resources, was rejected

#define TEST_AUTH_ADDRESS					"127.0.0.1"
#define TEST_AUTH_SERVICE_PORT				9021

#define TEST_AUTH_STUB_URL					"http://127.0.0.1:9021/api/auth/check"
#define TEST_AUTH_CLOSED_URL				"http://127.0.0.1:9022/api/auth/check"

#define TEST_AUTH_SERVICE_NAME				"libauth-test"
#define TEST_AUTH_SERVICE_ID				"507f1f77bcf86cd799439010"

#define TEST_AUTH_TOKEN						"Bearer libauth-test-token"
#define TEST_AUTH_TOKEN_ID					"507f1f77bcf86cd799439011"
#define TEST_AUTH_RESOURCE					"507f1f77bcf86cd799439012"

#define TEST_AUTH_ACTION					"tickets.create"
#define TEST_AUTH_ROLE						"admin"

#define TEST_AUTH_BUFFER_SIZE				(1 << 13)

// every authenticated request holds a thread while the stub answers it in another one
#define TEST_AUTH_THREADS					32

#define TEST_AUTH_CONNECT_RETRIES			256
// 2^22 ns
#define TEST_AUTH_CONNECT_INTERVAL			4194304L
#define TEST_AUTH_RECEIVE_TIMEOUT			16
#define TEST_AUTH_JOIN_TIMEOUT				32

// longer than the request timeout of the test build
#define TEST_AUTH_SLOW_SECONDS				(AUTH_REQUEST_TIMEOUT + 2)

// the resources of a management answer between the first buffer and the largest answer
#define TEST_AUTH_GROWN_RESOURCES			40

#define TEST_AUTH_CONCURRENT_CLIENTS		8
#define TEST_AUTH_CONCURRENT_REQUESTS		16

static const char *status_ok = { "HTTP/1.1 200" };
static const char *status_unauthorized = { "HTTP/1.1 401" };

static const char *token_answer = {
	"{\"token\": {\"id\": \"" TEST_AUTH_TOKEN_ID "\", \"t_type\": 4, \"user\": \"507f1f77bcf86cd799439014\"}}"
};

#pragma region stub

// what the stub answers and what it received, the cases run one at a time
typedef struct TestAuthStub {

	pthread_mutex_t mutex;

	unsigned int status;
	char answer[TEST_AUTH_BUFFER_SIZE];
	unsigned int delay_seconds;

	unsigned int n_requests;
	char authorization[TEST_AUTH_BUFFER_SIZE];
	char body[TEST_AUTH_BUFFER_SIZE];

	// the client and the id of the request that libauth authenticated
	char forwarded_for[TEST_AUTH_BUFFER_SIZE];
	char request_id[TEST_AUTH_BUFFER_SIZE];

} TestAuthStub;

static TestAuthStub stub = { PTHREAD_MUTEX_INITIALIZER, 200, { 0 }, 0, 0, { 0 }, { 0 }, { 0 }, { 0 } };

static void test_auth_stub_answer (const unsigned int status, const char *answer) {

	(void) pthread_mutex_lock (&stub.mutex);

	stub.status = status;
	(void) snprintf (stub.answer, TEST_AUTH_BUFFER_SIZE, "%s", answer);
	stub.delay_seconds = 0;

	stub.n_requests = 0;
	stub.authorization[0] = '\0';
	stub.body[0] = '\0';
	stub.forwarded_for[0] = '\0';
	stub.request_id[0] = '\0';

	(void) pthread_mutex_unlock (&stub.mutex);

}

static unsigned int test_auth_stub_requests (void) {

	(void) pthread_mutex_lock (&stub.mutex);
	const unsigned int n_requests = stub.n_requests;
	(void) pthread_mutex_unlock (&stub.mutex);

	return n_requests;

}

// the body that the stub received, as json
static json_t *test_auth_stub_body (void) {

	(void) pthread_mutex_lock (&stub.mutex);
	json_error_t error = { 0 };
	json_t *body = json_loads (stub.body, 0, &error);
	(void) pthread_mutex_unlock (&stub.mutex);

	test_check (json_is_object (body), "the auth service did not receive a json object");

	return body;

}

// POST /api/auth/check
static void test_auth_stub_handler (
	const HttpReceive *http_receive, const HttpRequest *request
) {

	(void) pthread_mutex_lock (&stub.mutex);

	stub.n_requests += 1;

	const String *authorization = http_request_get_header (request, HTTP_HEADER_AUTHORIZATION);
	(void) snprintf (stub.authorization, TEST_AUTH_BUFFER_SIZE, "%s", authorization ? authorization->str : "");

	const String *body = http_request_get_body (request);
	(void) snprintf (stub.body, TEST_AUTH_BUFFER_SIZE, "%s", body ? body->str : "");

	const String *forwarded_for = http_request_get_header (request, HTTP_HEADER_FORWARDED_FOR);
	(void) snprintf (stub.forwarded_for, TEST_AUTH_BUFFER_SIZE, "%s", forwarded_for ? forwarded_for->str : "");

	const String *request_id = http_request_get_header (request, HTTP_HEADER_REQUEST_ID);
	(void) snprintf (stub.request_id, TEST_AUTH_BUFFER_SIZE, "%s", request_id ? request_id->str : "");

	const unsigned int status = stub.status;
	const unsigned int delay_seconds = stub.delay_seconds;

	char answer[TEST_AUTH_BUFFER_SIZE];
	(void) snprintf (answer, TEST_AUTH_BUFFER_SIZE, "%s", stub.answer);

	(void) pthread_mutex_unlock (&stub.mutex);

	if (delay_seconds) (void) sleep (delay_seconds);

	(void) http_response_json_custom_reference_send (
		http_receive, (http_status) status, answer, strlen (answer)
	);

}

#pragma endregion

#pragma region service

static AuthService *auth_service = NULL;

// the auth values that a route received, as json
static void test_auth_service_handler (
	const HttpReceive *http_receive, const HttpRequest *request
) {

	const PercepthorAuth *auth = (const PercepthorAuth *) http_request_get_custom_data (request);

	unsigned int n_resources = 0;
	if (percepthor_auth_get_permissions (auth)) {
		n_resources = (unsigned int) percepthor_auth_get_permissions (auth)->size;
	}

	char answer[TEST_AUTH_BUFFER_SIZE];
	(void) snprintf (
		answer, TEST_AUTH_BUFFER_SIZE,
		"{\"id\": \"%s\", \"type\": %u, \"mask\": %ld, \"admin\": %s, \"resources\": %u, \"resource\": \"%s\"}",
		auth ? percepthor_auth_get_token_id (auth) : "",
		(unsigned int) percepthor_auth_get_type (auth),
		(long) percepthor_auth_get_mask (auth),
		percepthor_auth_get_admin (auth) ? "true" : "false",
		n_resources,
		auth ? percepthor_auth_get_resource (auth) : ""
	);

	(void) http_response_json_custom_reference_send (
		http_receive, HTTP_STATUS_OK, answer, strlen (answer)
	);

}

// GET /api/test/single/:id authenticates itself with the resource of its path
static void test_auth_single_handler (
	const HttpReceive *http_receive, const HttpRequest *request
) {

	const String *resource = http_request_get_param_at_idx (request, 0);

	if (!percepthor_single_authentication (http_receive, request, resource ? resource->str : NULL)) {
		test_auth_service_handler (http_receive, request);
	}

	else {
		(void) http_response_json_key_value_send (
			http_receive, HTTP_STATUS_UNAUTHORIZED, "error", "Failed authentication!"
		);
	}

}

static void test_auth_endpoint (
	HttpGroup *group, const char *path, AuthRoute *auth_route
) {

	HttpEndpoint *endpoint = http_group_route_add (
		group, REQUEST_METHOD_GET, path, test_auth_service_handler
	);

	test_check_ptr (endpoint);

	http_endpoint_set_auth (endpoint, HTTP_ROUTE_AUTH_TYPE_CUSTOM);
	http_endpoint_set_authentication_handler (endpoint, percepthor_custom_authentication_handler);

	if (auth_route) {
		http_endpoint_set_custom_data (endpoint, auth_route, auth_route_delete);
	}

}

static void test_auth_service_routes (HttpCerver *http_cerver) {

	HttpGroup *group = http_cerver_group_create (http_cerver, "api/test");
	test_check_ptr (group);

	test_auth_endpoint (group, "token", auth_route_create ());
	test_auth_endpoint (group, "action", auth_route_create_action (TEST_AUTH_ACTION));
	test_auth_endpoint (group, "role", auth_route_create_role (NULL, TEST_AUTH_ROLE));
	test_auth_endpoint (group, "service", auth_route_create_service ());
	test_auth_endpoint (group, "management", auth_route_create_permissions (
		PERCEPTHOR_AUTH_SCOPE_MANAGEMENT, PERMISSIONS_TYPE_ORGANIZATION, TEST_AUTH_ACTION
	));

	AuthRoute *multiple = auth_route_create ();
	multiple->auth_type = PERCEPTHOR_AUTH_TYPE_MULTIPLE;
	test_auth_endpoint (group, "multiple", multiple);

	// a route that was registered without its AuthRoute
	test_auth_endpoint (group, "missing", NULL);

	HttpEndpoint *single = http_group_route_add (
		group, REQUEST_METHOD_GET, "single/:id", test_auth_single_handler
	);

	test_check_ptr (single);

	http_endpoint_set_custom_data (
		single,
		auth_route_create_permissions (
			PERCEPTHOR_AUTH_SCOPE_SINGLE, PERMISSIONS_TYPE_ORGANIZATION, TEST_AUTH_ACTION
		),
		auth_route_delete
	);

}

static void test_auth_routes (HttpCerver *http_cerver) {

	HttpGroup *group = http_cerver_group_create (http_cerver, "api/auth");
	test_check_ptr (group);

	test_check_ptr (http_group_route_add (group, REQUEST_METHOD_POST, "check", test_auth_stub_handler));

	test_auth_service_routes (http_cerver);

}

#pragma endregion

#pragma region cervers

typedef struct TestAuthCerver {

	Cerver *cerver;
	pthread_t thread;

} TestAuthCerver;

static void *test_auth_cerver_thread (void *cerver_ptr) {

	(void) cerver_start ((Cerver *) cerver_ptr);

	return NULL;

}

static int test_auth_connect_once (const u16 port) {

	int fd = socket (AF_INET, SOCK_STREAM, 0);
	test_check (fd > -1, "socket () failed");

	struct sockaddr_in address;
	(void) memset (&address, 0, sizeof (struct sockaddr_in));
	address.sin_family = AF_INET;
	address.sin_port = htons (port);
	(void) inet_pton (AF_INET, TEST_AUTH_ADDRESS, &address.sin_addr);

	if (connect (fd, (const struct sockaddr *) &address, sizeof (struct sockaddr_in))) {
		(void) close (fd);
		fd = -1;
	}

	return fd;

}

static int test_auth_connect (const u16 port) {

	const struct timespec interval = { 0, TEST_AUTH_CONNECT_INTERVAL };

	int fd = -1;
	for (unsigned int i = 0; (i < TEST_AUTH_CONNECT_RETRIES) && (fd < 0); i++) {
		fd = test_auth_connect_once (port);
		if (fd < 0) (void) nanosleep (&interval, NULL);
	}

	test_check (fd > -1, "failed to connect to the test cerver");

	(void) sock_set_timeout (fd, TEST_AUTH_RECEIVE_TIMEOUT);

	return fd;

}

static TestAuthCerver test_auth_cerver_start (
	const char *name, const u16 port, void (*routes)(HttpCerver *)
) {

	TestAuthCerver test_cerver = { NULL, 0 };

	test_cerver.cerver = cerver_create_web (name, port, CERVER_DEFAULT_CONNECTION_QUEUE);
	test_check_ptr (test_cerver.cerver);

	cerver_set_handler_type (test_cerver.cerver, CERVER_HANDLER_TYPE_THREADS);
	cerver_set_thpool_n_threads (test_cerver.cerver, TEST_AUTH_THREADS);
	cerver_set_reusable_address_flags (test_cerver.cerver, true);

	routes ((HttpCerver *) test_cerver.cerver->cerver_data);

	test_check_int_eq (
		pthread_create (&test_cerver.thread, NULL, test_auth_cerver_thread, test_cerver.cerver),
		0, NULL
	);

	(void) close (test_auth_connect (port));

	return test_cerver;

}

static void test_auth_cerver_stop (TestAuthCerver *test_cerver) {

	test_check_unsigned_eq (cerver_shutdown (test_cerver->cerver), 0, NULL);

	struct timespec deadline;
	(void) clock_gettime (CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TEST_AUTH_JOIN_TIMEOUT;

	test_check_int_eq (pthread_timedjoin_np (test_cerver->thread, NULL, &deadline), 0, NULL);

	test_check_unsigned_eq (cerver_teardown (test_cerver->cerver), 0, NULL);

}

static void test_auth_service_set (const char *address) {

	if (auth_service) auth_service_delete (auth_service);

	auth_service = address
		? auth_service_create (TEST_AUTH_SERVICE_ID, TEST_AUTH_SERVICE_NAME, address)
		: NULL;

}

#pragma endregion

#pragma region client

typedef struct TestAuthResponse {

	char text[TEST_AUTH_BUFFER_SIZE];
	json_t *body;

} TestAuthResponse;

// sends a GET with the extra headers ("" for none) and reads the whole response,
// until the cerver closes the connection
static void test_auth_get_with (
	const char *path, const char *authorization, const char *headers, TestAuthResponse *response
) {

	char request[TEST_AUTH_BUFFER_SIZE];
	if (authorization) {
		(void) snprintf (
			request, TEST_AUTH_BUFFER_SIZE,
			"GET %s HTTP/1.1\r\nHost: localhost\r\nAuthorization: %s\r\n%s\r\n",
			path, authorization, headers
		);
	}

	else {
		(void) snprintf (
			request, TEST_AUTH_BUFFER_SIZE,
			"GET %s HTTP/1.1\r\nHost: localhost\r\n%s\r\n", path, headers
		);
	}

	const int fd = test_auth_connect (TEST_AUTH_SERVICE_PORT);

	const size_t length = strlen (request);
	test_check (send (fd, request, length, MSG_NOSIGNAL) == (ssize_t) length, "send () failed");

	size_t total = 0;
	ssize_t received = 0;
	while (
		(total < (TEST_AUTH_BUFFER_SIZE - 1))
		&& ((received = recv (fd, response->text + total, TEST_AUTH_BUFFER_SIZE - 1 - total, 0)) > 0)
	) {
		total += (size_t) received;
	}

	response->text[total] = '\0';

	(void) close (fd);

	response->body = NULL;
	const char *body = strstr (response->text, "\r\n\r\n");
	if (body) {
		json_error_t error = { 0 };
		response->body = json_loads (body + 4, 0, &error);
	}

}

static void test_auth_get (
	const char *path, const char *authorization, TestAuthResponse *response
) {

	test_auth_get_with (path, authorization, "", response);

}

static void test_auth_response_delete (TestAuthResponse *response) {

	if (response->body) json_decref (response->body);
	response->body = NULL;

}

static void test_auth_expect_status (const TestAuthResponse *response, const char *status, const char *label) {

	if (strncmp (response->text, status, strlen (status))) {
		(void) fprintf (stderr, "%s: expected %s, got:\n%s\n", label, status, response->text);
	}

	test_check (!strncmp (response->text, status, strlen (status)), label);

}

static void test_auth_expect_string (const json_t *body, const char *key, const char *expected) {

	const json_t *value = json_object_get (body, key);
	test_check (json_is_string (value), key);
	test_check_str_eq (json_string_value (value), expected, key);

}

static void test_auth_expect_integer (const json_t *body, const char *key, const json_int_t expected) {

	const json_t *value = json_object_get (body, key);
	test_check (json_is_integer (value), key);
	test_check_long_int_eq (json_integer_value (value), expected, key);

}

// a case that the auth service accepts and the route answers with its auth values
static json_t *test_auth_accepted (const char *path, const char *label, TestAuthResponse *response) {

	test_auth_get (path, TEST_AUTH_TOKEN, response);
	test_auth_expect_status (response, status_ok, label);
	test_check (response->body != NULL, label);

	return response->body;

}

static void test_auth_rejected (const char *path, const char *authorization, const char *label) {

	TestAuthResponse response = { 0 };
	test_auth_get (path, authorization, &response);
	test_auth_expect_status (&response, status_unauthorized, label);
	test_auth_response_delete (&response);

}

#pragma endregion

#pragma region cases

static void test_auth_without_token (void) {

	test_auth_stub_answer (200, token_answer);

	test_auth_rejected ("/api/test/token", NULL, "a request without a token");
	test_check_unsigned_eq (test_auth_stub_requests (), 0, NULL);

}

static void test_auth_token (void) {

	test_auth_stub_answer (200, token_answer);

	TestAuthResponse response = { 0 };
	json_t *body = test_auth_accepted ("/api/test/token", "a valid token", &response);
	test_auth_expect_string (body, "id", TEST_AUTH_TOKEN_ID);
	test_auth_expect_integer (body, "type", PERCEPTHOR_AUTH_TYPE_TOKEN);
	test_auth_response_delete (&response);

	// the token is forwarded as it came, with the source of the service
	test_check_unsigned_eq (test_auth_stub_requests (), 1, NULL);

	char authorization[TEST_AUTH_BUFFER_SIZE];
	(void) pthread_mutex_lock (&stub.mutex);
	(void) snprintf (authorization, TEST_AUTH_BUFFER_SIZE, "%s", stub.authorization);
	(void) pthread_mutex_unlock (&stub.mutex);

	test_check_str_eq (authorization, TEST_AUTH_TOKEN, NULL);

	json_t *sent = test_auth_stub_body ();
	test_auth_expect_integer (sent, "type", PERCEPTHOR_AUTH_TYPE_TOKEN);
	test_auth_expect_string (sent, "source", TEST_AUTH_SERVICE_NAME);
	json_decref (sent);

}

// the auth service receives the client's address and the request's id of the authenticated request,
// the cerver trusts the loopback as a proxy, like nginx in a private network
static void test_auth_client (HttpCerver *http_cerver) {

	http_cerver_set_request_id (http_cerver, true);
	http_cerver_set_trusted_proxies (http_cerver, HTTP_TRUSTED_PROXIES_PRIVATE);

	test_auth_stub_answer (200, token_answer);

	TestAuthResponse response = { 0 };
	test_auth_get_with (
		"/api/test/token", TEST_AUTH_TOKEN,
		"X-Forwarded-For: 203.0.113.5\r\nX-Request-Id: client-request-9\r\n", &response
	);

	test_auth_expect_status (&response, status_ok, "a request with its client");
	test_auth_response_delete (&response);

	char forwarded_for[TEST_AUTH_BUFFER_SIZE];
	char request_id[TEST_AUTH_BUFFER_SIZE];
	(void) pthread_mutex_lock (&stub.mutex);
	(void) snprintf (forwarded_for, TEST_AUTH_BUFFER_SIZE, "%s", stub.forwarded_for);
	(void) snprintf (request_id, TEST_AUTH_BUFFER_SIZE, "%s", stub.request_id);
	(void) pthread_mutex_unlock (&stub.mutex);

	test_check_str_eq (forwarded_for, "203.0.113.5", NULL);
	test_check_str_eq (request_id, "client-request-9", NULL);

	// without request ids the auth service still receives the client
	http_cerver_set_request_id (http_cerver, false);
	test_auth_stub_answer (200, token_answer);

	test_auth_get ("/api/test/token", TEST_AUTH_TOKEN, &response);
	test_auth_response_delete (&response);

	(void) pthread_mutex_lock (&stub.mutex);
	(void) snprintf (forwarded_for, TEST_AUTH_BUFFER_SIZE, "%s", stub.forwarded_for);
	(void) snprintf (request_id, TEST_AUTH_BUFFER_SIZE, "%s", stub.request_id);
	(void) pthread_mutex_unlock (&stub.mutex);

	test_check_str_eq (forwarded_for, TEST_AUTH_ADDRESS, NULL);
	test_check_str_eq (request_id, "", NULL);

	http_cerver_set_trusted_proxies (http_cerver, HTTP_TRUSTED_PROXIES_NONE);

}

// any answer of the auth service that is not a 200 with a json object is a rejection
static void test_auth_rejections (void) {

	static const unsigned int statuses[] = { 400, 401, 404, 500 };
	for (size_t i = 0; i < (sizeof (statuses) / sizeof (statuses[0])); i++) {
		test_auth_stub_answer (statuses[i], "{\"error\": \"Failed authentication!\"}");
		test_auth_rejected ("/api/test/token", TEST_AUTH_TOKEN, "a status of the auth service");
	}

	static const char *answers[] = { "", "not json", "[1, 2]", "{\"token\": " };
	for (size_t i = 0; i < (sizeof (answers) / sizeof (answers[0])); i++) {
		test_auth_stub_answer (200, answers[i]);
		test_auth_rejected ("/api/test/token", TEST_AUTH_TOKEN, "an answer that is not json");
		test_auth_rejected ("/api/test/service", TEST_AUTH_TOKEN, "a service answer that is not json");
		test_auth_rejected ("/api/test/management", TEST_AUTH_TOKEN, "a management answer that is not json");
		test_auth_rejected ("/api/test/single/" TEST_AUTH_RESOURCE, TEST_AUTH_TOKEN, "a single answer that is not json");
	}

}

// an answer larger than AUTH_RESPONSE_MAX_SIZE (4096 in the test build) is a rejection,
// never an overflow nor an answer read truncated
static void test_auth_answer_too_large (void) {

	char answer[TEST_AUTH_BUFFER_SIZE];
	(void) snprintf (answer, TEST_AUTH_BUFFER_SIZE, "{\"token\": {\"username\": \"%05000d\"}}", 1);

	test_auth_stub_answer (200, answer);
	test_auth_rejected ("/api/test/token", TEST_AUTH_TOKEN, "an answer larger than the largest one");

}

// the response buffer grows with the answer: the management permissions of many
// resources pass AUTH_RESPONSE_INITIAL_SIZE and are read whole
static void test_auth_answer_grows (void) {

	char answer[TEST_AUTH_BUFFER_SIZE];
	int written = snprintf (
		answer, TEST_AUTH_BUFFER_SIZE, "{\"token\": {\"id\": \"" TEST_AUTH_TOKEN_ID "\"}, \"resources\": ["
	);

	for (unsigned int i = 0; i < TEST_AUTH_GROWN_RESOURCES; i++) {
		written += snprintf (
			answer + written, (size_t) (TEST_AUTH_BUFFER_SIZE - written),
			"%s{\"_id\": \"507f1f77bcf86cd7994%05u\", \"actions\": [\"" TEST_AUTH_ACTION "\"]}",
			i ? ", " : "", i
		);
	}

	(void) snprintf (answer + written, (size_t) (TEST_AUTH_BUFFER_SIZE - written), "]}");
	test_check ((strlen (answer) > AUTH_RESPONSE_INITIAL_SIZE) && (strlen (answer) < AUTH_RESPONSE_MAX_SIZE), NULL);

	test_auth_stub_answer (200, answer);

	TestAuthResponse response = { 0 };
	json_t *body = test_auth_accepted ("/api/test/management", "an answer larger than the first buffer", &response);
	test_auth_expect_integer (body, "resources", TEST_AUTH_GROWN_RESOURCES);
	test_auth_response_delete (&response);

}

static void test_auth_action (void) {

	test_auth_stub_answer (200, token_answer);

	TestAuthResponse response = { 0 };
	json_t *body = test_auth_accepted ("/api/test/action", "an action", &response);
	test_auth_expect_integer (body, "type", PERCEPTHOR_AUTH_TYPE_ACTION);
	test_auth_response_delete (&response);

	json_t *sent = test_auth_stub_body ();
	test_auth_expect_string (sent, "action", TEST_AUTH_ACTION);
	json_decref (sent);

}

// a role without an action sends the role and the source, never an empty action
static void test_auth_role (void) {

	test_auth_stub_answer (200, token_answer);

	TestAuthResponse response = { 0 };
	(void) test_auth_accepted ("/api/test/role", "a role", &response);
	test_auth_response_delete (&response);

	json_t *sent = test_auth_stub_body ();
	test_auth_expect_integer (sent, "type", PERCEPTHOR_AUTH_TYPE_ROLE);
	test_auth_expect_string (sent, "role", TEST_AUTH_ROLE);
	test_auth_expect_string (sent, "source", TEST_AUTH_SERVICE_NAME);
	test_check_null_ptr (json_object_get (sent, "action"));
	json_decref (sent);

}

// the mask comes as a number from the token permissions and as a string from redis
static void test_auth_service (void) {

	static const char *answers[] = {
		"{\"token\": {\"id\": \"" TEST_AUTH_TOKEN_ID "\"}, \"mask\": 12}",
		"{\"token\": {\"id\": \"" TEST_AUTH_TOKEN_ID "\"}, \"mask\": \"12\"}"
	};

	for (size_t i = 0; i < 2; i++) {
		test_auth_stub_answer (200, answers[i]);

		TestAuthResponse response = { 0 };
		json_t *body = test_auth_accepted ("/api/test/service", answers[i], &response);
		test_auth_expect_integer (body, "mask", 12);
		test_auth_expect_integer (body, "type", PERCEPTHOR_AUTH_TYPE_SERVICE);
		test_auth_response_delete (&response);

		json_t *sent = test_auth_stub_body ();
		test_auth_expect_string (sent, "service", TEST_AUTH_SERVICE_ID);
		json_decref (sent);
	}

}

// the services create their AuthService without an id: a route of a service is rejected
// without asking the auth service, that would answer 400 to a check without the service
static void test_auth_service_without_id (HttpCerver *http_cerver) {

	test_auth_stub_answer (200, "{\"token\": {\"id\": \"" TEST_AUTH_TOKEN_ID "\"}, \"mask\": 12}");

	AuthService *without_id = auth_service_create (NULL, TEST_AUTH_SERVICE_NAME, TEST_AUTH_STUB_URL);
	http_cerver_set_custom_data (http_cerver, without_id);

	test_auth_rejected ("/api/test/service", TEST_AUTH_TOKEN, "a service route without the service id");
	test_check_unsigned_eq (test_auth_stub_requests (), 0, NULL);

	// the other routes do not need it
	TestAuthResponse response = { 0 };
	test_auth_stub_answer (200, token_answer);
	(void) test_auth_accepted ("/api/test/token", "a token route without the service id", &response);
	test_auth_response_delete (&response);

	http_cerver_set_custom_data (http_cerver, auth_service);
	auth_service_delete (without_id);

}

static void test_auth_management (void) {

	test_auth_stub_answer (
		200,
		"{\"token\": {\"id\": \"" TEST_AUTH_TOKEN_ID "\"}, \"resources\": ["
		"{\"_id\": \"" TEST_AUTH_RESOURCE "\", \"actions\": [\"" TEST_AUTH_ACTION "\"]}"
		"]}"
	);

	TestAuthResponse response = { 0 };
	json_t *body = test_auth_accepted ("/api/test/management", "the management permissions", &response);
	test_auth_expect_integer (body, "resources", 1);
	test_auth_response_delete (&response);

	json_t *sent = test_auth_stub_body ();
	test_auth_expect_integer (sent, "scope", PERCEPTHOR_AUTH_SCOPE_MANAGEMENT);
	test_auth_expect_integer (sent, "permissions_type", PERMISSIONS_TYPE_ORGANIZATION);
	test_auth_expect_string (sent, "action", TEST_AUTH_ACTION);
	json_decref (sent);

	test_auth_stub_answer (200, "{\"admin\": true}");
	body = test_auth_accepted ("/api/test/management", "an admin", &response);
	test_check_true (json_is_true (json_object_get (body, "admin")));
	test_auth_response_delete (&response);

}

static void test_auth_single (void) {

	test_auth_stub_answer (200, token_answer);

	TestAuthResponse response = { 0 };
	json_t *body = test_auth_accepted ("/api/test/single/" TEST_AUTH_RESOURCE, "a single permission", &response);
	test_auth_expect_string (body, "resource", TEST_AUTH_RESOURCE);
	test_auth_expect_integer (body, "type", PERCEPTHOR_AUTH_TYPE_PERMISSIONS);
	test_auth_response_delete (&response);

	// the action is the permissions action of the route
	json_t *sent = test_auth_stub_body ();
	test_auth_expect_integer (sent, "scope", PERCEPTHOR_AUTH_SCOPE_SINGLE);
	test_auth_expect_string (sent, "resource", TEST_AUTH_RESOURCE);
	test_auth_expect_string (sent, "action", TEST_AUTH_ACTION);
	json_decref (sent);

	test_auth_stub_answer (401, "{\"error\": \"Failed authentication!\"}");
	test_auth_rejected ("/api/test/single/" TEST_AUTH_RESOURCE, TEST_AUTH_TOKEN, "a single permission that is denied");

}

// the resource comes from the path: its quotes can not change the request to the auth service
static void test_auth_single_injection (void) {

	test_auth_stub_answer (200, token_answer);

	TestAuthResponse response = { 0 };
	test_auth_get (
		"/api/test/single/x%22,%22scope%22:0,%22y%22:%22", TEST_AUTH_TOKEN, &response
	);
	test_auth_response_delete (&response);

	if (test_auth_stub_requests ()) {
		json_t *sent = test_auth_stub_body ();
		test_auth_expect_integer (sent, "scope", PERCEPTHOR_AUTH_SCOPE_SINGLE);
		test_check_null_ptr (json_object_get (sent, "y"));
		json_decref (sent);
	}

}

static void test_auth_unsupported_types (void) {

	test_auth_stub_answer (200, token_answer);

	test_auth_rejected ("/api/test/multiple", TEST_AUTH_TOKEN, "a multiple auth route");
	test_auth_rejected ("/api/test/missing", TEST_AUTH_TOKEN, "a route without its auth route");
	test_check_unsigned_eq (test_auth_stub_requests (), 0, NULL);

}

// a cerver without its AuthService rejects every request instead of crashing
static void test_auth_without_service (HttpCerver *http_cerver) {

	test_auth_stub_answer (200, token_answer);

	http_cerver_set_custom_data (http_cerver, NULL);

	test_auth_rejected ("/api/test/token", TEST_AUTH_TOKEN, "a cerver without its auth service");
	test_auth_rejected ("/api/test/single/" TEST_AUTH_RESOURCE, TEST_AUTH_TOKEN, "a single without its auth service");
	test_check_unsigned_eq (test_auth_stub_requests (), 0, NULL);

	http_cerver_set_custom_data (http_cerver, auth_service);

}

static void test_auth_unreachable (HttpCerver *http_cerver) {

	AuthService *closed = auth_service_create (TEST_AUTH_SERVICE_ID, TEST_AUTH_SERVICE_NAME, TEST_AUTH_CLOSED_URL);
	http_cerver_set_custom_data (http_cerver, closed);

	test_auth_rejected ("/api/test/token", TEST_AUTH_TOKEN, "an auth service that is not listening");

	http_cerver_set_custom_data (http_cerver, auth_service);
	auth_service_delete (closed);

}

// a slow auth service is cut by the request timeout instead of holding the thread
static void test_auth_slow (void) {

	test_auth_stub_answer (200, token_answer);

	(void) pthread_mutex_lock (&stub.mutex);
	stub.delay_seconds = TEST_AUTH_SLOW_SECONDS;
	(void) pthread_mutex_unlock (&stub.mutex);

	const time_t start = time (NULL);
	test_auth_rejected ("/api/test/token", TEST_AUTH_TOKEN, "a slow auth service");
	test_check ((time (NULL) - start) <= (AUTH_REQUEST_TIMEOUT + 1), "the request timeout did not cut the auth service");

	test_auth_stub_answer (200, token_answer);

	// lets the stub thread that is still sleeping end before the next case
	(void) sleep (TEST_AUTH_SLOW_SECONDS - AUTH_REQUEST_TIMEOUT + 1);

}

static unsigned int concurrent_accepted = 0;

static void *test_auth_concurrent_client (void *unused) {

	for (unsigned int i = 0; i < TEST_AUTH_CONCURRENT_REQUESTS; i++) {
		TestAuthResponse response = { 0 };
		test_auth_get ("/api/test/token", TEST_AUTH_TOKEN, &response);

		if (!strncmp (response.text, status_ok, strlen (status_ok))) {
			test_counter_add (&concurrent_accepted);
		}

		test_auth_response_delete (&response);
	}

	return unused;

}

// the threads of the cerver authenticate at the same time
static void test_auth_concurrent (void) {

	test_auth_stub_answer (200, token_answer);

	pthread_t clients[TEST_AUTH_CONCURRENT_CLIENTS];
	for (unsigned int i = 0; i < TEST_AUTH_CONCURRENT_CLIENTS; i++) {
		test_check_int_eq (pthread_create (&clients[i], NULL, test_auth_concurrent_client, NULL), 0, NULL);
	}

	for (unsigned int i = 0; i < TEST_AUTH_CONCURRENT_CLIENTS; i++) {
		(void) pthread_join (clients[i], NULL);
	}

	test_check_unsigned_eq (
		concurrent_accepted, TEST_AUTH_CONCURRENT_CLIENTS * TEST_AUTH_CONCURRENT_REQUESTS, NULL
	);

}

#pragma endregion

// TEST_AUTH_CASE runs a single case, to see each regression fail on its own
#define TEST_AUTH_CASE_VARIABLE				"TEST_AUTH_CASE"

#define test_auth_case(name, call)											\
	({																		\
		const char *selected = getenv (TEST_AUTH_CASE_VARIABLE);			\
		if (!selected || !strcmp (selected, name)) {						\
			(void) printf ("\t%s\n", name);								\
			call;															\
		}																	\
	})

int main (int argc, char **argv) {

	(void) printf ("Testing AUTH integration...\n");

	test_auth_service_set (TEST_AUTH_STUB_URL);

	TestAuthCerver service_cerver = test_auth_cerver_start ("auth-test", TEST_AUTH_SERVICE_PORT, test_auth_routes);

	HttpCerver *http_cerver = (HttpCerver *) service_cerver.cerver->cerver_data;
	http_cerver_set_custom_data (http_cerver, auth_service);

	test_auth_case ("without_token", test_auth_without_token ());
	test_auth_case ("token", test_auth_token ());
	test_auth_case ("client", test_auth_client (http_cerver));
	test_auth_case ("rejections", test_auth_rejections ());
	test_auth_case ("answer_too_large", test_auth_answer_too_large ());
	test_auth_case ("answer_grows", test_auth_answer_grows ());
	test_auth_case ("action", test_auth_action ());
	test_auth_case ("role", test_auth_role ());
	test_auth_case ("service", test_auth_service ());
	test_auth_case ("service_without_id", test_auth_service_without_id (http_cerver));
	test_auth_case ("management", test_auth_management ());
	test_auth_case ("single", test_auth_single ());
	test_auth_case ("single_injection", test_auth_single_injection ());
	test_auth_case ("unsupported_types", test_auth_unsupported_types ());
	test_auth_case ("without_service", test_auth_without_service (http_cerver));
	test_auth_case ("unreachable", test_auth_unreachable (http_cerver));
	test_auth_case ("slow", test_auth_slow ());
	test_auth_case ("concurrent", test_auth_concurrent ());

	http_cerver_set_custom_data (http_cerver, NULL);

	test_auth_cerver_stop (&service_cerver);

	test_auth_service_set (NULL);

	(void) printf ("Done!\n");

	return 0;

}
