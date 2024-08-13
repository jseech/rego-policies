# policy.rego
package envoy.authz

import rego.v1

import input.attributes.request.http as http_request

default allow := false

allow if {
	action_allowed
}

action_allowed if {
	http_request.method == "GET"
	token.payload.role == "guest"
	glob.match("/people", ["/"], http_request.path)
}

action_allowed if {
	http_request.method == "GET"
	token.payload.role == "admin"
	glob.match("/people", ["/"], http_request.path)
}

action_allowed if {
	http_request.method == "POST"
	token.payload.role == "admin"
	glob.match("/people", ["/"], http_request.path)
	lower(input.parsed_body.firstname) != base64url.decode(token.payload.sub)
}
