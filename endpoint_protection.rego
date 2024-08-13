# policy.rego
package envoy.authz

import rego.v1

import input.attributes.request.http as http_request

default allow := false

allow if {
	is_token_valid
	action_allowed
}

is_token_valid if {
	token.valid
	now := time.now_ns() / 1000000000
	token.payload.nbf <= now
	now < token.payload.exp
}

action_allowed if {
	http_request.method == "GET"
	token.payload.role == "admin"
	glob.match("/app", ["/"], http_request.path)
}

token := {"valid": valid, "payload": payload} if {
	[_, encoded] := split(http_request.headers.authorization, " ")
	[valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret"})
}
