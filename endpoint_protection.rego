# policy.rego
package envoy.authz
import rego.v1

default allow := false

allow if {
	is_action_allowed
    is_allowed_path
    is_admin
}

allowed_actions := ["POST", "GET"]

is_action_allowed if input.attributes.request.http.method in allowed_actions
is_allowed_path if {
    glob.match("/app*", ["."], input.attributes.request.http.path)
}
is_admin if claims.role == "admin"






claims := payload if {
	# Verify the signature on the Bearer token. In this example the secret is
	# hardcoded into the policy however it could also be loaded via data or
	# an environment variable. Environment variables can be accessed using
	# the `opa.runtime()` built-in function.
# 	io.jwt.verify_hs256(bearer_token, "B41BD5F462719C6D6118E673A2389")

	# This statement invokes the built-in function `io.jwt.decode` passing the
	# parsed bearer_token as a parameter. The `io.jwt.decode` function returns an
	# array:
	#
	#	[header, payload, signature]
	#
	# In Rego, you can pattern match values using the `=` and `:=` operators. This
	# example pattern matches on the result to obtain the JWT payload.
	[_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.attributes.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
