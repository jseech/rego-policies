package example

import rego.v1

default allow := false

allowed_roles := ["admin", "user"]

allow if {
	input.user.role in allowed_roles
}
