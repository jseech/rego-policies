package example

import rego.v1

default allow := false

violation contains input.user.role if {
	input.user.role != "admin"
}

allow if {
	count(violation) == 0
}
