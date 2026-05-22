package deploypolicy

import rego.v1

default allow := false

allow if {
	valid_branch
	valid_event
	valid_environment
	valid_prod_controls
}

valid_branch if {
	input.branch == data.deploy.allowed_release_branch
}

valid_event if {
	input.event_name in data.deploy.allowed_events
}

valid_environment if {
	input.target_environment in data.deploy.allowed_envs
}

valid_prod_controls if {
	input.target_environment != "prod"
}

valid_prod_controls if {
	input.target_environment == "prod"
	input.release_approved == "true"
	input.actor in data.deploy.authorized_prod_actors
}

deny contains msg if {
	not valid_branch
	msg := sprintf(
		"Deploy denied: branch '%s' is not allowed. Only '%s' can be deployed.",
		[input.branch, data.deploy.allowed_release_branch],
	)
}

deny contains msg if {
	not valid_event
	msg := sprintf(
		"Deploy denied: event '%s' is not allowed. Allowed events: %v.",
		[input.event_name, data.deploy.allowed_events],
	)
}

deny contains msg if {
	not valid_environment
	msg := sprintf(
		"Deploy denied: target environment '%s' is invalid. Allowed environments: %v.",
		[input.target_environment, data.deploy.allowed_envs],
	)
}

deny contains msg if {
	input.target_environment == "prod"
	input.release_approved != "true"
	msg := "Deploy denied: production requires explicit release approval."
}

deny contains msg if {
	input.target_environment == "prod"
	not input.actor in data.deploy.authorized_prod_actors
	msg := sprintf(
		"Deploy denied: actor '%s' is not authorized for production deployment.",
		[input.actor],
	)
}