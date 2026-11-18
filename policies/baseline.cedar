// Baseline: what every agent gets, and what no agent ever gets.
// @reason text is shown to the agent when a call is denied, so the model
// can understand why and pick another path.

@id("read-tools-for-every-agent")
@reason("Read-only tools are open to every registered agent.")
permit (principal is Agent, action in Action::"read", resource);

@id("no-destructive-tools")
@reason("Destructive tools such as delete_namespace never go through the gate. A human runs them directly.")
forbid (principal, action in Action::"destructive", resource);
