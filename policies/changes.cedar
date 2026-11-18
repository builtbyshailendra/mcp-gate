// Who may change things. Namespaces starting with "prod-" are production.

@id("sre-changes-outside-prod")
@reason("SRE agents may restart and scale deployments outside prod.")
permit (principal in Team::"sre", action in Action::"write", resource)
when { !(context.args.namespace like "prod-*") };

@id("prod-changes-need-on-call")
@reason("In prod, only an SRE agent marked on-call may restart or scale.")
permit (principal in Team::"sre", action in Action::"write", resource)
when { context.args.namespace like "prod-*" && principal.on_call };
