// Guardrails. In Cedar a forbid always beats a permit, so these hold no
// matter which permit matched.

@id("never-scale-prod-to-zero")
@reason("Scaling a prod deployment to zero replicas takes the service down.")
forbid (principal, action == Action::"scale_deployment", resource)
when { context.args.namespace like "prod-*" && context.args.replicas < 1 };

@id("replica-cap")
@reason("No deployment may be scaled above 20 replicas through the gate.")
forbid (principal, action == Action::"scale_deployment", resource)
when { context.args.replicas > 20 };

@id("weekend-prod-freeze")
@reason("Prod is frozen for changes on Saturdays and Sundays; a human makes any weekend change.")
forbid (principal, action in Action::"write", resource)
when {
  context.args.namespace like "prod-*" &&
  (context.clock.weekday == 0 || context.clock.weekday == 6)
};
