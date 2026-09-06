# One skill by name. Useful as a precondition: fail the plan if something the
# automation depends on is no longer published.
data "upwind_threat_skill" "policy_manager" {
  name = "threat-policy-manager"
}

check "skill_is_available" {
  assert {
    condition     = data.upwind_threat_skill.policy_manager.version != ""
    error_message = "The threat-policy-manager skill is not published in this organization."
  }
}
