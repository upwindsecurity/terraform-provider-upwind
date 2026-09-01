# All published threat agent skills.
data "upwind_threat_skills" "all" {}

output "available_skills" {
  value = [for s in data.upwind_threat_skills.all.skills : s.name]
}
