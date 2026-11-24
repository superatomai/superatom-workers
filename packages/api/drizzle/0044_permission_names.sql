-- Custom SQL migration file, put your code below! --
-- Permissions renamed to resource.action (lib/permissions.ts). Each old name a
-- custom role holds becomes the new names that mean the same; the powers now
-- fixed to the built-in roles (members, admins, roles, data access, org
-- settings) are removed from every custom role. Built-in roles have no rows here.
INSERT INTO "role_permissions" ("role_id", "permission")
SELECT rp."role_id", m."new"
FROM "role_permissions" rp
JOIN (VALUES
  ('platform.access', 'platform.access'),
  ('projects.create', 'project.view'), ('projects.create', 'project.create'),
  ('projects.edit', 'project.view'), ('projects.edit', 'project.edit'),
  ('projects.delete', 'project.view'), ('projects.delete', 'project.delete'),
  ('sources.manage', 'source.view'), ('sources.manage', 'source.create'), ('sources.manage', 'source.edit'), ('sources.manage', 'source.delete'),
  ('dashboards.create', 'dashboard.view'), ('dashboards.create', 'dashboard.create'),
  ('reports.create', 'report.view'), ('reports.create', 'report.create'),
  ('chat_agents.create', 'agent.view'), ('chat_agents.create', 'agent.create'),
  ('apps.create', 'app.view'), ('apps.create', 'app.create'),
  ('graph.manage', 'model.view'), ('graph.manage', 'model.edit'),
  ('concepts.create', 'model.view'), ('concepts.create', 'model.edit'),
  ('intents.create', 'model.view'), ('intents.create', 'model.edit'),
  ('design.edit', 'design.view'), ('design.edit', 'design.edit'),
  ('feedback.triage', 'feedback.view'), ('feedback.triage', 'feedback.triage'),
  ('analytics.view', 'analytics.view'), ('analytics.view', 'analytics.export'),
  ('emails.manage', 'email.view'), ('emails.manage', 'email.send'),
  ('programs.publish', 'program.view'), ('programs.publish', 'program.publish'),
  ('updates.manage', 'update.view'), ('updates.manage', 'update.apply')
) AS m("old", "new") ON m."old" = rp."permission"
ON CONFLICT DO NOTHING;
--> statement-breakpoint
DELETE FROM "role_permissions"
WHERE "permission" IN (
  'projects.create', 'projects.edit', 'projects.delete', 'sources.manage',
  'dashboards.create', 'reports.create', 'chat_agents.create', 'apps.create',
  'graph.manage', 'concepts.create', 'intents.create', 'emails.manage',
  'programs.publish', 'updates.manage',
  'members.manage', 'access.manage', 'admins.manage', 'roles.manage', 'org.edit', 'org.settings'
);
