INSERT INTO object_roles (key, name, description, is_system)
VALUES
  ('view', 'Viewer', 'Can view an object', true),
  ('edit', 'Editor', 'Can view, create, edit and delete', true),
  ('manage', 'Manager', 'Can view, create, edit, delete, share and disable', true)
ON CONFLICT DO NOTHING;
--> statement-breakpoint

INSERT INTO object_role_actions (role_id, action)
SELECT r.id, a.action
FROM object_roles AS r
JOIN (VALUES
  ('view', 'view'),
  ('edit', 'view'), ('edit', 'create'), ('edit', 'edit'), ('edit', 'delete'),
  ('manage', 'view'), ('manage', 'create'), ('manage', 'edit'), ('manage', 'delete'),
  ('manage', 'share'), ('manage', 'disable')
) AS a(role_key, action) ON a.role_key = r.key
WHERE r.org_id IS NULL AND r.is_system = true
ON CONFLICT DO NOTHING;
--> statement-breakpoint

UPDATE object_grants AS g
SET object_role_id = r.id
FROM object_roles AS r
WHERE g.object_role_id IS NULL
  AND r.org_id IS NULL
  AND r.is_system = true
  AND r.key = CASE g.level
    WHEN 'comment' THEN 'view'
    WHEN 'admin' THEN 'manage'
    ELSE g.level
  END;
