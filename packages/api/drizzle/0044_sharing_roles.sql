-- Custom SQL migration file, put your code below! --
-- Sharing roles are now Viewer, Editor and Manager (view, edit, manage), the same
-- on apps, projects and data sources (lib/objects.ts). Commenter is gone: there
-- is no commenting, so whoever was a commenter becomes a Viewer.
UPDATE "object_grants" SET "level" = 'view' WHERE "level" = 'comment';
