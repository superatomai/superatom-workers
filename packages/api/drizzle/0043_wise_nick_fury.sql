ALTER TABLE "roles" ADD COLUMN "scope" varchar(16) DEFAULT 'org' NOT NULL;--> statement-breakpoint
-- Data: super admin as a platform role, and every super admin pointing at it.
INSERT INTO "roles" ("key", "name", "description", "is_system", "scope")
SELECT 'super_admin', 'Super admin', 'Super admin with access to every organization and its data', true, 'platform'
WHERE NOT EXISTS (SELECT 1 FROM "roles" WHERE "org_id" IS NULL AND "key" = 'super_admin');--> statement-breakpoint
UPDATE "users" SET "role_id" = (SELECT "id" FROM "roles" WHERE "org_id" IS NULL AND "key" = 'super_admin')
WHERE "role" = 'super_admin';
