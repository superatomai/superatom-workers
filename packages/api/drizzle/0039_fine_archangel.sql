CREATE TABLE "role_changes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"changed_by" uuid,
	"from_role" varchar(64),
	"to_role" varchar(64),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "role_permissions" (
	"role_id" uuid NOT NULL,
	"permission" varchar(64) NOT NULL,
	CONSTRAINT "role_permissions_role_id_permission_pk" PRIMARY KEY("role_id","permission")
);
--> statement-breakpoint
CREATE TABLE "roles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid,
	"key" varchar(64) NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"is_system" boolean DEFAULT false NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "role_id" uuid;--> statement-breakpoint
ALTER TABLE "role_changes" ADD CONSTRAINT "role_changes_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_changes" ADD CONSTRAINT "role_changes_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_changes" ADD CONSTRAINT "role_changes_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "role_changes_org_idx" ON "role_changes" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "roles_org_key_idx" ON "roles" USING btree ("org_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "roles_builtin_key_idx" ON "roles" USING btree ("key") WHERE "roles"."org_id" IS NULL;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_role_id_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."roles"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
-- Data, written by hand (drizzle-kit generates schema only). See ROLES-IMPLEMENTATION.md.
-- The built-in roles. Their permissions live in code (lib/permissions.ts BUILT_IN_ROLES).
INSERT INTO "roles" ("org_id", "key", "name", "description", "is_system") VALUES
  (NULL, 'owner',  'Owner',  'Full control of the organization, including its admins and roles', true),
  (NULL, 'admin',  'Admin',  'Manages members, projects, sources and apps; cannot manage admins', true),
  (NULL, 'member', 'Member', 'Uses the apps given to them', true);--> statement-breakpoint
-- Every existing user gets the built-in role matching their users.role.
UPDATE "users" SET "role_id" = (SELECT "id" FROM "roles" WHERE "org_id" IS NULL AND "key" = 'admin')
  WHERE "role" = 'org_admin';--> statement-breakpoint
UPDATE "users" SET "role_id" = (SELECT "id" FROM "roles" WHERE "org_id" IS NULL AND "key" = 'member')
  WHERE "role" = 'member';--> statement-breakpoint
-- Each organization's first Owner: its earliest active admin.
UPDATE "users" SET "role_id" = (SELECT "id" FROM "roles" WHERE "org_id" IS NULL AND "key" = 'owner')
  WHERE "id" IN (
    SELECT DISTINCT ON ("org_id") "id" FROM "users"
    WHERE "role" = 'org_admin' AND "is_active" AND "org_id" IS NOT NULL
    ORDER BY "org_id", "created_at"
  );