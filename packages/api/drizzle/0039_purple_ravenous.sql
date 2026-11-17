CREATE TABLE "object_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"object_id" uuid NOT NULL,
	"principal_type" varchar(16) NOT NULL,
	"principal_id" uuid NOT NULL,
	"level" varchar(16) NOT NULL,
	"granted_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "objects" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid,
	"type" varchar(32) NOT NULL,
	"ref_id" varchar(255) NOT NULL,
	"owner_id" uuid,
	"created_by" uuid,
	"status" varchar(16) DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "object_grants" ADD CONSTRAINT "object_grants_object_id_objects_id_fk" FOREIGN KEY ("object_id") REFERENCES "public"."objects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "object_grants" ADD CONSTRAINT "object_grants_granted_by_users_id_fk" FOREIGN KEY ("granted_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "objects" ADD CONSTRAINT "objects_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "objects" ADD CONSTRAINT "objects_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "objects" ADD CONSTRAINT "objects_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "objects" ADD CONSTRAINT "objects_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "object_grants_principal_idx" ON "object_grants" USING btree ("object_id","principal_type","principal_id");--> statement-breakpoint
CREATE INDEX "object_grants_lookup_idx" ON "object_grants" USING btree ("principal_type","principal_id");--> statement-breakpoint
CREATE UNIQUE INDEX "objects_type_ref_idx" ON "objects" USING btree ("type","ref_id");--> statement-breakpoint
CREATE INDEX "objects_org_idx" ON "objects" USING btree ("org_id");--> statement-breakpoint
-- Data, written by hand (drizzle-kit generates schema only). See ROLES-IMPLEMENTATION.md, step 2.
-- Every app becomes an object, owned by whoever created it.
INSERT INTO "objects" ("org_id", "project_id", "type", "ref_id", "owner_id", "created_by")
SELECT p."org_id", a."project_id", a."type"::text, a."id"::text, a."created_by", a."created_by"
FROM "apps" a JOIN "projects" p ON p."id" = a."project_id"
ON CONFLICT ("type", "ref_id") DO NOTHING;--> statement-breakpoint
-- Every app permission becomes a grant to that user; admin becomes manage.
INSERT INTO "object_grants" ("object_id", "principal_type", "principal_id", "level", "granted_by", "created_at")
SELECT o."id", 'user', ap."user_id",
  CASE ap."permission" WHEN 'admin' THEN 'manage' ELSE ap."permission"::text END,
  ap."granted_by", ap."created_at"
FROM "app_permissions" ap
JOIN "objects" o ON o."ref_id" = ap."app_id"::text AND o."type" IN ('dashboard', 'chat_agent', 'report', 'app')
ON CONFLICT DO NOTHING;