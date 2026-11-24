CREATE TABLE "object_denials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"object_id" uuid NOT NULL,
	"principal_type" varchar(16) NOT NULL,
	"principal_id" uuid NOT NULL,
	"action" varchar(32) NOT NULL,
	"reason" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "object_role_actions" (
	"role_id" uuid NOT NULL,
	"action" varchar(32) NOT NULL,
	CONSTRAINT "object_role_actions_role_id_action_pk" PRIMARY KEY("role_id","action")
);
--> statement-breakpoint
CREATE TABLE "object_roles" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid,
	"key" varchar(64) NOT NULL,
	"name" varchar(255) NOT NULL,
	"description" text,
	"object_type" varchar(32),
	"is_system" boolean DEFAULT false NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "object_roles_scope_chk" CHECK (("object_roles"."is_system" AND "object_roles"."org_id" IS NULL) OR (NOT "object_roles"."is_system" AND "object_roles"."org_id" IS NOT NULL))
);
--> statement-breakpoint
ALTER TABLE "object_grants" ADD COLUMN "object_role_id" uuid;--> statement-breakpoint
ALTER TABLE "object_denials" ADD CONSTRAINT "object_denials_object_id_objects_id_fk" FOREIGN KEY ("object_id") REFERENCES "public"."objects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "object_denials" ADD CONSTRAINT "object_denials_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "object_role_actions" ADD CONSTRAINT "object_role_actions_role_id_object_roles_id_fk" FOREIGN KEY ("role_id") REFERENCES "public"."object_roles"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "object_roles" ADD CONSTRAINT "object_roles_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "object_roles" ADD CONSTRAINT "object_roles_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "object_denials_rule_idx" ON "object_denials" USING btree ("object_id","principal_type","principal_id","action");--> statement-breakpoint
CREATE INDEX "object_denials_lookup_idx" ON "object_denials" USING btree ("principal_type","principal_id");--> statement-breakpoint
CREATE UNIQUE INDEX "object_roles_org_key_idx" ON "object_roles" USING btree ("org_id","key");--> statement-breakpoint
CREATE UNIQUE INDEX "object_roles_builtin_key_idx" ON "object_roles" USING btree ("key") WHERE "object_roles"."org_id" IS NULL;--> statement-breakpoint
ALTER TABLE "object_grants" ADD CONSTRAINT "object_grants_object_role_id_object_roles_id_fk" FOREIGN KEY ("object_role_id") REFERENCES "public"."object_roles"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "object_grants_role_idx" ON "object_grants" USING btree ("object_role_id");