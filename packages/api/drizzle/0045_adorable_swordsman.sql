CREATE TABLE "access_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"actor_id" uuid,
	"action" varchar(64) NOT NULL,
	"target_type" varchar(16) NOT NULL,
	"target_id" varchar(255) NOT NULL,
	"subject_id" uuid,
	"before" jsonb,
	"after" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "access_log" ADD CONSTRAINT "access_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_log" ADD CONSTRAINT "access_log_actor_id_users_id_fk" FOREIGN KEY ("actor_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_log" ADD CONSTRAINT "access_log_subject_id_users_id_fk" FOREIGN KEY ("subject_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "access_log_org_idx" ON "access_log" USING btree ("org_id","created_at");--> statement-breakpoint
CREATE INDEX "access_log_target_idx" ON "access_log" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE INDEX "access_log_subject_idx" ON "access_log" USING btree ("subject_id");--> statement-breakpoint
CREATE INDEX "access_log_actor_idx" ON "access_log" USING btree ("actor_id");--> statement-breakpoint
-- Data: the role history so far, moved into the access log (role_changes is dropped next).
INSERT INTO "access_log" ("org_id", "actor_id", "action", "target_type", "target_id", "subject_id", "before", "after", "created_at")
SELECT "org_id", "changed_by",
  CASE WHEN "from_role" IS NULL THEN 'member.added' ELSE 'member.role_changed' END,
  'user', "user_id"::text, "user_id",
  CASE WHEN "from_role" IS NULL THEN NULL ELSE jsonb_build_object('role', "from_role") END,
  jsonb_build_object('role', "to_role"),
  "created_at"
FROM "role_changes";