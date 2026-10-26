CREATE TABLE "project_programs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"version" varchar(255) NOT NULL,
	"name" varchar(255) NOT NULL,
	"hash" varchar(64) NOT NULL,
	"commit" varchar(40) NOT NULL,
	"published_by" varchar(255),
	"notes" text,
	"published_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "pinned_program_version" varchar(255);--> statement-breakpoint
ALTER TABLE "project_programs" ADD CONSTRAINT "project_programs_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "project_programs_version_idx" ON "project_programs" USING btree ("project_id","version");--> statement-breakpoint
CREATE INDEX "project_programs_latest_idx" ON "project_programs" USING btree ("project_id","published_at");