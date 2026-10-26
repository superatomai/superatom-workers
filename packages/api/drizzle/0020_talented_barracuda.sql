CREATE TYPE "public"."checklist_ran_by" AS ENUM('agent', 'human');--> statement-breakpoint
CREATE TYPE "public"."checklist_run_status" AS ENUM('pass', 'fail', 'partial');--> statement-breakpoint
CREATE TABLE "checklist_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"checklist_id" varchar(100) NOT NULL,
	"scope" jsonb NOT NULL,
	"org_id" uuid,
	"project_id" uuid,
	"status" "checklist_run_status" NOT NULL,
	"ran_by" "checklist_ran_by" NOT NULL,
	"summary" text,
	"findings_count" integer DEFAULT 0 NOT NULL,
	"failed_count" integer DEFAULT 0 NOT NULL,
	"version" varchar(255),
	"r2_key" varchar(512) NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"finished_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "checklist_runs" ADD CONSTRAINT "checklist_runs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "checklist_runs" ADD CONSTRAINT "checklist_runs_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "checklist_runs_checklist_idx" ON "checklist_runs" USING btree ("checklist_id","created_at");--> statement-breakpoint
CREATE INDEX "checklist_runs_project_idx" ON "checklist_runs" USING btree ("project_id","created_at");--> statement-breakpoint
CREATE INDEX "checklist_runs_org_idx" ON "checklist_runs" USING btree ("org_id","created_at");