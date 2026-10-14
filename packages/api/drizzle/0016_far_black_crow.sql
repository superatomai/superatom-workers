CREATE TABLE "project_releases" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"project_id" uuid NOT NULL,
	"version" varchar(255) NOT NULL,
	"branch" varchar(255) NOT NULL,
	"commit" varchar(40) NOT NULL,
	"image" varchar(512) NOT NULL,
	"image_digest" varchar(71) NOT NULL,
	"bundle_sha256" varchar(64) NOT NULL,
	"engine_version" varchar(32),
	"compose_version" varchar(32),
	"migrations" integer,
	"published_by" varchar(255),
	"published_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "code_branch" varchar(255) DEFAULT 'main' NOT NULL;--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "pinned_version" varchar(255);--> statement-breakpoint
ALTER TABLE "project_releases" ADD CONSTRAINT "project_releases_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "project_releases_version_idx" ON "project_releases" USING btree ("project_id","version");--> statement-breakpoint
CREATE INDEX "project_releases_latest_idx" ON "project_releases" USING btree ("project_id","published_at");