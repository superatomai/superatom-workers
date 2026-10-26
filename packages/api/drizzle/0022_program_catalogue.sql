DROP INDEX "project_programs_version_idx";--> statement-breakpoint
DROP INDEX "project_programs_latest_idx";--> statement-breakpoint
ALTER TABLE "project_programs" ALTER COLUMN "published_at" DROP DEFAULT;--> statement-breakpoint
ALTER TABLE "project_programs" ALTER COLUMN "published_at" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "bytes" integer NOT NULL;--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "built_by" varchar(255);--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "uploaded_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "program_pins" jsonb DEFAULT '{}'::jsonb NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "project_programs_hash_idx" ON "project_programs" USING btree ("project_id","hash");--> statement-breakpoint
CREATE UNIQUE INDEX "project_programs_version_idx" ON "project_programs" USING btree ("project_id","name","version");--> statement-breakpoint
CREATE INDEX "project_programs_latest_idx" ON "project_programs" USING btree ("project_id","name","published_at");--> statement-breakpoint
ALTER TABLE "projects" DROP COLUMN "pinned_program_version";