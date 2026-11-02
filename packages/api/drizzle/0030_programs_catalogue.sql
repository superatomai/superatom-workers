ALTER TABLE "project_programs" ADD COLUMN "creator_id" uuid;--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "manifest" jsonb;--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "status" varchar(16) DEFAULT 'pending' NOT NULL;--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "key" varchar(512);--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "source_key" varchar(512);--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "source_hash" varchar(64);--> statement-breakpoint
ALTER TABLE "project_programs" ADD COLUMN "source_bytes" integer;--> statement-breakpoint
ALTER TABLE "project_programs" ADD CONSTRAINT "project_programs_creator_id_users_id_fk" FOREIGN KEY ("creator_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;