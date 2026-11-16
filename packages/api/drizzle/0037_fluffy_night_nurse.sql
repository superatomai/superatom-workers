CREATE TYPE "public"."feedback_resolution" AS ENUM('open', 'resolved', 'later_scope', 'not_an_issue', 'duplicate', 'needs_info');--> statement-breakpoint
ALTER TABLE "answer_feedback" ADD COLUMN "resolution" "feedback_resolution" DEFAULT 'open' NOT NULL;--> statement-breakpoint
ALTER TABLE "answer_feedback" ADD COLUMN "resolution_note" text;--> statement-breakpoint
ALTER TABLE "answer_feedback" ADD COLUMN "resolved_by" varchar(255);--> statement-breakpoint
ALTER TABLE "answer_feedback" ADD COLUMN "resolved_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "answer_feedback_resolution_idx" ON "answer_feedback" USING btree ("resolution");