ALTER TABLE "email_campaigns" ADD COLUMN "schedule" jsonb;--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD COLUMN "parent_id" uuid;--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD CONSTRAINT "email_campaigns_parent_id_email_campaigns_id_fk" FOREIGN KEY ("parent_id") REFERENCES "public"."email_campaigns"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "email_campaigns_parent_idx" ON "email_campaigns" USING btree ("parent_id","created_at");