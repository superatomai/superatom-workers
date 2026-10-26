CREATE TABLE "email_attachments" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"campaign_id" uuid NOT NULL,
	"file_name" varchar(255) NOT NULL,
	"content_type" varchar(255),
	"size_bytes" integer NOT NULL,
	"r2_key" text NOT NULL,
	"status" varchar(16) DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "email_attachments_status_check" CHECK ("email_attachments"."status" in ('pending', 'ready'))
);
--> statement-breakpoint
ALTER TABLE "email_attachments" ADD CONSTRAINT "email_attachments_campaign_id_email_campaigns_id_fk" FOREIGN KEY ("campaign_id") REFERENCES "public"."email_campaigns"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "email_attachments_campaign_idx" ON "email_attachments" USING btree ("campaign_id");