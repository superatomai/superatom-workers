ALTER TABLE "email_branding" ADD COLUMN "resend_key_enc" text;--> statement-breakpoint
ALTER TABLE "email_branding" ADD COLUMN "resend_key_last4" varchar(4);--> statement-breakpoint
ALTER TABLE "email_branding" ADD COLUMN "sender_domains" jsonb;