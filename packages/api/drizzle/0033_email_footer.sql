ALTER TABLE "email_branding" ADD COLUMN "footer_mode" varchar(8) DEFAULT 'default' NOT NULL;--> statement-breakpoint
ALTER TABLE "email_branding" ADD COLUMN "footer_html" text;--> statement-breakpoint
ALTER TABLE "email_branding" ADD COLUMN "button_color" varchar(7);--> statement-breakpoint
UPDATE "email_branding" SET "button_color" = "header_color" WHERE "header_color" IS NOT NULL;
