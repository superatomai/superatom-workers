CREATE TABLE "email_branding" (
	"org_id" uuid PRIMARY KEY NOT NULL,
	"header_color" varchar(7),
	"logo_url" text,
	"show_superatom_logo" boolean DEFAULT true NOT NULL,
	"sender_name" varchar(100),
	"sender_email" varchar(255),
	"why_text" varchar(500),
	"footer_note" varchar(300),
	"updated_by" uuid,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD COLUMN "body_format" varchar(8) DEFAULT 'markdown' NOT NULL;--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD COLUMN "title" varchar(200);--> statement-breakpoint
ALTER TABLE "email_branding" ADD CONSTRAINT "email_branding_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_branding" ADD CONSTRAINT "email_branding_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD CONSTRAINT "email_campaigns_body_format_check" CHECK ("email_campaigns"."body_format" in ('markdown', 'html'));