CREATE TABLE "email_api_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"name" varchar(100) NOT NULL,
	"key_prefix" varchar(20) NOT NULL,
	"key_hash" varchar(64) NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD COLUMN "source" varchar(16) DEFAULT 'ui' NOT NULL;--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD COLUMN "api_key_id" uuid;--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD COLUMN "idempotency_key" varchar(255);--> statement-breakpoint
ALTER TABLE "email_sends" ADD COLUMN "subject" varchar(255);--> statement-breakpoint
ALTER TABLE "email_api_keys" ADD CONSTRAINT "email_api_keys_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_api_keys" ADD CONSTRAINT "email_api_keys_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "email_api_keys_hash_idx" ON "email_api_keys" USING btree ("key_hash");--> statement-breakpoint
CREATE INDEX "email_api_keys_org_idx" ON "email_api_keys" USING btree ("org_id","created_at");--> statement-breakpoint
ALTER TABLE "email_campaigns" ADD CONSTRAINT "email_campaigns_api_key_id_email_api_keys_id_fk" FOREIGN KEY ("api_key_id") REFERENCES "public"."email_api_keys"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "email_campaigns_api_idempotency_idx" ON "email_campaigns" USING btree ("api_key_id","idempotency_key");