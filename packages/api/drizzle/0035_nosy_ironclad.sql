CREATE TYPE "public"."access_source" AS ENUM('token', 'stored', 'none');--> statement-breakpoint
CREATE TABLE "access_configs" (
	"user_id" uuid NOT NULL,
	"access_hash" varchar(64) NOT NULL,
	"org_id" uuid,
	"config" jsonb NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "access_configs_user_id_access_hash_pk" PRIMARY KEY("user_id","access_hash")
);
--> statement-breakpoint
ALTER TABLE "chat_analytics" ADD COLUMN "access_source" "access_source";--> statement-breakpoint
ALTER TABLE "chat_analytics" ADD COLUMN "access_hash" varchar(64);--> statement-breakpoint
ALTER TABLE "chat_analytics" ADD COLUMN "access_applied" jsonb;--> statement-breakpoint
ALTER TABLE "access_configs" ADD CONSTRAINT "access_configs_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_configs" ADD CONSTRAINT "access_configs_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "access_configs_access_hash_idx" ON "access_configs" USING btree ("access_hash");--> statement-breakpoint
CREATE INDEX "access_configs_org_id_idx" ON "access_configs" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "chat_analytics_access_hash_idx" ON "chat_analytics" USING btree ("access_hash");