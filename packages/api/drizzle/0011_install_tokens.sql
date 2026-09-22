CREATE TABLE "install_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"token_hash" varchar(64) NOT NULL,
	"project_id" uuid NOT NULL,
	"org_id" uuid NOT NULL,
	"install_name" varchar(63) NOT NULL,
	"llm_budget_cents" integer DEFAULT 0 NOT NULL,
	"llm_client_id" varchar(100),
	"created_by" varchar(255) NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"redeemed_at" timestamp with time zone,
	"redeemed_ip" varchar(64),
	"redeemed_commit" varchar(40),
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "install_tokens" ADD CONSTRAINT "install_tokens_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "install_tokens_hash_idx" ON "install_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "install_tokens_project_idx" ON "install_tokens" USING btree ("project_id");