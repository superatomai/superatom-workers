CREATE TABLE "email_subscription_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"category" varchar(32) NOT NULL,
	"subscribed" boolean NOT NULL,
	"source" varchar(16) NOT NULL,
	"changed_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "email_unsubscribes" ADD COLUMN "source" varchar(16) DEFAULT 'self' NOT NULL;--> statement-breakpoint
ALTER TABLE "email_unsubscribes" ADD COLUMN "changed_by" uuid;--> statement-breakpoint
ALTER TABLE "email_subscription_events" ADD CONSTRAINT "email_subscription_events_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_subscription_events" ADD CONSTRAINT "email_subscription_events_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "email_subscription_events_user_idx" ON "email_subscription_events" USING btree ("user_id","created_at");--> statement-breakpoint
ALTER TABLE "email_unsubscribes" ADD CONSTRAINT "email_unsubscribes_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;