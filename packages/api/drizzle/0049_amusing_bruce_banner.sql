CREATE TABLE "user_permission_limits" (
	"user_id" uuid NOT NULL,
	"permission" varchar(64) NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_permission_limits_user_id_permission_pk" PRIMARY KEY("user_id","permission")
);
--> statement-breakpoint
ALTER TABLE "user_permission_limits" ADD CONSTRAINT "user_permission_limits_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_permission_limits" ADD CONSTRAINT "user_permission_limits_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;