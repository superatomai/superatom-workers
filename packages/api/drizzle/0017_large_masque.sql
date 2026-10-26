CREATE TABLE "project_installs" (
	"project_id" uuid NOT NULL,
	"install_name" varchar(255) NOT NULL,
	"release_version" varchar(255),
	"image_digest" varchar(71),
	"target_version" varchar(255),
	"target_set_by" varchar(255),
	"target_set_at" timestamp with time zone,
	"last_error" text,
	"last_seen_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_installs_project_id_install_name_pk" PRIMARY KEY("project_id","install_name")
);
--> statement-breakpoint
ALTER TABLE "project_installs" ADD CONSTRAINT "project_installs_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;