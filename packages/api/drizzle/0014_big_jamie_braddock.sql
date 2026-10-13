CREATE TABLE "graph_changes" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"entity" varchar(8) NOT NULL,
	"entity_id" integer NOT NULL,
	"action" varchar(8) NOT NULL,
	"via" varchar(8) NOT NULL,
	"change_request_id" integer,
	"before" jsonb,
	"after" jsonb,
	"changed_by" uuid,
	"changed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "graph_changes" ADD CONSTRAINT "graph_changes_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_changes" ADD CONSTRAINT "graph_changes_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_changes" ADD CONSTRAINT "graph_changes_change_request_id_graph_change_requests_id_fk" FOREIGN KEY ("change_request_id") REFERENCES "public"."graph_change_requests"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_changes" ADD CONSTRAINT "graph_changes_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "graph_changes_item_idx" ON "graph_changes" USING btree ("entity","entity_id","changed_at");--> statement-breakpoint
CREATE INDEX "graph_changes_project_idx" ON "graph_changes" USING btree ("project_id","changed_at");