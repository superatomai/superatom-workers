CREATE TYPE "public"."concept_type" AS ENUM('global', 'user', 'group');--> statement-breakpoint
CREATE TABLE "concepts" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"owner_id" uuid,
	"name" varchar(64) NOT NULL,
	"body" text NOT NULL,
	"kind" varchar(24) DEFAULT 'definition' NOT NULL,
	"type" "concept_type" DEFAULT 'global' NOT NULL,
	"requires" text[] DEFAULT '{}'::text[] NOT NULL,
	"returns" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"aliases" text[] DEFAULT '{}'::text[] NOT NULL,
	"description" varchar(240),
	"origin" varchar(24),
	"source_id" varchar(100),
	"origin_ref" varchar(100),
	"supersedes" integer,
	"verified" boolean DEFAULT true NOT NULL,
	"edit_version" integer DEFAULT 1 NOT NULL,
	"created_by" uuid,
	"updated_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "graph_change_requests" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"entity" varchar(8) NOT NULL,
	"entity_id" integer,
	"action" varchar(8) NOT NULL,
	"base_edit_version" integer,
	"proposed" jsonb NOT NULL,
	"author_id" uuid,
	"source" varchar(12) NOT NULL,
	"origin_ref" varchar(100),
	"status" varchar(10) DEFAULT 'open' NOT NULL,
	"reviewed_by" uuid,
	"reviewed_at" timestamp with time zone,
	"review_comment" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "graph_domain_terms" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"node_id" integer NOT NULL,
	"term" varchar(64) NOT NULL,
	"weight" integer DEFAULT 1 NOT NULL
);
--> statement-breakpoint
CREATE TABLE "graph_edges" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"parent_id" integer NOT NULL,
	"child_node_id" integer,
	"child_concept_id" integer,
	"role" varchar(12) NOT NULL,
	"position" integer NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "graph_edges_one_child" CHECK (("graph_edges"."child_node_id" IS NULL) <> ("graph_edges"."child_concept_id" IS NULL)),
	CONSTRAINT "graph_edges_no_self_link" CHECK ("graph_edges"."child_node_id" IS NULL OR "graph_edges"."child_node_id" <> "graph_edges"."parent_id")
);
--> statement-breakpoint
CREATE TABLE "graph_engine_state" (
	"project_id" uuid NOT NULL,
	"engine_id" varchar(64) NOT NULL,
	"org_id" uuid NOT NULL,
	"applied_release_id" integer,
	"applied_root_hash" varchar(64),
	"status" varchar(12) NOT NULL,
	"last_error" text,
	"last_seen_at" timestamp with time zone,
	"last_ack_at" timestamp with time zone,
	CONSTRAINT "graph_engine_state_project_id_engine_id_pk" PRIMARY KEY("project_id","engine_id")
);
--> statement-breakpoint
CREATE TABLE "graph_nodes" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"owner_id" uuid,
	"kind" varchar(16) NOT NULL,
	"name" varchar(96) NOT NULL,
	"title" varchar(160),
	"body" text NOT NULL,
	"meta" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"hash" varchar(64) NOT NULL,
	"status" varchar(12) DEFAULT 'draft' NOT NULL,
	"origin" varchar(24),
	"edit_version" integer DEFAULT 1 NOT NULL,
	"created_by" uuid,
	"updated_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "graph_release_events" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"event_seq" bigint NOT NULL,
	"action" varchar(12) NOT NULL,
	"from_release_id" integer,
	"to_release_id" integer NOT NULL,
	"reason" text,
	"actor" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "graph_releases" (
	"id" serial PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"seq" integer NOT NULL,
	"items" jsonb NOT NULL,
	"root_hash" varchar(64) NOT NULL,
	"parent_release_id" integer,
	"notes" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "graph_revisions" (
	"entity" varchar(8) NOT NULL,
	"entity_id" integer NOT NULL,
	"rev" integer NOT NULL,
	"org_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"content" jsonb NOT NULL,
	"hash" varchar(64) NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "graph_revisions_entity_entity_id_rev_pk" PRIMARY KEY("entity","entity_id","rev")
);
--> statement-breakpoint
ALTER TABLE "concepts" ADD CONSTRAINT "concepts_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "concepts" ADD CONSTRAINT "concepts_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "concepts" ADD CONSTRAINT "concepts_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "concepts" ADD CONSTRAINT "concepts_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "concepts" ADD CONSTRAINT "concepts_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_change_requests" ADD CONSTRAINT "graph_change_requests_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_change_requests" ADD CONSTRAINT "graph_change_requests_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_change_requests" ADD CONSTRAINT "graph_change_requests_author_id_users_id_fk" FOREIGN KEY ("author_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_change_requests" ADD CONSTRAINT "graph_change_requests_reviewed_by_users_id_fk" FOREIGN KEY ("reviewed_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_domain_terms" ADD CONSTRAINT "graph_domain_terms_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_domain_terms" ADD CONSTRAINT "graph_domain_terms_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_domain_terms" ADD CONSTRAINT "graph_domain_terms_node_id_graph_nodes_id_fk" FOREIGN KEY ("node_id") REFERENCES "public"."graph_nodes"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_edges" ADD CONSTRAINT "graph_edges_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_edges" ADD CONSTRAINT "graph_edges_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_edges" ADD CONSTRAINT "graph_edges_parent_id_graph_nodes_id_fk" FOREIGN KEY ("parent_id") REFERENCES "public"."graph_nodes"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_edges" ADD CONSTRAINT "graph_edges_child_node_id_graph_nodes_id_fk" FOREIGN KEY ("child_node_id") REFERENCES "public"."graph_nodes"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_edges" ADD CONSTRAINT "graph_edges_child_concept_id_concepts_id_fk" FOREIGN KEY ("child_concept_id") REFERENCES "public"."concepts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_edges" ADD CONSTRAINT "graph_edges_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_engine_state" ADD CONSTRAINT "graph_engine_state_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_engine_state" ADD CONSTRAINT "graph_engine_state_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_engine_state" ADD CONSTRAINT "graph_engine_state_applied_release_id_graph_releases_id_fk" FOREIGN KEY ("applied_release_id") REFERENCES "public"."graph_releases"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_nodes" ADD CONSTRAINT "graph_nodes_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_nodes" ADD CONSTRAINT "graph_nodes_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_nodes" ADD CONSTRAINT "graph_nodes_owner_id_users_id_fk" FOREIGN KEY ("owner_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_nodes" ADD CONSTRAINT "graph_nodes_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_nodes" ADD CONSTRAINT "graph_nodes_updated_by_users_id_fk" FOREIGN KEY ("updated_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_release_events" ADD CONSTRAINT "graph_release_events_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_release_events" ADD CONSTRAINT "graph_release_events_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_release_events" ADD CONSTRAINT "graph_release_events_from_release_id_graph_releases_id_fk" FOREIGN KEY ("from_release_id") REFERENCES "public"."graph_releases"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_release_events" ADD CONSTRAINT "graph_release_events_to_release_id_graph_releases_id_fk" FOREIGN KEY ("to_release_id") REFERENCES "public"."graph_releases"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_release_events" ADD CONSTRAINT "graph_release_events_actor_users_id_fk" FOREIGN KEY ("actor") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_releases" ADD CONSTRAINT "graph_releases_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_releases" ADD CONSTRAINT "graph_releases_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_releases" ADD CONSTRAINT "graph_releases_parent_release_id_graph_releases_id_fk" FOREIGN KEY ("parent_release_id") REFERENCES "public"."graph_releases"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_releases" ADD CONSTRAINT "graph_releases_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_revisions" ADD CONSTRAINT "graph_revisions_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_revisions" ADD CONSTRAINT "graph_revisions_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_revisions" ADD CONSTRAINT "graph_revisions_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "concepts_project_name_source_idx" ON "concepts" USING btree ("project_id",lower("name"),coalesce("source_id", '')) WHERE "concepts"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "concepts_aliases_idx" ON "concepts" USING gin ("aliases");--> statement-breakpoint
CREATE INDEX "concepts_project_kind_idx" ON "concepts" USING btree ("project_id","kind");--> statement-breakpoint
CREATE INDEX "concepts_project_type_idx" ON "concepts" USING btree ("project_id","type");--> statement-breakpoint
CREATE INDEX "concepts_owner_idx" ON "concepts" USING btree ("owner_id");--> statement-breakpoint
CREATE INDEX "graph_change_requests_project_status_idx" ON "graph_change_requests" USING btree ("project_id","status");--> statement-breakpoint
CREATE INDEX "graph_change_requests_entity_idx" ON "graph_change_requests" USING btree ("entity","entity_id","status");--> statement-breakpoint
CREATE INDEX "graph_change_requests_author_idx" ON "graph_change_requests" USING btree ("author_id");--> statement-breakpoint
CREATE UNIQUE INDEX "graph_domain_terms_node_term_idx" ON "graph_domain_terms" USING btree ("node_id",lower("term"));--> statement-breakpoint
CREATE INDEX "graph_edges_parent_idx" ON "graph_edges" USING btree ("parent_id","role","position");--> statement-breakpoint
CREATE INDEX "graph_edges_child_node_idx" ON "graph_edges" USING btree ("child_node_id");--> statement-breakpoint
CREATE INDEX "graph_edges_child_concept_idx" ON "graph_edges" USING btree ("child_concept_id");--> statement-breakpoint
CREATE UNIQUE INDEX "graph_nodes_project_kind_name_idx" ON "graph_nodes" USING btree ("project_id","kind",lower("name")) WHERE "graph_nodes"."deleted_at" IS NULL;--> statement-breakpoint
CREATE INDEX "graph_nodes_project_kind_idx" ON "graph_nodes" USING btree ("project_id","kind");--> statement-breakpoint
CREATE INDEX "graph_nodes_owner_idx" ON "graph_nodes" USING btree ("owner_id");--> statement-breakpoint
CREATE UNIQUE INDEX "graph_release_events_project_seq_idx" ON "graph_release_events" USING btree ("project_id","event_seq");--> statement-breakpoint
CREATE UNIQUE INDEX "graph_releases_project_seq_idx" ON "graph_releases" USING btree ("project_id","seq");--> statement-breakpoint
CREATE INDEX "graph_revisions_project_idx" ON "graph_revisions" USING btree ("project_id");