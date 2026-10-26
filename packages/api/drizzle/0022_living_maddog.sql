CREATE TABLE "graph_change_heads" (
	"project_id" uuid PRIMARY KEY NOT NULL,
	"org_id" uuid NOT NULL,
	"seq" bigint NOT NULL
);
--> statement-breakpoint
ALTER TABLE "graph_changes" ADD COLUMN "seq" bigint;--> statement-breakpoint
-- Existing history: 1, 2, 3 … per project in id order (the order it was written; graph writes held the project lock).
UPDATE "graph_changes" c SET "seq" = n.seq
  FROM (SELECT "id", row_number() OVER (PARTITION BY "project_id" ORDER BY "id") AS seq FROM "graph_changes") n
 WHERE c."id" = n."id";--> statement-breakpoint
ALTER TABLE "graph_changes" ALTER COLUMN "seq" SET NOT NULL;--> statement-breakpoint
-- Each project's head starts at its last number, so new edits carry on from there.
INSERT INTO "graph_change_heads" ("project_id", "org_id", "seq")
SELECT DISTINCT ON ("project_id") "project_id", "org_id", "seq" FROM "graph_changes" ORDER BY "project_id", "seq" DESC;--> statement-breakpoint
ALTER TABLE "graph_engine_state" ADD COLUMN "applied_change_seq" bigint;--> statement-breakpoint
ALTER TABLE "graph_change_heads" ADD CONSTRAINT "graph_change_heads_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "graph_change_heads" ADD CONSTRAINT "graph_change_heads_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "graph_changes_project_seq_idx" ON "graph_changes" USING btree ("project_id","seq");