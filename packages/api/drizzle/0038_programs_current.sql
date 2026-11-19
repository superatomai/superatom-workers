-- The current pointer per program row (renumbered from the programs-v2 branch's 0035 when it merged with
-- dev's 0035–0037). Added and backfilled only when the columns are missing, so a database that ran the old
-- 0035 is left as it is.
DO $$ BEGIN
	IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'project_programs' AND column_name = 'current') THEN
		ALTER TABLE "project_programs" ADD COLUMN "current" boolean DEFAULT false NOT NULL;
		ALTER TABLE "project_programs" ADD COLUMN "pinned" boolean DEFAULT false NOT NULL;
		-- Backfill the pointer from the rule it replaces: the pin in projects.program_pins, else the newest published build per name.
		UPDATE "project_programs" p SET "current" = true, "pinned" = true FROM "projects" pr WHERE p."project_id" = pr."id" AND p."status" = 'ready' AND p."published_at" IS NOT NULL AND pr."program_pins" ->> p."name" = p."version";
		UPDATE "project_programs" p SET "current" = true WHERE p."status" = 'ready' AND p."published_at" IS NOT NULL AND NOT EXISTS (SELECT 1 FROM "project_programs" q WHERE q."project_id" = p."project_id" AND q."name" = p."name" AND q."current") AND p."published_at" = (SELECT max(q."published_at") FROM "project_programs" q WHERE q."project_id" = p."project_id" AND q."name" = p."name" AND q."status" = 'ready' AND q."published_at" IS NOT NULL);
	END IF;
END $$;
