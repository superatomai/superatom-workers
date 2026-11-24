ALTER TABLE "object_grants" ALTER COLUMN "object_role_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "object_grants" DROP COLUMN "level";