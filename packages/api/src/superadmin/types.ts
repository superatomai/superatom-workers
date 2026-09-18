import type { Database } from "../db";

export type SuperAdminVariables = {
  db: Database;
  admin: { id: string; email: string; name: string };
};
