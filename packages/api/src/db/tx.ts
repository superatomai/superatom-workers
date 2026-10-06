import { Pool } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import type { PgDatabase } from "drizzle-orm/pg-core";
import * as schema from "./schema";

/** Interactive transactions on a per-call Pool (Neon HTTP can't read-then-write in one transaction). */

function createTxDb(pool: Pool) {
  return drizzle(pool, { schema });
}

type TxDb = ReturnType<typeof createTxDb>;
export type Tx = Parameters<Parameters<TxDb["transaction"]>[0]>[0];

/** Anything queries can run on: the request `db` or a transaction. */
export type Q = PgDatabase<any, any, any>;

export async function withTransaction<T>(
  databaseUrl: string,
  fn: (tx: Tx) => Promise<T>,
  config?: { isolationLevel?: "read committed" | "repeatable read" | "serializable" },
): Promise<T> {
  const pool = new Pool({ connectionString: databaseUrl });
  try {
    return await createTxDb(pool).transaction(fn, config);
  } finally {
    await pool.end();
  }
}
