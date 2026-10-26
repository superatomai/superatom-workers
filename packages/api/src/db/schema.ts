import {
  pgTable,
  uuid,
  varchar,
  text,
  boolean,
  timestamp,
  jsonb,
  serial,
  integer,
  numeric,
  pgEnum,
  uniqueIndex,
  index,
  bigserial,
  bigint,
  primaryKey,
  check,
  type AnyPgColumn,
} from "drizzle-orm/pg-core";
import { relations, sql } from "drizzle-orm";

// ─── Enums ───────────────────────────────────────────────

export const userRoleEnum = pgEnum("user_role", ["super_admin", "org_admin", "member"]);

export const appTypeEnum = pgEnum("app_type", [
  "dashboard",
  "app",
  "report",
  "chat_agent",
]);

export const permissionEnum = pgEnum("permission_level", [
  "view",
  "edit",
  "admin",
]);

export const ssoProviderEnum = pgEnum("sso_provider", [
  "microsoft_entra",
  "okta",
  "generic_oidc",
  "saml",
]);

// ─── Organizations ───────────────────────────────────────

export const organizations = pgTable("organizations", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  slug: varchar("slug", { length: 100 }).unique().notNull(),
  icon: text("icon"),
  defaultAppId: uuid("default_app_id"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const organizationsRelations = relations(organizations, ({ many }) => ({
  users: many(users),
  projects: many(projects),
}));

// ─── Users ───────────────────────────────────────────────

export const users = pgTable(
  "users",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: uuid("org_id").references(() => organizations.id, { onDelete: "cascade" }),
    email: varchar("email", { length: 255 }).notNull(),
    name: varchar("name", { length: 255 }).notNull(),
    passwordHash: varchar("password_hash", { length: 255 }),
    ssoSubject: varchar("sso_subject", { length: 500 }),
    role: userRoleEnum("role").default("member").notNull(),
    isActive: boolean("is_active").default(true).notNull(),
    /**
     * Data-access config: row filters the relay stamps on every request.
     *
     * SDK sign-ins never write here. What the customer sends as `access` travels
     * in the access token instead (routes/sdk-auth.ts), so their latest word
     * applies to that session and nothing we stored can go stale against it.
     * This column is the platform's own: an admin sets it, and the relay uses it
     * only for sessions whose token carries no access.
     */
    config: jsonb("config"), // free-form per-user config
    /**
     * The user's role names in the CUSTOMER's own system (e.g. ["sales_manager"]),
     * as sent in the `roles` claim of an SDK sign-in. A list, since a user can hold
     * several. Stored only: it never grants our permissions — `role` above alone
     * decides those. Nullable — NULL for users who never signed in through the SDK.
     */
    externalRoles: jsonb("external_roles").$type<string[]>(),
    /**
     * Session revocation cutoff: tokens issued before this instant are rejected.
     * This is what makes logout actually invalidate a JWT rather than merely
     * asking the browser to forget it. Nullable — NULL means "never revoked", so
     * adding this column leaves every existing token working.
     */
    tokensValidAfter: timestamp("tokens_valid_after", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("users_org_email_idx").on(table.orgId, table.email),
    uniqueIndex("users_org_sso_subject_idx").on(table.orgId, table.ssoSubject),
  ]
);

export const usersRelations = relations(users, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [users.orgId],
    references: [organizations.id],
  }),
  appPermissions: many(appPermissions),
  createdProjects: many(projects),
  createdApps: many(apps),
}));

// ─── Projects ────────────────────────────────────────────

export const projects = pgTable(
  "projects",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    slug: varchar("slug", { length: 100 }).notNull(),
    description: text("description"),
    icon: text("icon"),
    designSystem: jsonb("design_system"),
    config: jsonb("config"),
    // Which superatom-setup-code branch the publish script builds for this project.
    // A build input, not a delivery one: the VM pulls an image, never a git ref.
    codeBranch: varchar("code_branch", { length: 255 }).notNull().default("main"),
    // Set to roll back; null means the newest row in project_releases.
    pinnedVersion: varchar("pinned_version", { length: 255 }),
    // Per program name, the version to run instead of the newest published one —
    // e.g. { "home": "0.1.0" } rolls home back. A name not listed runs its newest.
    programPins: jsonb("program_pins").$type<Record<string, string>>().notNull().default({}),
    createdBy: uuid("created_by").references(() => users.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [uniqueIndex("projects_org_slug_idx").on(table.orgId, table.slug)]
);

/**
 * One row per published release: the image, the engine it expects and the bundle
 * that goes with it, pinned together so a rollback cannot mix versions. Written
 * by the publish script; read by redeem/update to tell a VM what to run.
 */
export const projectReleases = pgTable(
  "project_releases",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    version: varchar("version", { length: 255 }).notNull(),
    branch: varchar("branch", { length: 255 }).notNull(),
    commit: varchar("commit", { length: 40 }).notNull(),
    // Repository and tag; the registry host comes from config, so an image stays
    // valid if the host ever changes.
    image: varchar("image", { length: 512 }).notNull(),
    imageDigest: varchar("image_digest", { length: 71 }).notNull(),
    bundleSha256: varchar("bundle_sha256", { length: 64 }).notNull(),
    // Null means "whatever engine/current.json publishes".
    engineVersion: varchar("engine_version", { length: 32 }),
    composeVersion: varchar("compose_version", { length: 32 }),
    // Migration count in this release, so a rollback across a schema change can warn.
    migrations: integer("migrations"),
    publishedBy: varchar("published_by", { length: 255 }),
    // The commit log since the project's previous release, as RELEASE.md shows it.
    // Stored so the UI can say what changed without fetching the bundle from R2.
    notes: text("notes"),
    publishedAt: timestamp("published_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("project_releases_version_idx").on(table.projectId, table.version),
    index("project_releases_latest_idx").on(table.projectId, table.publishedAt),
  ]
);

export const projectReleasesRelations = relations(projectReleases, ({ one }) => ({
  project: one(projects, { fields: [projectReleases.projectId], references: [projects.id] }),
}));

/**
 * One row per uploaded program build — the catalogue (architecture doc §11).
 *
 * A project has many programs, each one job's server side and/or UI, versioned
 * apart from the engine and from each other. A build is its archive,
 * programs/<projectId>/<hash>.tar.gz in the install bucket; the hash is the
 * archive's sha256, so every hop can check what it got.
 *
 * An uploaded build is a draft until it is published (published_at set). What a
 * project runs, per program name: its pin in projects.program_pins, else its
 * newest published build.
 */
export const projectPrograms = pgTable(
  "project_programs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // The program's name and version, from its program.json.
    name: varchar("name", { length: 255 }).notNull(),
    version: varchar("version", { length: 255 }).notNull(),
    hash: varchar("hash", { length: 64 }).notNull(),
    // The archive's size, checked with the hash.
    bytes: integer("bytes").notNull(),
    // The program repository's commit it was built from.
    commit: varchar("commit", { length: 40 }).notNull(),
    builtBy: varchar("built_by", { length: 255 }),
    uploadedAt: timestamp("uploaded_at", { withTimezone: true }).defaultNow().notNull(),
    // Null while a draft.
    publishedBy: varchar("published_by", { length: 255 }),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    notes: text("notes"),
  },
  (table) => [
    uniqueIndex("project_programs_version_idx").on(table.projectId, table.name, table.version),
    // One row per build: the same archive cannot be registered twice.
    uniqueIndex("project_programs_hash_idx").on(table.projectId, table.hash),
    index("project_programs_latest_idx").on(table.projectId, table.name, table.publishedAt),
  ]
);

export const projectProgramsRelations = relations(projectPrograms, ({ one }) => ({
  project: one(projects, { fields: [projectPrograms.projectId], references: [projects.id] }),
}));

/**
 * One row per installed copy of a project — a client VM. The VM reports what it is
 * running and reads targetVersion to know where to converge. Nothing derivable is
 * stored (behind / in sync / updating), so the row cannot go stale.
 */
export const projectInstalls = pgTable(
  "project_installs",
  {
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // Matches install_tokens.install_name: one project can run on several VMs.
    installName: varchar("install_name", { length: 255 }).notNull(),
    // What the VM last reported running; null until it reports for the first time.
    releaseVersion: varchar("release_version", { length: 255 }),
    imageDigest: varchar("image_digest", { length: 71 }),
    // What an admin approved. The updater only ever moves towards this, so
    // publishing a release does not deploy it.
    targetVersion: varchar("target_version", { length: 255 }),
    targetSetBy: varchar("target_set_by", { length: 255 }),
    targetSetAt: timestamp("target_set_at", { withTimezone: true }),
    // The updater's last failure, cleared on its next successful report.
    lastError: text("last_error"),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [primaryKey({ columns: [table.projectId, table.installName] })]
);

export const projectInstallsRelations = relations(projectInstalls, ({ one }) => ({
  project: one(projects, { fields: [projectInstalls.projectId], references: [projects.id] }),
}));

export const checklistRunStatusEnum = pgEnum("checklist_run_status", ["pass", "fail", "partial"]);
export const checklistRanByEnum = pgEnum("checklist_ran_by", ["agent", "human"]);

/**
 * One row per checklist run, indexing a report stored in R2 (full JSON body,
 * including per-item results — too large/variable-shaped for a query table).
 * `checklistId` + `scope` cover both today's project-scoped deploy checklists
 * (scope: {orgSlug, projectId}) and a future repo-scoped one, e.g. a
 * dev->prod merge gate (scope: {repo, commit}) — no schema change needed to
 * add that later. orgId/projectId are nullable for exactly that reason.
 */
export const checklistRuns = pgTable(
  "checklist_runs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    checklistId: varchar("checklist_id", { length: 100 }).notNull(),
    scope: jsonb("scope").notNull(),
    orgId: uuid("org_id").references(() => organizations.id, { onDelete: "set null" }),
    projectId: uuid("project_id").references(() => projects.id, { onDelete: "set null" }),
    status: checklistRunStatusEnum("status").notNull(),
    ranBy: checklistRanByEnum("ran_by").notNull(),
    summary: text("summary"),
    findingsCount: integer("findings_count").notNull().default(0),
    failedCount: integer("failed_count").notNull().default(0),
    // Git sha/tag or release version this run is against, when known.
    version: varchar("version", { length: 255 }),
    // Key of the full report JSON in the CHECKLIST_REPORTS bucket.
    r2Key: varchar("r2_key", { length: 512 }).notNull(),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull(),
    finishedAt: timestamp("finished_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("checklist_runs_checklist_idx").on(table.checklistId, table.createdAt),
    index("checklist_runs_project_idx").on(table.projectId, table.createdAt),
    index("checklist_runs_org_idx").on(table.orgId, table.createdAt),
  ]
);

export const checklistRunsRelations = relations(checklistRuns, ({ one }) => ({
  project: one(projects, { fields: [checklistRuns.projectId], references: [projects.id] }),
  organization: one(organizations, { fields: [checklistRuns.orgId], references: [organizations.id] }),
}));

export const projectsRelations = relations(projects, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [projects.orgId],
    references: [organizations.id],
  }),
  creator: one(users, {
    fields: [projects.createdBy],
    references: [users.id],
  }),
  apps: many(apps),
}));

// ─── Apps ────────────────────────────────────────────────

export const apps = pgTable("apps", {
  id: uuid("id").defaultRandom().primaryKey(),
  projectId: uuid("project_id")
    .notNull()
    .references(() => projects.id, { onDelete: "cascade" }),
  type: appTypeEnum("type").notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  description: varchar("description"),
  icon: text("icon"),
  config: jsonb("config"),
  createdBy: uuid("created_by").references(() => users.id, {
    onDelete: "set null",
  }),
  isActive: boolean("is_active").default(true).notNull(),
  // Bypasses app_permissions entirely — every member of this app's org can see
  // and open it, with no per-user grant needed. Separate from
  // organizations.defaultAppId (the single "land here by default" app); this
  // can be set on any number of apps. Name may get revisited later.
  isDefault: boolean("is_default").default(false).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const appsRelations = relations(apps, ({ one, many }) => ({
  project: one(projects, {
    fields: [apps.projectId],
    references: [projects.id],
  }),
  creator: one(users, {
    fields: [apps.createdBy],
    references: [users.id],
  }),
  permissions: many(appPermissions),
}));

// ─── App Permissions ─────────────────────────────────────

export const appPermissions = pgTable(
  "app_permissions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    appId: uuid("app_id")
      .notNull()
      .references(() => apps.id, { onDelete: "cascade" }),
    permission: permissionEnum("permission").notNull(),
    grantedBy: uuid("granted_by").references(() => users.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("app_permissions_user_app_idx").on(table.userId, table.appId),
  ]
);

export const appPermissionsRelations = relations(
  appPermissions,
  ({ one }) => ({
    user: one(users, {
      fields: [appPermissions.userId],
      references: [users.id],
    }),
    app: one(apps, {
      fields: [appPermissions.appId],
      references: [apps.id],
    }),
    granter: one(users, {
      fields: [appPermissions.grantedBy],
      references: [users.id],
      relationName: "grantedPermissions",
    }),
  })
);

// ─── API Keys (existing table, updated) ──────────────────

export const apiKeys = pgTable("api_keys", {
  id: serial("id").primaryKey(),
  projectId: varchar("project_id", { length: 255 }).notNull(),
  orgId: uuid("org_id").references(() => organizations.id, {
    onDelete: "set null",
  }),
  keyHash: varchar("key_hash", { length: 255 }).notNull(),
  keyPrefix: varchar("key_prefix", { length: 20 }).notNull(),
  isActive: boolean("is_active").default(true).notNull(),
  createdBy: varchar("created_by", { length: 255 }),
  description: varchar("description", { length: 500 }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
}, (table) => [
  // At most one ACTIVE API key per project. Revoked rows (is_active = false)
  // stay for history, so revoke→create rotation works. Replaces the need for a
  // full UNIQUE(project_id) constraint, which would block rotation.
  uniqueIndex("idx_api_keys_active")
    .on(table.projectId)
    .where(sql`${table.isActive} = true`),
]);

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
  organization: one(organizations, {
    fields: [apiKeys.orgId],
    references: [organizations.id],
  }),
}));

// ─── SSO Configs ────────────────────────────────────────

export const ssoConfigs = pgTable("sso_configs", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: uuid("org_id")
    .notNull()
    .unique()
    .references(() => organizations.id, { onDelete: "cascade" }),
  provider: ssoProviderEnum("provider").notNull(),
  protocol: varchar("protocol", { length: 10 }).default("oidc").notNull(),
  // OIDC fields (nullable — not used for SAML configs)
  clientId: varchar("client_id", { length: 500 }),
  clientSecret: text("client_secret"),
  issuerUrl: varchar("issuer_url", { length: 1000 }),
  scopes: varchar("scopes", { length: 500 }).default("openid email profile"),
  // SAML fields (nullable — not used for OIDC configs)
  samlIdpEntityId: varchar("saml_idp_entity_id", { length: 1000 }),
  samlIdpSsoUrl: varchar("saml_idp_sso_url", { length: 1000 }),
  samlIdpCertificates: jsonb("saml_idp_certificates"),
  isActive: boolean("is_active").default(true).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const ssoConfigsRelations = relations(ssoConfigs, ({ one }) => ({
  organization: one(organizations, {
    fields: [ssoConfigs.orgId],
    references: [organizations.id],
  }),
}));

// ─── Analytics Status Enum ──────────────────────────────

export const analyticsStatusEnum = pgEnum("analytics_status", [
  "success",
  "error",
  "aborted",
]);

// One row shape covers chat, dashboard-agent, and report-generation usage —
// `type` is the discriminator; the fields specific to one type (threadId/
// messageIndex/question for chat, appId for dashboard/report) are nullable
// and only populated for their own type. Kept as one table with one
// ingest/query path rather than per-type tables so all three can be
// queried/filtered together via a single `type` param instead of juggling
// separate endpoints.
export const analyticsTypeEnum = pgEnum("analytics_type", [
  "chat_agent",
  "dashboard",
  "report",
]);

// ─── Chat Analytics ─────────────────────────────────────

export const chatAnalytics = pgTable(
  "chat_analytics",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    type: analyticsTypeEnum("type").notNull().default("chat_agent"),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    orgId: uuid("org_id")
      .references(() => organizations.id, { onDelete: "set null" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // Chat-only grouping fields — null for dashboard/report rows, which group
    // by appId instead (see below).
    threadId: varchar("thread_id", { length: 255 }),
    messageIndex: integer("message_index"),
    question: text("question"),
    sourcesUsed: jsonb("sources_used"), // [{ sourceId, sourceName, sourceType }]
    sqlGenerated: text("sql_generated"),
    // The full saved-conversation response object — same shape as fusion-5's
    // user_conversations.response ({ id, component, analysis, user_prompt,
    // error?, scriptBinding? }), mirrored here centrally (same pattern as
    // answer_feedback.answerSnapshot). Nullable — older SDK versions won't
    // send it, and aborted/error turns may have a partial one.
    response: jsonb("response"),
    // Dashboard-agent / report-generation identifier — null for chat rows.
    // One column for both, not separate dashboardId/reportId, since both are
    // just "apps" (see appTypeEnum above — dashboard/report/chat_agent/app
    // are all app types already).
    appId: varchar("app_id", { length: 255 }),
    // Row id of the saved conversation in the main backend's OWN Postgres
    // (user_conversations / dashboard_agent_conversations / reports_conversations
    // — a different database this service has no connection to, hence no FK).
    // Nullable/optional: older SDK versions won't send it.
    conversationId: integer("conversation_id"),
    model: varchar("model", { length: 255 }).notNull(),
    inputTokens: integer("input_tokens").notNull(),
    outputTokens: integer("output_tokens").notNull(),
    cost: numeric("cost", { precision: 12, scale: 6 }).notNull(),
    latencyMs: integer("latency_ms").notNull(),
    status: analyticsStatusEnum("status").notNull(),
    errorMessage: text("error_message"),
    feedback: varchar("feedback", { length: 50 }), // 'thumbs_up' | 'thumbs_down' | null
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("chat_analytics_type_idx").on(table.type),
    index("chat_analytics_app_id_idx").on(table.appId),
    index("chat_analytics_conversation_id_idx").on(table.conversationId),
    index("chat_analytics_user_id_idx").on(table.userId),
    index("chat_analytics_org_id_idx").on(table.orgId),
    index("chat_analytics_project_id_idx").on(table.projectId),
    index("chat_analytics_created_at_idx").on(table.createdAt),
    index("chat_analytics_model_idx").on(table.model),
    index("chat_analytics_status_idx").on(table.status),
  ]
);

export const chatAnalyticsRelations = relations(chatAnalytics, ({ one }) => ({
  user: one(users, {
    fields: [chatAnalytics.userId],
    references: [users.id],
  }),
  organization: one(organizations, {
    fields: [chatAnalytics.orgId],
    references: [organizations.id],
  }),
  project: one(projects, {
    fields: [chatAnalytics.projectId],
    references: [projects.id],
  }),
}));

// ─── Speech (voice input) Usage ──────────────────────────
//
// Deliberately no FK references (unlike chatAnalytics above) — this is a
// best-effort metering log (see logUsage() in routes/speech.ts, which never
// blocks or fails the user's transcription on an insert error) and must
// never itself fail because a referenced org/user/project row is missing.

export const speechUsage = pgTable(
  "speech_usage",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: varchar("org_id", { length: 255 }),
    userId: varchar("user_id", { length: 255 }),
    projectId: varchar("project_id", { length: 255 }),
    model: varchar("model", { length: 128 }).notNull(),
    audioBytes: integer("audio_bytes").notNull(),
    audioSeconds: numeric("audio_seconds"),
    cost: numeric("cost"),
    latencyMs: integer("latency_ms"),
    ok: boolean("ok").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("speech_usage_org_id_idx").on(table.orgId),
    index("speech_usage_user_id_idx").on(table.userId),
    index("speech_usage_created_at_idx").on(table.createdAt),
  ]
);

// ─── Refresh Tokens ──────────────────────────────────────

/**
 * Rotating refresh tokens.
 *
 * Access tokens are short-lived (15m) and stateless; refreshing them needs
 * server state, because a stateless token cannot be revoked. Each refresh
 * consumes the presented token and issues a replacement in the same `familyId`.
 *
 * Presenting an ALREADY-ROTATED token means two parties hold it — the real user
 * and a thief — so the whole family is revoked and everyone re-authenticates.
 * That does not prevent theft; it makes theft self-limiting and detectable.
 *
 * Only the SHA-256 of the secret is stored, so a database leak does not yield
 * usable tokens.
 */
export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** Shared by every token descended from one login; revoked as a unit. */
    familyId: uuid("family_id").notNull(),
    tokenHash: varchar("token_hash", { length: 64 }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    /** Set when this token has been exchanged. Non-null + past grace = reuse. */
    rotatedAt: timestamp("rotated_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    replacedById: uuid("replaced_by_id"),
    userAgent: varchar("user_agent", { length: 500 }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("refresh_tokens_family_idx").on(table.familyId),
    index("refresh_tokens_user_idx").on(table.userId),
    index("refresh_tokens_expires_idx").on(table.expiresAt),
  ]
);

// ─── Answer Feedback (Feedback 1) ───────────────────────
// Dual-write: local Postgres (authoritative) + central Neon (aggregate mirror)
// This is the central Neon table. Local table lives in superatom-setup-code.

export const feedbackStatus = pgEnum('feedback_status', ['correct', 'incorrect', 'partial'])

export const answerFeedback = pgTable("answer_feedback", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id", { length: 255 }),
  projectId: varchar("project_id", { length: 255 }),
  userId: varchar("user_id", { length: 255 }),
  threadId: varchar("thread_id", { length: 255 }),
  uiBlockId: varchar("ui_block_id", { length: 255 }).notNull(),
  userPrompt: text("user_prompt").notNull(),
  status: feedbackStatus(),
  feedbackText: text("feedback_text"),
  answerSnapshot: jsonb("answer_snapshot"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  // Unique constraint for UPSERT: (userId, uiBlockId) — mirrors the local
  // idx_answer_feedback_user_uiblock constraint in superatom-setup-code.
  uniqueIndex("answer_feedback_user_uiblock_unique").on(
    table.userId,
    table.uiBlockId
  ),
  index("answer_feedback_org_id_idx").on(table.orgId),
  index("answer_feedback_thread_id_idx").on(table.threadId),
  index("answer_feedback_ui_block_id_idx").on(table.uiBlockId),
  index("answer_feedback_created_at_idx").on(table.createdAt),
]);

// ─── Product Feedback (Feedback 2) ──────────────────────
// Central Neon only — aggregates feedback from all client deployments

export const productFeedback = pgTable("product_feedback", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: varchar("org_id", { length: 255 }),
  userId: varchar("user_id", { length: 255 }),
  category: varchar("category", { length: 50 }),
  message: text("message").notNull(),
  pageContext: varchar("page_context", { length: 255 }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index("product_feedback_org_id_idx").on(table.orgId),
  index("product_feedback_category_idx").on(table.category),
  index("product_feedback_created_at_idx").on(table.createdAt),
]);

// ─── Super Admins ────────────────────────────────────────
// Superatom staff who use the super-admin console. Kept out of `users` so they
// never collide with a client-org account and sa-api's login can't load them.

export const superAdmins = pgTable(
  "super_admins",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    email: varchar("email", { length: 255 }).notNull(),
    name: varchar("name", { length: 255 }).notNull(),
    /** PBKDF2-SHA256, formatted `pbkdf2_sha256$<iterations>$<salt>$<hash>`. */
    passwordHash: varchar("password_hash", { length: 255 }).notNull(),
    isActive: boolean("is_active").default(true).notNull(),
    /** Sessions issued before this instant are rejected (logout, reset, deactivate). */
    tokensValidAfter: timestamp("tokens_valid_after", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [uniqueIndex("super_admins_email_idx").on(sql`lower(${table.email})`)]
);

// ─── Install Tokens ─────────────────────────────────────
// One-time tokens for `curl -fsSL https://install.superatom.ai | sh`, generated in the
// super-admin console. Only the SHA-256 is stored; redeeming issues the project's API key.

export const installTokens = pgTable(
  "install_tokens",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    tokenHash: varchar("token_hash", { length: 64 }).notNull(),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    orgId: uuid("org_id").notNull(),
    /** Stack / folder name on the VM, and the LLM proxy clientId. */
    installName: varchar("install_name", { length: 63 }).notNull(),
    /** 0 = unlimited. */
    llmBudgetCents: integer("llm_budget_cents").default(0).notNull(),
    /** Set once this token created the LLM proxy client, so a retry after a failed redeem may rotate it. */
    llmClientId: varchar("llm_client_id", { length: 100 }),
    createdBy: varchar("created_by", { length: 255 }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    redeemedAt: timestamp("redeemed_at", { withTimezone: true }),
    redeemedIp: varchar("redeemed_ip", { length: 64 }),
    redeemedCommit: varchar("redeemed_commit", { length: 40 }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("install_tokens_hash_idx").on(table.tokenHash),
    index("install_tokens_project_idx").on(table.projectId),
  ]
);

// ═════════════════════════════════════════════════════════
// Composition graph — authored on the platform, replicated to engines.
// Working tables keep the engine's columns (plus org/project/owner) and global
// integer ids, so an engine's replica keeps the same ids.
// ═════════════════════════════════════════════════════════

/** Who a concept applies to: everyone in the project, one user, or a group. */
export const conceptTypeEnum = pgEnum("concept_type", ["global", "user", "group"]);

// ─── Graph Nodes ─────────────────────────────────────────
// Every node (a domain or any other kind); non-owner edits go to graph_change_requests.

export const graphNodes = pgTable(
  "graph_nodes",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    ownerId: uuid("owner_id").references(() => users.id, { onDelete: "set null" }),
    // domain | part | file | setting | program | … (intermediate kinds to confirm)
    kind: varchar("kind", { length: 16 }).notNull(),
    name: varchar("name", { length: 96 }).notNull(),
    title: varchar("title", { length: 160 }),
    body: text("body").notNull(),
    // Kind-specific: a domain's threshold/shared/fallback, a file's path, a setting's key/value.
    meta: jsonb("meta").default({}).notNull(),
    // sha256 of kind + name + body + meta, computed by sa-api on save.
    hash: varchar("hash", { length: 64 }).notNull(),
    // draft | published | retired — whether a domain is routable. Versioned with the content.
    status: varchar("status", { length: 12 }).default("draft").notNull(),
    // platform | import | agent
    origin: varchar("origin", { length: 24 }),
    // Optimistic concurrency: a save sends the version it read; a mismatch is a 409.
    editVersion: integer("edit_version").default(1).notNull(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    updatedBy: uuid("updated_by").references(() => users.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
    // Soft delete: ids are never reused; deleted rows are left out of new releases.
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("graph_nodes_project_kind_name_idx")
      .on(table.projectId, table.kind, sql`lower(${table.name})`)
      .where(sql`${table.deletedAt} IS NULL`),
    index("graph_nodes_project_kind_idx").on(table.projectId, table.kind),
    index("graph_nodes_owner_idx").on(table.ownerId),
  ]
);

// ─── Concepts ────────────────────────────────────────────
// Same columns as the engine's `concepts`; proposals live in graph_change_requests.

export const concepts = pgTable(
  "concepts",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    ownerId: uuid("owner_id").references(() => users.id, { onDelete: "set null" }),
    name: varchar("name", { length: 64 }).notNull(),
    body: text("body").notNull(),
    // definition | lookup | filter | formula | invariant (invariant = always injected)
    kind: varchar("kind", { length: 24 }).default("definition").notNull(),
    // Optional: null until type-based routing exists.
    type: conceptTypeEnum("type"),
    // Names of concepts this one depends on (as in the engine).
    requires: text("requires").array().default(sql`'{}'::text[]`).notNull(),
    // Output contract: { type, unit, grain, caveats }.
    returns: jsonb("returns").default({}).notNull(),
    aliases: text("aliases").array().default(sql`'{}'::text[]`).notNull(),
    description: varchar("description", { length: 240 }),
    // platform | data_source | knowledge_node | user_question | agent_validated
    origin: varchar("origin", { length: 24 }),
    // The engine's project_sources.id; null = any source. Not an FK (sources live in the engine).
    sourceId: varchar("source_id", { length: 100 }),
    // Which item it came from, e.g. 'kb:42'.
    originRef: varchar("origin_ref", { length: 100 }),
    // Parity with the engine: always null here.
    supersedes: integer("supersedes"),
    // Parity with the engine: rows here are always verified.
    verified: boolean("verified").default(true).notNull(),
    // Off: answers leave it out (its domain links stay, so turning it back on puts it back).
    // Versioned like any field. Not the engine's review status, which is a separate thing.
    active: boolean("active").default(true).notNull(),
    editVersion: integer("edit_version").default(1).notNull(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    updatedBy: uuid("updated_by").references(() => users.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("concepts_project_name_source_idx")
      .on(table.projectId, sql`lower(${table.name})`, sql`coalesce(${table.sourceId}, '')`)
      .where(sql`${table.deletedAt} IS NULL`),
    index("concepts_aliases_idx").using("gin", table.aliases),
    index("concepts_project_kind_idx").on(table.projectId, table.kind),
    index("concepts_project_type_idx").on(table.projectId, table.type),
    index("concepts_owner_idx").on(table.ownerId),
  ]
);

// ─── Graph Edges ─────────────────────────────────────────
// Links node → node and node → concept, owned with their parent node. Must stay acyclic.

export const graphEdges = pgTable(
  "graph_edges",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    parentId: integer("parent_id")
      .notNull()
      .references(() => graphNodes.id, { onDelete: "cascade" }),
    childNodeId: integer("child_node_id").references(() => graphNodes.id, { onDelete: "cascade" }),
    childConceptId: integer("child_concept_id").references(() => concepts.id, { onDelete: "cascade" }),
    // concept | prompt | file | setting | program | domain (+ intermediate roles to confirm)
    role: varchar("role", { length: 12 }).notNull(),
    // Order within the parent and role: 1, 2, 3 …
    position: integer("position").notNull(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    // Exactly one child: a node or a concept.
    check("graph_edges_one_child", sql`(${table.childNodeId} IS NULL) <> (${table.childConceptId} IS NULL)`),
    check("graph_edges_no_self_link", sql`${table.childNodeId} IS NULL OR ${table.childNodeId} <> ${table.parentId}`),
    index("graph_edges_parent_idx").on(table.parentId, table.role, table.position),
    index("graph_edges_child_node_idx").on(table.childNodeId),
    index("graph_edges_child_concept_idx").on(table.childConceptId),
  ]
);

// ─── Graph Domain Terms ──────────────────────────────────
// A domain's routing keywords. Belong to the domain (same ownership).

export const graphDomainTerms = pgTable(
  "graph_domain_terms",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    nodeId: integer("node_id")
      .notNull()
      .references(() => graphNodes.id, { onDelete: "cascade" }),
    // Lower-case; a multi-word term matches as a phrase.
    term: varchar("term", { length: 64 }).notNull(),
    weight: integer("weight").default(1).notNull(),
  },
  (table) => [
    uniqueIndex("graph_domain_terms_node_term_idx").on(table.nodeId, sql`lower(${table.term})`),
  ]
);

// ─── Graph Change Requests ───────────────────────────────
// Non-owner edits and agent proposals, held until the owner merges or rejects them.

export const graphChangeRequests = pgTable(
  "graph_change_requests",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // node | concept
    entity: varchar("entity", { length: 8 }).notNull(),
    // graph_nodes.id or concepts.id per `entity` (not an FK); null when proposing a new item.
    entityId: integer("entity_id"),
    // create | update | delete
    action: varchar("action", { length: 8 }).notNull(),
    // The item's edit_version when the request was started; a mismatch at merge is a conflict.
    baseEditVersion: integer("base_edit_version"),
    // Full proposed content (for a node: fields + edges + terms).
    proposed: jsonb("proposed").notNull(),
    // Null for an agent proposal.
    authorId: uuid("author_id").references(() => users.id, { onDelete: "set null" }),
    // user | agent | import
    source: varchar("source", { length: 12 }).notNull(),
    originRef: varchar("origin_ref", { length: 100 }),
    // open | merged | rejected | withdrawn
    status: varchar("status", { length: 10 }).default("open").notNull(),
    reviewedBy: uuid("reviewed_by").references(() => users.id, { onDelete: "set null" }),
    reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
    // Required when rejecting.
    reviewComment: text("review_comment"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("graph_change_requests_project_status_idx").on(table.projectId, table.status),
    index("graph_change_requests_entity_idx").on(table.entity, table.entityId, table.status),
    index("graph_change_requests_author_idx").on(table.authorId),
  ]
);

// ─── Graph Changes ───────────────────────────────────────
// Append-only edit history of the working copy (before/after per change). Releases don't use it.

export const graphChanges = pgTable(
  "graph_changes",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // 1, 2, 3 … per project with no gaps, in commit order (from graph_change_heads); engines follow it.
    seq: bigint("seq", { mode: "number" }).notNull(),
    // node | concept
    entity: varchar("entity", { length: 8 }).notNull(),
    // graph_nodes.id or concepts.id per `entity` (not an FK: history outlives the row).
    entityId: integer("entity_id").notNull(),
    // create | update | delete | restore | owner
    action: varchar("action", { length: 8 }).notNull(),
    // edit | merge | import | discard
    via: varchar("via", { length: 8 }).notNull(),
    // Set when `via` is merge.
    changeRequestId: integer("change_request_id").references(() => graphChangeRequests.id, { onDelete: "set null" }),
    // The item before and after (for a node: fields + edges + terms; for owner: { ownerId }). Null for create / delete.
    before: jsonb("before"),
    after: jsonb("after"),
    changedBy: uuid("changed_by").references(() => users.id, { onDelete: "set null" }),
    changedAt: timestamp("changed_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    index("graph_changes_item_idx").on(table.entity, table.entityId, table.changedAt),
    index("graph_changes_project_idx").on(table.projectId, table.changedAt),
    uniqueIndex("graph_changes_project_seq_idx").on(table.projectId, table.seq),
  ]
);

// ─── Graph Change Heads ──────────────────────────────────
// The last graph_changes.seq per project. Taking the next number locks this row
// until the edit commits, so numbers are handed out in commit order with no gaps.

export const graphChangeHeads = pgTable("graph_change_heads", {
  projectId: uuid("project_id")
    .primaryKey()
    .references(() => projects.id, { onDelete: "cascade" }),
  orgId: uuid("org_id")
    .notNull()
    .references(() => organizations.id, { onDelete: "cascade" }),
  seq: bigint("seq", { mode: "number" }).notNull(),
});

// ─── Graph Revisions ─────────────────────────────────────
// Append-only: an immutable copy of an item each time a release includes a change to it.

export const graphRevisions = pgTable(
  "graph_revisions",
  {
    // node | concept
    entity: varchar("entity", { length: 8 }).notNull(),
    // graph_nodes.id or concepts.id per `entity` (not an FK: history outlives the row).
    entityId: integer("entity_id").notNull(),
    // 1, 2, 3 … per item.
    rev: integer("rev").notNull(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // Full snapshot (for a node: fields + edges + terms).
    content: jsonb("content").notNull(),
    // Hash of content plus its children's hashes (Merkle).
    hash: varchar("hash", { length: 64 }).notNull(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.entity, table.entityId, table.rev] }),
    index("graph_revisions_project_idx").on(table.projectId),
  ]
);

// ─── Graph Releases ──────────────────────────────────────
// Append-only: a published, immutable snapshot of a project's whole graph.

export const graphReleases = pgTable(
  "graph_releases",
  {
    id: serial("id").primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // Release number per project: 1, 2, 3 …
    seq: integer("seq").notNull(),
    // [{ entity, id, rev, hash }] — exactly which revision of every node and concept.
    items: jsonb("items").notNull(),
    // Hash over all items; engines compare it to verify their copy.
    rootHash: varchar("root_hash", { length: 64 }).notNull(),
    // The release this one was built on (for diffs).
    parentReleaseId: integer("parent_release_id").references((): AnyPgColumn => graphReleases.id, {
      onDelete: "set null",
    }),
    notes: text("notes"),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [uniqueIndex("graph_releases_project_seq_idx").on(table.projectId, table.seq)]
);

// ─── Graph Release Events ────────────────────────────────
// Append-only publish/rollback log; the latest event's to_release_id is current.
// Engines order by event_seq, so a rollback to an older release still applies.

export const graphReleaseEvents = pgTable(
  "graph_release_events",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // +1 per event per project.
    eventSeq: bigint("event_seq", { mode: "number" }).notNull(),
    // publish | rollback
    action: varchar("action", { length: 12 }).notNull(),
    // Null on the first release.
    fromReleaseId: integer("from_release_id").references(() => graphReleases.id),
    toReleaseId: integer("to_release_id")
      .notNull()
      .references(() => graphReleases.id),
    // Required for rollback.
    reason: text("reason"),
    actor: uuid("actor").references(() => users.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [uniqueIndex("graph_release_events_project_seq_idx").on(table.projectId, table.eventSeq)]
);

// ─── Graph Engine State ──────────────────────────────────
// Which release each engine runs, from its GRAPH_ACK / GRAPH_NACK.

export const graphEngineState = pgTable(
  "graph_engine_state",
  {
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // The id the engine sends in GRAPH_HELLO (a UUID stored on the engine machine).
    engineId: varchar("engine_id", { length: 64 }).notNull(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    // Last release it acknowledged.
    appliedReleaseId: integer("applied_release_id").references(() => graphReleases.id, {
      onDelete: "set null",
    }),
    appliedRootHash: varchar("applied_root_hash", { length: 64 }),
    // Last working-copy change (graph_changes.seq) it applied to its draft.
    appliedChangeSeq: bigint("applied_change_seq", { mode: "number" }),
    // in_sync | behind | error
    status: varchar("status", { length: 12 }).notNull(),
    // Error from the last GRAPH_NACK.
    lastError: text("last_error"),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    lastAckAt: timestamp("last_ack_at", { withTimezone: true }),
  },
  (table) => [primaryKey({ columns: [table.projectId, table.engineId] })]
);

// ─── Files ───────────────────────────────────────────────
// One row per file kept in R2, whatever put it there. The row is the record of
// the file; the object in R2 is its content. A changed file is a new row that
// points at the one it replaces, never an overwrite.

export const files = pgTable(
  "files",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    projectId: uuid("project_id")
      .notNull()
      .references(() => projects.id, { onDelete: "cascade" }),
    // The chat agent the file belongs to, when it belongs to one.
    appId: uuid("app_id").references(() => apps.id, { onDelete: "set null" }),
    // Who put it there; null once that user is removed.
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    // chat_attachment now; agent_output and source_file later.
    kind: varchar("kind", { length: 32 }).notNull(),
    // What the file belongs to: ownerType "thread" with the thread id, "source" with
    // the data source's id, and so on. These ids live in the project's own database
    // (thread ids are nanoids, source ids look like "excel-168814462398"), so they
    // are plain strings with no foreign key. Both set, or both empty.
    ownerType: varchar("owner_type", { length: 32 }),
    ownerId: varchar("owner_id", { length: 255 }),
    fileName: text("file_name").notNull(),
    contentType: varchar("content_type", { length: 255 }),
    sizeBytes: bigint("size_bytes", { mode: "number" }),
    r2Key: text("r2_key").notNull(),
    etag: varchar("etag", { length: 128 }),
    // pending: reserved, not yet confirmed in R2 | ready | deleted | expired: never completed
    status: varchar("status", { length: 16 }).notNull().default("pending"),
    version: integer("version").notNull().default(1),
    // The row this one replaces, when it is a changed copy.
    previousVersionId: uuid("previous_version_id").references((): AnyPgColumn => files.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("files_r2_key_unique").on(table.r2Key),
    index("files_org_idx").on(table.orgId),
    index("files_project_kind_idx").on(table.projectId, table.kind),
    index("files_owner_idx").on(table.ownerType, table.ownerId),
    check("files_owner_check", sql`(${table.ownerType} is null) = (${table.ownerId} is null)`),
    // The sweep that expires uploads that never completed.
    index("files_status_created_idx").on(table.status, table.createdAt),
    check("files_status_check", sql`${table.status} in ('pending', 'ready', 'deleted', 'expired')`),
  ]
);
