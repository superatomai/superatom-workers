#!/usr/bin/env node
/**
 * Access simulation: tries every way someone could get more access than they
 * were given (privilege escalation) against a running SA-API, and checks each
 * one is refused. Proof that the hierarchy holds:
 *   Owner > Admin > custom roles and Members; nobody acts on themselves; a role,
 *   a share or a project boundary never reaches further than it should.
 *
 * It signs in as the org's Owner, creates its own test people, roles and apps,
 * runs the attacks, and removes everything it created.
 *
 *   SIM_API=http://127.0.0.1:8787 \
 *   SIM_ORG_SLUG=superatom SIM_OWNER_EMAIL=… SIM_OWNER_PASSWORD=… \
 *   SIM_PROJECT_A=<project id> SIM_PROJECT_B=<another project id> \
 *   node tests/integration/access-simulation.mjs
 *
 * Run it against a local or development API only: it creates and removes users.
 */
const API = process.env.SIM_API ?? "http://127.0.0.1:8787";
const { SIM_ORG_SLUG: SLUG, SIM_OWNER_EMAIL, SIM_OWNER_PASSWORD, SIM_PROJECT_A: A, SIM_PROJECT_B: B } = process.env;
if (!SLUG || !SIM_OWNER_EMAIL || !SIM_OWNER_PASSWORD || !A || !B) {
  console.error("Set SIM_ORG_SLUG, SIM_OWNER_EMAIL, SIM_OWNER_PASSWORD, SIM_PROJECT_A and SIM_PROJECT_B (see the top of this file).");
  process.exit(2);
}
const PASSWORD = "Sim@Test12345";
const stamp = Date.now().toString(36);

// ── HTTP ────────────────────────────────────────────────────────────────────
async function call(method, path, token, body) {
  const r = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let b = null;
  try { b = await r.json(); } catch {}
  return { s: r.status, b };
}
const login = async (email, password = PASSWORD) => {
  const r = await call("POST", "/auth/login", null, { email, password, orgSlug: SLUG });
  if (!r.b?.token) throw new Error(`sign-in failed for ${email}: ${r.s} ${JSON.stringify(r.b)}`);
  return { token: r.b.token, id: r.b.user.id };
};

// ── Results ─────────────────────────────────────────────────────────────────
const results = [];
let n = 0;
/**
 * One attack: `attempt` runs it; `held` says whether the system did the right
 * thing. `opts.allowed`: something that SHOULD work, checked so the safety
 * rules are not simply refusing everything. `opts.note`: what `held` checked,
 * when it looks at the result rather than the response.
 */
async function attack(who, what, attempt, held, opts = {}) {
  n++;
  let r, ok, detail;
  try {
    r = await attempt();
    ok = await held(r);
    detail = opts.note ?? (r?.b?.error ? `${r.s} "${r.b.error}"` : String(r?.s ?? ""));
  } catch (e) {
    ok = false;
    detail = String(e);
  }
  results.push({ n, ok });
  const verdict = opts.allowed ? (ok ? "works" : "BROKEN") : ok ? "stopped" : "NOT STOPPED";
  console.log(`  ${ok ? "✔" : "✘"} ${String(n).padStart(2)}. ${who}: ${what}  →  ${verdict} (${detail})`);
}
const refused = (r) => r.s === 403 || r.s === 400 || r.s === 401 || r.s === 404 || r.s === 409;

// ── Setup ───────────────────────────────────────────────────────────────────
console.log(`Access simulation against ${API}\n`);
const owner = await login(SIM_OWNER_EMAIL, SIM_OWNER_PASSWORD);
const me = await call("GET", "/auth/me", owner.token);
const ORG = me.b.organization.id;
const made = { users: [], roles: [], apps: [] };

const newRole = async (name, permissions) => {
  const r = await call("POST", `/orgs/${ORG}/roles`, owner.token, { name: `${name} ${stamp}`, permissions });
  if (r.s !== 201) throw new Error(`could not create role ${name}: ${JSON.stringify(r.b)}`);
  made.roles.push(r.b.id);
  return r.b;
};
const newUser = async (name, role, extra = {}) => {
  const email = `sim.${name}.${stamp}@example.com`;
  const r = await call("POST", `/orgs/${ORG}/users`, owner.token, { email, name: `Sim ${name}`, password: PASSWORD, role, ...extra });
  if (r.s !== 201) throw new Error(`could not create ${name}: ${JSON.stringify(r.b)}`);
  made.users.push(r.b.id);
  return { ...(await login(email)), email };
};
const newApp = async (name, projectId = A) => {
  const r = await call("POST", `/projects/${projectId}/apps`, owner.token, { name: `Sim ${name} ${stamp}`, type: "dashboard" });
  if (r.s !== 201) throw new Error(`could not create app ${name}: ${JSON.stringify(r.b)}`);
  made.apps.push(r.b.id);
  return r.b.id;
};

const analystRole = await newRole("Analyst", ["platform.access", "dashboard.view"]);
// Runtime only: no platform access, so no other permission either (a role holding
// one without platform access is refused; see "Dependent permissions" below).
const noPlatformRole = await newRole("No Platform", []);
// A new Admin starts without the people powers (members.*); the Owner ticks
// them all for admin1 and the limited Admin (limits: []), and leaves admin2 as created.
const admin1 = await newUser("admin1", "admin", { limits: [] });
const admin2 = await newUser("admin2", "admin");
const limitedAdmin = await newUser("limitedadmin", "admin", { projectScope: "selected", projectIds: [A], limits: [] });
const analyst = await newUser("analyst", analystRole.key);
// A second platform user (same custom role), for the cases that need a Manager who is not an Admin.
const curator = await newUser("curator", analystRole.key);
const noPlatform = await newUser("noplatform", noPlatformRole.key);
const member = await newUser("member", "member");
const outsider = await newUser("outsider", "member", { projectScope: "selected", projectIds: [B] });
const X = await newApp("Revenue");
const Y = await newApp("Draft");
const Z = await newApp("Scratch");
const ownerRoleId = (await call("GET", `/orgs/${ORG}/roles`, owner.token)).b.find((r) => r.key === "owner").id;
const shareX = (principalId, level, token = owner.token) => call("POST", `/apps/${X}/grants`, token, { principalType: "user", principalId, level });
const levelOn = async (app, token) => (await call("GET", `/apps/${app}`, token)).b?.level ?? null;

// ── Attacks ─────────────────────────────────────────────────────────────────
console.log("Nobody changes their own role or reach");
await attack("A Member", "makes themselves Admin", () => call("PUT", `/orgs/${ORG}/users/${member.id}`, member.token, { role: "admin" }), refused);
await attack("An Admin", "makes themselves Owner", () => call("PUT", `/orgs/${ORG}/users/${admin1.id}`, admin1.token, { role: "owner" }), refused);
await attack("The Owner", "changes their own role (could leave the org without an Owner)", () => call("PUT", `/orgs/${ORG}/users/${owner.id}`, owner.token, { role: "admin" }), refused);
await attack("An Admin", "changes their own projects", () => call("PUT", `/orgs/${ORG}/users/${admin1.id}`, admin1.token, { projectScope: "selected", projectIds: [A] }), refused);
await attack("The Owner", "removes themselves", () => call("DELETE", `/orgs/${ORG}/users/${owner.id}`, owner.token), refused);

console.log("\nThe hierarchy: Owner > Admin > everyone else");
await attack("An Admin", "makes a Member an Admin", () => call("PUT", `/orgs/${ORG}/users/${member.id}`, admin1.token, { role: "admin" }), refused);
await attack("An Admin", "makes a Member the Owner", () => call("PUT", `/orgs/${ORG}/users/${member.id}`, admin1.token, { role: "owner" }), refused);

console.log("\nOnly the super admin makes Owners");
await attack("The Owner", "makes a Member an Owner", () => call("PUT", `/orgs/${ORG}/users/${member.id}`, owner.token, { role: "owner" }), refused);
await attack("The Owner", "makes an Admin an Owner", () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, owner.token, { role: "owner" }), refused);
await attack(
  "The Owner",
  "adds a new member straight in as Owner",
  async () => {
    const r = await call("POST", `/orgs/${ORG}/users`, owner.token, { email: `sim.own.${stamp}@example.com`, name: "Sim own", password: PASSWORD, role: "owner" });
    if (r.b?.id) made.users.push(r.b.id);
    return r;
  },
  refused
);
await attack("An Admin", "adds a new Admin", () => call("POST", `/orgs/${ORG}/users`, admin1.token, { email: `sim.x.${stamp}@example.com`, name: "X", password: PASSWORD, role: "admin" }), refused);
await attack("An Admin", "demotes another Admin", () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, admin1.token, { role: "member" }), refused);
await attack("An Admin", "removes another Admin", () => call("DELETE", `/orgs/${ORG}/users/${admin2.id}`, admin1.token), refused);
await attack("An Admin", "removes the Owner", () => call("DELETE", `/orgs/${ORG}/users/${owner.id}`, admin1.token), refused);
await attack("An Admin", "resets another Admin's password", () => call("POST", `/orgs/${ORG}/users/${admin2.id}/password`, admin1.token, { password: "Hijack@12345" }), refused);

console.log("\nAn Admin manages people only if the Owner ticked it");
await attack("An Admin without people powers", "adds a member", () => call("POST", `/orgs/${ORG}/users`, admin2.token, { email: `sim.np.${stamp}@example.com`, name: "NP", password: PASSWORD }), refused);
await attack("An Admin without people powers", "resets a member's password", () => call("POST", `/orgs/${ORG}/users/${member.id}/password`, admin2.token, { password: "Hijack@12345" }), refused);
await attack("An Admin without people powers", "reads people's data rules and access history", () => call("GET", `/orgs/${ORG}/users/${member.id}/access-history`, admin2.token), refused);
await attack("An Admin without people powers", "reads the access log", () => call("GET", `/orgs/${ORG}/access-log`, admin2.token), refused);
await attack("An Admin", "gives themselves the people powers", () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, admin2.token, { limits: [] }), refused);
await attack("An Admin with people powers", "lifts another Admin's limits", () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, admin1.token, { limits: [] }), refused);
await attack("An Admin", "changes their own data rules", () => call("PUT", `/orgs/${ORG}/users/${admin1.id}`, admin1.token, { config: null }), refused);

console.log("\nManaging admins and roles is fixed in code, not a permission");
await attack("The Owner", "creates a role carrying member management", () => call("POST", `/orgs/${ORG}/roles`, owner.token, { name: `Bad ${stamp}`, permissions: ["members.manage"] }), refused);
await attack("The Owner", "creates a role carrying role management", () => call("POST", `/orgs/${ORG}/roles`, owner.token, { name: `Bad2 ${stamp}`, permissions: ["roles.manage"] }), refused);
await attack("An Admin", "creates a custom role", () => call("POST", `/orgs/${ORG}/roles`, admin1.token, { name: `Mine ${stamp}`, permissions: [] }), refused);
await attack("A custom role user", "adds a member", () => call("POST", `/orgs/${ORG}/users`, analyst.token, { email: `sim.y.${stamp}@example.com`, name: "Y", password: PASSWORD }), refused);
await attack("A custom role user", "changes someone's role", () => call("PUT", `/orgs/${ORG}/users/${member.id}`, analyst.token, { role: "admin" }), refused);
await attack("A custom role user", "adds permissions to their own role", () => call("PUT", `/orgs/${ORG}/roles/${analystRole.id}`, analyst.token, { permissions: ["platform.access", "project.delete"] }), refused);
await attack("A custom role user", "reads the access log", () => call("GET", `/orgs/${ORG}/access-log`, analyst.token), refused);
await attack("A role without platform access", "uses the platform", () => call("GET", `/orgs/${ORG}/users`, noPlatform.token), refused);
await attack(
  "An Admin",
  "sneaks the Owner role in through extra fields (role_id, org_id, password_hash)",
  () => call("PUT", `/orgs/${ORG}/users/${member.id}`, admin1.token, { name: "Sim member", roleId: ownerRoleId, role_id: ownerRoleId, orgId: ORG, passwordHash: "x" }),
  async () => (await call("GET", `/orgs/${ORG}/users/${member.id}`, owner.token)).b?.orgRole === "member",
  { note: "the extra fields were ignored: still a Member" }
);

console.log("\nDependent permissions: nothing without platform access, no Members action without See members");
// A role the API wrongly accepts is still cleaned up at the end.
const tryRole = async (name, permissions) => {
  const r = await call("POST", `/orgs/${ORG}/roles`, owner.token, { name: `${name} ${stamp}`, permissions });
  if (r.s === 201) made.roles.push(r.b.id);
  return r;
};
await attack("The Owner", "creates a role with dashboards but no platform access", () => tryRole("NoSignIn", ["dashboard.view"]), refused);
await attack("The Owner", "creates a role with analytics export but no platform access", () => tryRole("NoSignIn2", ["analytics.view", "analytics.export"]), refused);
await attack("The Owner", "creates a role that edits members without seeing them", () => tryRole("BlindEdit", ["platform.access", "members.edit"]), refused);
await attack("The Owner", "creates a role that sets data rules without seeing members", () => tryRole("BlindRules", ["platform.access", "members.data_rules"]), refused);
await attack("The Owner", "takes platform access out of the analyst role, keeping dashboards", () => call("PUT", `/orgs/${ORG}/roles/${analystRole.id}`, owner.token, { permissions: ["dashboard.view"] }), refused);
await attack(
  "The Owner",
  "lets an Admin edit members without seeing them (limits: members.view)",
  () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, owner.token, { limits: ["members.view"] }),
  refused
);
await attack(
  "The Owner",
  "takes platform access from an Admin but leaves the rest",
  () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, owner.token, { limits: ["platform.access"] }),
  refused
);
await attack("A role without platform access", "reads the access log", () => call("GET", `/orgs/${ORG}/access-log`, noPlatform.token), refused);

console.log("\nSharing never reaches further than the sharer's own role");
await attack("A Viewer", "edits the dashboard", () => call("PUT", `/apps/${X}`, analyst.token, { description: "changed" }), refused);
await attack("A Viewer", "shares the dashboard", () => shareX(member.id, "view", analyst.token), refused);
const editorGrant = (await shareX(analyst.id, "edit")).b;
await attack("An Editor", "shares the dashboard", () => shareX(member.id, "view", analyst.token), refused);
await attack("An Editor", "raises their own share to Manager", () => call("PUT", `/apps/${X}/grants/${editorGrant.id}`, analyst.token, { level: "manage" }), refused);
await attack("An Editor", "disables the dashboard", () => call("PUT", `/apps/${X}/status`, analyst.token, { status: "disabled" }), refused);
await call("PUT", `/apps/${X}/grants/${editorGrant.id}`, owner.token, { level: "manage" });
await attack("A Manager", "gives someone the owner role", () => shareX(member.id, "owner", analyst.token), refused);
await attack("A Manager", "takes ownership for themselves", () => call("PUT", `/apps/${X}/owner`, analyst.token, { userId: analyst.id }), refused);
await attack(
  "A Manager",
  "removes every share, to lock the owner out",
  async () => {
    for (const g of (await call("GET", `/apps/${X}/grants`, analyst.token)).b?.grants ?? []) await call("DELETE", `/apps/${X}/grants/${g.id}`, analyst.token);
    return { s: 200 };
  },
  async () => (await levelOn(X, owner.token)) === "owner",
  { note: "ownership is not a share: the owner keeps full control" }
);

console.log("\nProject boundaries hold, whatever is shared");
await attack("The Owner", "shares a project A dashboard with someone limited to project B", () => shareX(outsider.id, "view"), refused);
await attack("The Owner", "hands a project A dashboard to someone limited to project B", () => call("PUT", `/apps/${X}/owner`, owner.token, { userId: outsider.id }), refused);
const orgGrant = (await call("POST", `/apps/${X}/grants`, owner.token, { principalType: "org", principalId: ORG, level: "view" })).b;
await attack("Someone limited to project B", "opens a project A dashboard shared with everyone", () => call("GET", `/apps/${X}`, outsider.token), refused);
await call("DELETE", `/apps/${X}/grants/${orgGrant.id}`, owner.token);
await attack("An Admin limited to project A", "opens project B", () => call("GET", `/orgs/${ORG}/projects/${B}`, limitedAdmin.token), refused);
await attack("An Admin limited to project A", "creates someone with every project", () => call("POST", `/orgs/${ORG}/users`, limitedAdmin.token, { email: `sim.z.${stamp}@example.com`, name: "Z", password: PASSWORD, projectScope: "all" }), refused);
await attack("An Admin limited to project A", "gives someone project B", () => call("PUT", `/orgs/${ORG}/users/${member.id}`, limitedAdmin.token, { projectScope: "selected", projectIds: [B] }), refused);

console.log("\nRoles on a project and its data sources");
const projectGrant = (await call("POST", `/projects/${A}/grants`, owner.token, { principalType: "user", principalId: analyst.id, level: "view" })).b;
await attack("A project Viewer", "shares the project", () => call("POST", `/projects/${A}/grants`, analyst.token, { principalType: "user", principalId: member.id, level: "manage" }), refused);
await attack("A project Viewer", "reads who has access to the project", () => call("GET", `/projects/${A}/access`, analyst.token), refused);
await attack("A project Viewer", "asks why someone else has access", () => call("GET", `/projects/${A}/access/explain?userId=${owner.id}`, analyst.token), refused);
await call("POST", `/projects/${A}/sources/sim-${stamp}/grants`, owner.token, { principalType: "user", principalId: analyst.id, level: "manage" });
await attack("A data source Manager", "manages the whole project's access", () => call("GET", `/projects/${A}/grants`, analyst.token), refused);
await call("DELETE", `/projects/${A}/grants/${projectGrant.id}`, owner.token);

console.log('\nNarrowing one person\'s share ("Editor, but not delete"), without a new role');
const W = await newApp("Shared");
const shareW = (principalId, level, token = owner.token) => call("POST", `/apps/${W}/grants`, token, { principalType: "user", principalId, level });
const denyW = (token, principalType, principalId, action) => call("POST", `/apps/${W}/denials`, token, { principalType, principalId, action });
const ruleOnW = async (userId, action) => (await call("GET", `/apps/${W}/denials`, owner.token)).b.find((d) => d.principalId === userId && d.action === action);
await shareW(curator.id, "manage");
await shareW(analyst.id, "edit");
await attack("A Manager", "takes delete away from one Editor", () => denyW(curator.token, "user", analyst.id, "delete"), (r) => r.s === 201, { allowed: true });
await attack("That Editor", "deletes the dashboard anyway", () => call("DELETE", `/apps/${W}`, analyst.token), refused);
const restriction = await ruleOnW(analyst.id, "delete");
await attack("That Editor", "lifts the restriction on themselves", () => call("DELETE", `/apps/${W}/denials/${restriction?.id}`, analyst.token), refused);
await attack("A Manager", "takes an action away from themselves", () => denyW(curator.token, "user", curator.id, "delete"), refused);
await attack("A Manager", "restricts an Admin", () => denyW(curator.token, "user", admin1.id, "edit"), refused);
await attack("A Manager", "denies everyone in the organization", () => denyW(curator.token, "org", ORG, "edit"), refused);
await attack("A Manager", "takes View away instead of stopping sharing", () => denyW(curator.token, "user", analyst.id, "view"), refused);
await attack("The Owner", "takes an action away from the dashboard's own owner", () => denyW(owner.token, "user", owner.id, "delete"), refused);
await denyW(owner.token, "user", analyst.id, "edit");
const ownersRule = await ruleOnW(analyst.id, "edit");
await attack("A Manager", "removes the Owner's deny rule", () => call("DELETE", `/apps/${W}/denials/${ownersRule?.id}`, curator.token), refused);
await attack(
  "A Manager",
  "stops sharing and shares again",
  async () => {
    const grant = (await call("GET", `/apps/${W}/grants`, curator.token)).b.grants.find((g) => g.principalId === analyst.id);
    await call("DELETE", `/apps/${W}/grants/${grant.id}`, curator.token);
    return shareW(analyst.id, "edit", curator.token);
  },
  async () => {
    const actions = (await call("GET", `/apps/${W}`, analyst.token)).b?.actions ?? [];
    return actions.includes("delete") && !actions.includes("edit");
  },
  { allowed: true, note: "the Manager's restriction went with the share; the Owner's stayed" }
);

console.log("\nSomeone who does not use the platform only ever views");
const V = await newApp("Viewing");
const shareV = (principalType, principalId, level) => call("POST", `/apps/${V}/grants`, owner.token, { principalType, principalId, level });
await attack("The Owner", "gives a Member Editor on a dashboard", () => shareV("user", member.id, "edit"), refused);
await attack("The Owner", "gives everyone in the organization Editor", () => shareV("org", ORG, "edit"), refused);
await attack("The Owner", "gives a Member View", () => shareV("user", member.id, "view"), (r) => r.s === 201, { allowed: true });

console.log("\nOther doors");
await call("PUT", `/apps/${Y}/status`, owner.token, { status: "disabled" });
await attack("A Viewer", "opens a disabled dashboard", () => call("GET", `/apps/${Y}`, analyst.token), refused);
await attack("Anyone", "opens a dashboard id that is not in their organization", () => call("GET", `/apps/00000000-0000-4000-8000-000000000000`, analyst.token), refused);
await attack("Anyone", "calls the API with no sign-in", () => call("GET", `/orgs/${ORG}/users`, null), refused);
const leaving = await newUser("leaving", "member");
await call("DELETE", `/orgs/${ORG}/users/${leaving.id}`, owner.token);
await attack("A removed member", "keeps using the session they had", () => call("GET", "/auth/me", leaving.token), refused);

console.log("\nAnd what should work still works");
await call("POST", `/apps/${Z}/grants`, owner.token, { principalType: "user", principalId: analyst.id, level: "edit" });
await attack("An Editor", "deletes a dashboard shared with them", () => call("DELETE", `/apps/${Z}`, analyst.token), (r) => r.s === 200, { allowed: true });
made.apps = made.apps.filter((a) => a !== Z);
await attack(
  "An Admin",
  "adds a Member",
  async () => {
    const r = await call("POST", `/orgs/${ORG}/users`, admin1.token, { email: `sim.ok.${stamp}@example.com`, name: "Sim ok", password: PASSWORD });
    if (r.b?.id) made.users.push(r.b.id);
    return r;
  },
  (r) => r.s === 201,
  { allowed: true }
);
await attack(
  "The Owner",
  "creates a role that sees and edits members, with platform access",
  () => tryRole("PeopleLead", ["platform.access", "members.view", "members.edit"]),
  (r) => r.s === 201,
  { allowed: true }
);
await attack(
  "The Owner",
  "lets an Admin see members but change nothing (every Members action limited but View and the log)",
  () => call("PUT", `/orgs/${ORG}/users/${admin2.id}`, owner.token, {
    limits: ["members.create", "members.edit", "members.assign", "members.data_rules", "members.reset_password"],
  }),
  (r) => r.s === 200,
  { allowed: true }
);
await attack("A platform user made Manager of a dashboard", "shares it onward as Manager", async () => {
  await shareX(curator.id, "manage");
  return call("POST", `/apps/${X}/grants`, curator.token, { principalType: "user", principalId: analyst.id, level: "manage" });
}, (r) => r.s === 201, { allowed: true });

// ── Cleanup ─────────────────────────────────────────────────────────────────
for (const a of made.apps) await call("DELETE", `/apps/${a}`, owner.token);
for (const u of made.users) await call("DELETE", `/orgs/${ORG}/users/${u}`, owner.token, { transferTo: owner.id });
for (const r of made.roles) await call("DELETE", `/orgs/${ORG}/roles/${r}`, owner.token);

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length} of ${results.length} held.${failed.length ? ` NOT stopped: ${failed.map((f) => f.n).join(", ")}` : " The hierarchy holds."}`);
process.exit(failed.length ? 1 : 0);
