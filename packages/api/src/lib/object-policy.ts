/** Actions on a shared project, app, or data source. */
export const OBJECT_ACTIONS = ["view", "create", "edit", "delete", "share", "disable", "handover"] as const;
export type ObjectAction = (typeof OBJECT_ACTIONS)[number];

export const BUILTIN_ACTIONS = {
  view: ["view"],
  edit: ["view", "create", "edit", "delete"],
  manage: ["view", "create", "edit", "delete", "share", "disable"],
  owner: OBJECT_ACTIONS,
} as const satisfies Record<string, readonly ObjectAction[]>;
export type BuiltinLevel = keyof typeof BUILTIN_ACTIONS;

export function isObjectAction(value: unknown): value is ObjectAction {
  return typeof value === "string" && (OBJECT_ACTIONS as readonly string[]).includes(value);
}

/** Grants add actions; an explicit deny removes an action even from an owner or admin. */
export function effectiveActions(allows: Iterable<ObjectAction>, denies: Iterable<ObjectAction>): ObjectAction[] {
  const allowed = new Set(allows);
  const denied = new Set(denies);
  if (denied.has("view") || !allowed.has("view")) return [];
  return OBJECT_ACTIONS.filter((action) => allowed.has(action) && !denied.has(action));
}

/** A compatibility summary for clients still reading `level`. Check `actions` for decisions. */
export function levelForActions(actions: readonly ObjectAction[]): BuiltinLevel | null {
  if (!actions.includes("view")) return null;
  // Old clients treat a level as the whole built-in action set. Report only
  // a level whose complete set is present, so a partial custom role cannot
  // accidentally appear to have delete access in those clients.
  if (BUILTIN_ACTIONS.owner.every((action) => actions.includes(action))) return "owner";
  if (BUILTIN_ACTIONS.manage.every((action) => actions.includes(action))) return "manage";
  if (BUILTIN_ACTIONS.edit.every((action) => actions.includes(action))) return "edit";
  return "view";
}
