/** The graph must stay a DAG — checked on link save and at publish; engines also stop at MAX_DEPTH. */

export const MAX_DEPTH = 64;

export type NodeLink = { parentId: number; childId: number };

export type GraphCheck =
  | {
      ok: true;
      /** Children before their parents, so hashes can be built bottom-up. */
      order: number[];
      /** Longest path below each node. */
      depth: Map<number, number>;
    }
  | { ok: false; cycle: number[] };

export function analyseGraph(nodeIds: Iterable<number>, links: NodeLink[]): GraphCheck {
  const children = new Map<number, number[]>();
  for (const l of links) {
    const list = children.get(l.parentId);
    if (list) list.push(l.childId);
    else children.set(l.parentId, [l.childId]);
  }

  // 1 = on the current path, 2 = finished.
  const state = new Map<number, 1 | 2>();
  const order: number[] = [];
  const depth = new Map<number, number>();
  const path: number[] = [];
  const found: { cycle: number[] | null } = { cycle: null };

  const visit = (id: number): void => {
    if (found.cycle) return;
    const s = state.get(id);
    if (s === 2) return;
    if (s === 1) {
      found.cycle = [...path.slice(path.indexOf(id)), id];
      return;
    }
    state.set(id, 1);
    path.push(id);
    let d = 0;
    for (const child of children.get(id) ?? []) {
      visit(child);
      if (found.cycle) return;
      d = Math.max(d, (depth.get(child) ?? 0) + 1);
    }
    path.pop();
    state.set(id, 2);
    depth.set(id, d);
    order.push(id);
  };

  for (const id of nodeIds) visit(id);
  // Links can name nodes outside nodeIds (e.g. a just-added child); visit them too.
  for (const l of links) visit(l.childId);

  return found.cycle ? { ok: false, cycle: found.cycle } : { ok: true, order, depth };
}
