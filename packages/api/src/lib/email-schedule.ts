/**
 * Email schedules, same shape as report schedules (sa-platform-ui ScheduleReportDialog):
 * a frequency plus local time in the admin's time zone. nextRun() turns that into a UTC instant.
 */

export type Frequency = "once" | "daily" | "weekly" | "monthly" | "quarterly" | "yearly";

export interface EmailSchedule {
  frequency: Frequency;
  /** "HH:mm", local to `timezone`. */
  time: string;
  timezone: string;
  /** "YYYY-MM-DD" (once). */
  scheduledDate?: string;
  /** "monday".."sunday" (weekly). */
  dayOfWeek?: string;
  /** "1".."28" or "last" (monthly, quarterly, yearly). */
  dayOfMonth?: string;
  /** "1".."3" (quarterly). */
  monthOfQuarter?: string;
  /** "1".."12" (yearly). */
  monthOfYear?: string;
}

const DAYS = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
const FREQUENCIES: Frequency[] = ["once", "daily", "weekly", "monthly", "quarterly", "yearly"];

function validTimezone(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** Normalises a client-sent schedule; null when invalid. Keeps only the fields its frequency uses. */
export function parseSchedule(raw: unknown): EmailSchedule | null {
  const s = raw as Partial<Record<keyof EmailSchedule, unknown>> | null;
  if (!s || typeof s !== "object") return null;
  const frequency = s.frequency as Frequency;
  if (!FREQUENCIES.includes(frequency)) return null;
  if (typeof s.time !== "string" || !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time)) return null;
  if (typeof s.timezone !== "string" || !validTimezone(s.timezone)) return null;
  const out: EmailSchedule = { frequency, time: s.time, timezone: s.timezone };

  if (frequency === "once") {
    if (typeof s.scheduledDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s.scheduledDate)) return null;
    out.scheduledDate = s.scheduledDate;
  }
  if (frequency === "weekly") {
    if (typeof s.dayOfWeek !== "string" || !DAYS.includes(s.dayOfWeek)) return null;
    out.dayOfWeek = s.dayOfWeek;
  }
  if (frequency === "monthly" || frequency === "quarterly" || frequency === "yearly") {
    const d = s.dayOfMonth;
    if (d !== "last" && !(typeof d === "string" && /^\d+$/.test(d) && +d >= 1 && +d <= 28)) return null;
    out.dayOfMonth = d;
  }
  if (frequency === "quarterly") {
    if (!["1", "2", "3"].includes(s.monthOfQuarter as string)) return null;
    out.monthOfQuarter = s.monthOfQuarter as string;
  }
  if (frequency === "yearly") {
    const m = s.monthOfYear;
    if (!(typeof m === "string" && /^\d+$/.test(m) && +m >= 1 && +m <= 12)) return null;
    out.monthOfYear = m;
  }
  return out;
}

export const isRecurring = (s: EmailSchedule | null | undefined): boolean => !!s && s.frequency !== "once";

/** ms to add to a UTC instant to get the wall-clock time in `tz` at that instant. */
function tzOffset(t: number, tz: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    hourCycle: "h23",
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "numeric",
    minute: "numeric",
    second: "numeric",
  }).formatToParts(new Date(t));
  const get = (type: string) => Number(parts.find((p) => p.type === type)!.value);
  return Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second")) - (t - (t % 1000));
}

/** The UTC instant of a wall-clock time in `tz`; DST-correct by re-checking the offset. */
function zonedToUtc(y: number, m: number, d: number, h: number, mi: number, tz: string): number {
  const wall = Date.UTC(y, m - 1, d, h, mi);
  const first = wall - tzOffset(wall, tz);
  return wall - tzOffset(first, tz);
}

function matches(s: EmailSchedule, y: number, m: number, d: number): boolean {
  const lastDay = new Date(Date.UTC(y, m, 0)).getUTCDate();
  const dayOk = () => (s.dayOfMonth === "last" ? d === lastDay : d === Number(s.dayOfMonth));
  switch (s.frequency) {
    case "daily":
      return true;
    case "weekly":
      return DAYS[new Date(Date.UTC(y, m - 1, d)).getUTCDay()] === s.dayOfWeek;
    case "monthly":
      return dayOk();
    case "quarterly":
      return String(((m - 1) % 3) + 1) === s.monthOfQuarter && dayOk();
    case "yearly":
      return String(m) === s.monthOfYear && dayOk();
    default:
      return false;
  }
}

/** First run strictly after `after`, or null (a past "once", or nothing within ~13 months). */
export function nextRun(s: EmailSchedule, after: Date): Date | null {
  const [h, mi] = s.time.split(":").map(Number);
  if (s.frequency === "once") {
    const [y, m, d] = s.scheduledDate!.split("-").map(Number);
    const t = zonedToUtc(y, m, d, h, mi, s.timezone);
    return t > after.getTime() ? new Date(t) : null;
  }
  // Walk local calendar days from "today" in the schedule's zone.
  const local = new Date(after.getTime() + tzOffset(after.getTime(), s.timezone));
  for (let i = 0; i <= 400; i++) {
    const day = new Date(Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() + i));
    const [y, m, d] = [day.getUTCFullYear(), day.getUTCMonth() + 1, day.getUTCDate()];
    if (!matches(s, y, m, d)) continue;
    const t = zonedToUtc(y, m, d, h, mi, s.timezone);
    if (t > after.getTime()) return new Date(t);
  }
  return null;
}
