import { listSites, insertCheck } from './db.js';
import { checkSite } from './monitor.js';

// Runs a check on every monitored site once and stores the results.
export async function runAllChecks() {
  const sites = listSites();
  const results = await Promise.all(
    sites.map(async (site) => {
      const result = await checkSite(site.url);
      insertCheck(site.id, result);
      return { id: site.id, url: site.url, ok: result.ok };
    })
  );
  return results;
}

// Starts periodic checks. Returns a stop() function. Disabled unless an
// interval is configured, so the default behaviour stays on-demand.
export function startScheduler({ intervalMs, onError = () => {} } = {}) {
  const tick = () => runAllChecks().catch(onError);
  tick(); // run once at startup
  const timer = setInterval(tick, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
