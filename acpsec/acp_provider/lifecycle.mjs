// lifecycle.mjs
// Startup banner + graceful shutdown for the provider poll loop.
// Auth-agnostic: knows nothing about signers/SDK — only process lifecycle.

/**
 * Print a one-time startup banner.
 * @param {object} info  Plain key/values to log (NO secrets — caller's responsibility).
 */
export function logStartup(info = {}) {
  const ts = new Date().toISOString();
  console.log(`[provider] starting @ ${ts}`);
  for (const [k, v] of Object.entries(info)) {
    console.log(`[provider]   ${k}: ${v}`);
  }
}

/**
 * Install SIGINT/SIGTERM handlers for graceful shutdown.
 *
 * @param {object} opts
 * @param {() => void}            opts.onStop     Called once on first signal — flip your loop's
 *                                                "keep running" flag to false here.
 * @param {() => boolean}         [opts.isBusy]   Returns true while a job is in flight. Shutdown
 *                                                polls this and waits for it to clear before exit.
 * @param {() => Promise<void>}   [opts.cleanup]  Optional async teardown (close clients, flush).
 * @param {number}                [opts.graceMs]  Max ms to wait for isBusy to clear (default 30000).
 * @param {number}                [opts.pollMs]   How often to re-check isBusy (default 250).
 */
export function installGracefulShutdown({
  onStop,
  isBusy = () => false,
  cleanup = async () => {},
  graceMs = 30_000,
  pollMs = 250,
}) {
  let shuttingDown = false;

  const handle = async (signal) => {
    if (shuttingDown) {
      // Second signal — operator is impatient. Exit now.
      console.log(`[provider] ${signal} again — forcing exit.`);
      process.exit(1);
    }
    shuttingDown = true;
    console.log(`[provider] ${signal} received — stopping after current job…`);

    try {
      onStop(); // tell the loop to stop accepting new work
    } catch (e) {
      console.error(`[provider] onStop threw: ${e?.message ?? e}`);
    }

    // Wait for the in-flight job to finish, up to graceMs.
    const deadline = Date.now() + graceMs;
    while (isBusy() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, pollMs));
    }
    if (isBusy()) {
      console.warn(`[provider] job still running after ${graceMs}ms — exiting anyway.`);
    }

    try {
      await cleanup();
    } catch (e) {
      console.error(`[provider] cleanup threw: ${e?.message ?? e}`);
    }

    console.log(`[provider] stopped cleanly @ ${new Date().toISOString()}`);
    process.exit(0);
  };

  process.on('SIGINT', () => handle('SIGINT'));   // Ctrl-C
  process.on('SIGTERM', () => handle('SIGTERM')); // kill / container stop
}
