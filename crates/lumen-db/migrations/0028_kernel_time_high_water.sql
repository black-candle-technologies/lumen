-- 0028_kernel_time_high_water.sql: durable monotonic time anchor for
-- lease persistence.
--
-- Lease liveness, purge eligibility, and the boot re-validation
-- self-check all read the wall clock. Once leases survive restarts via
-- retired issuer generations, a backward clock jump before `open` could
-- resurrect expired authority: an expired stored lease would look live
-- again and its retained historical key would still verify it.
--
-- This table records the greatest effective time the kernel has ever
-- acted on, per workspace. At open the kernel refuses to boot when the
-- wall clock has moved backward beyond a small tolerance
-- (`CLOCK_BACKWARD_TOLERANCE_MS` in lumen-server), and otherwise acts on
-- `max(wall clock, high-water mark)`. Within a boot the in-memory mark
-- only moves forward, so no authority decision ever sees time run
-- backward. The mark is public (a timestamp), never secret.

CREATE TABLE kernel_time_high_water(
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE RESTRICT,
 high_water_ms INTEGER NOT NULL CHECK(high_water_ms >= 0),
 PRIMARY KEY(workspace_id)
) STRICT;
