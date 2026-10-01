'use strict';
// Trusted and hash-pinned. Node runs this before the Pi entrypoint, including
// before any extension/provider/repository code. Any failure aborts startup.
const guard = require('/guard/guard.node');
if (guard.sealed !== true) throw new Error('Native Lumen confinement is unavailable');
