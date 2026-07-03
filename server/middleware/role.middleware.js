// Our custom error class — same one used in verifyToken.
// Handles (statusCode, message) so Express's error handler can respond correctly.
const ApiError = require('../utils/ApiError'); // adjust path as needed

// requireRole is a FACTORY function, not middleware itself.
// It takes the allowed roles as arguments and RETURNS a middleware function.
// This is what lets it be called like: requireRole('client', 'freelancer')
// instead of a fixed-argument version that could only ever check one thing.
//
// `...allowedRoles` (rest params) collects every argument passed in
// into a single array. So:
//   requireRole('client')                 -> allowedRoles = ['client']
//   requireRole('client', 'freelancer')   -> allowedRoles = ['client', 'freelancer']
function requireRole(...allowedRoles) {
  // This inner function is the ACTUAL Express middleware — it matches the
  // standard (req, res, next) signature Express expects. The outer
  // requireRole() call happens once, at route-definition time, to configure
  // which roles are allowed; this inner function runs once PER REQUEST.
  return (req, res, next) => {
    // Step 4: Defensive check — req.user should already exist because
    // verifyToken ran earlier in the middleware chain and attached it.
    // If req.user is missing entirely, that means requireRole was used
    // WITHOUT verifyToken running first — a bug in how routes were wired up,
    // not something the client did wrong.
    //
    // We use 500 here (not 401) because this isn't a client auth failure —
    // the client might have sent a perfectly valid token, but the server
    // route itself is misconfigured (missing verifyToken in the chain).
    // That's our bug to fix, not something the user can correct by
    // logging in again.
    if (!req.user) {
      console.error(
        'requireRole used without verifyToken running first — req.user is missing'
      );
      return next(
        new ApiError(500, 'Server error: authorization misconfigured')
      );
    }

    // Step 5: Check whether the authenticated user's role is one of the
    // roles this route allows. `.includes()` checks membership in the array.
    //
    // Example: allowedRoles = ['client', 'freelancer'], req.user.role = 'admin'
    // -> 'admin' is not in the array -> access denied.
    if (!allowedRoles.includes(req.user.role)) {
      // 403 Forbidden, NOT 401 Unauthorized.
      // The distinction matters:
      // - 401 means "I don't know who you are" (missing/invalid credentials).
      // - 403 means "I know exactly who you are — you're just not allowed
      //   to do this." The user is authenticated (verifyToken already
      //   confirmed their token is valid), they just lack permission.
      return next(new ApiError(403, 'You do not have permission to perform this action'));
    }

    // Step 6: The user's role is allowed — proceed to the next
    // middleware or the actual route handler.
    next();
  };
}

// Export the factory function so routes can use it like:
//   router.post('/gigs', verifyToken, requireRole('client'), createGigHandler)
//   router.get('/admin', verifyToken, requireRole('admin'), adminHandler)
module.exports = requireRole;