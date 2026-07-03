// Import the jsonwebtoken library — provides jwt.verify() to check
// a token's signature and expiry against our secret.
const jwt = require('jsonwebtoken');

// Our custom error class, presumably something like:
// class ApiError extends Error { constructor(statusCode, message) { ... } }
// Adjust this path to wherever it actually lives in your project.
const ApiError = require('../utils/ApiError'); // adjust path as needed

// Express middleware signature: (req, res, next).
// Middleware doesn't return a response itself — it either calls next()
// to continue to the next handler, or next(err) to hand off to error-handling middleware.
function verifyToken(req, res, next) {
  // HTTP headers are case-insensitive, but Node/Express lowercases them
  // when storing in req.headers, so we look up 'authorization' (lowercase),
  // even though the client sends it as "Authorization".
  const authHeader = req.headers['authorization'];

  // Step 2: If there's no Authorization header at all, authHeader will be
  // undefined. Reject immediately with a 401 (Unauthorized) and a clear message.
  // `return` here stops execution of this function — without it, the code
  // below would still run and crash trying to read properties of undefined.
  if (!authHeader) {
    return next(new ApiError(401, 'No token provided'));
  }

  // Step 3: The expected header format is "Bearer <token>" — one word,
  // one space, then the token. Splitting on a single space gives us
  // an array. For a well-formed header this array has exactly 2 elements:
  // ["Bearer", "<token>"].
  const parts = authHeader.split(' ');

  // Validate the format strictly:
  // - parts.length !== 2   → header wasn't exactly "word space word"
  //                          (e.g. no space at all, or extra spaces/words)
  // - parts[0] !== 'Bearer' → the scheme keyword is missing or wrong
  //                          (e.g. someone sent "Token abc123" or just "abc123")
  // If either condition is true, this is not a valid Bearer header —
  // reject it rather than trying to guess what the client meant.
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return next(new ApiError(401, 'Malformed authorization header'));
  }

  // At this point we know parts has exactly 2 elements and parts[0] is
  // literally "Bearer", so parts[1] is the actual token string.
  const token = parts[1];

  // Step 4 (pre-check): jwt.verify() needs a secret key to check the
  // token's signature. If JWT_SECRET isn't set in the environment
  // (e.g. a missing .env entry or misconfigured deployment), jwt.verify()
  // would throw "secretOrPrivateKey must have a value" — and without this
  // check, that error would fall into the catch block below and get
  // reported to the CLIENT as "Invalid or expired token", hiding a
  // server-side bug behind a client-side-sounding error.
  // We catch it here explicitly and report it correctly as OUR fault (500).
  if (!process.env.JWT_SECRET) {
    // console.error logs to stderr — visible in server logs/monitoring,
    // but never sent to the client. This is for you (the developer) to see.
    console.error('FATAL: JWT_SECRET is not set in environment');
    // 500 = Internal Server Error — signals "this isn't your fault, it's ours,"
    // as opposed to 401 which implies the client did something wrong.
    return next(new ApiError(500, 'Server configuration error'));
  }

  // try/catch is needed here because jwt.verify() doesn't return null or
  // false on failure — it *throws* an exception for any invalid token:
  // expired, tampered signature, malformed structure, wrong secret, etc.
  try {
    // Step 4: Actually verify the token.
    // - token: the string we extracted above
    // - process.env.JWT_SECRET: the secret key used to sign tokens originally;
    //   verify() re-checks the signature against this to confirm the token
    //   wasn't forged or altered, and also checks the 'exp' (expiry) claim.
    // If verification succeeds, jwt.verify() RETURNS the decoded payload
    // (the original data that was signed, e.g. { userId, role, iat, exp }).
    // If it fails for ANY reason, it throws instead of returning — so
    // execution jumps straight to the catch block below.
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Step 5: Attach the decoded payload to req.user. This makes the
    // authenticated user's info available to every downstream handler
    // (e.g. route handlers can read req.user.userId, req.user.role, etc.)
    req.user = decoded;

    // Call next() with NO arguments — this tells Express "everything's fine,
    // proceed to the next middleware/route handler in the chain."
    next();
  } catch (err) {
    // We land here if jwt.verify() threw — could be TokenExpiredError,
    // JsonWebTokenError (bad signature/malformed), NotBeforeError, etc.
    // We log the REAL, specific error message server-side so that if you're
    // debugging later, you can distinguish "token was expired" from
    // "signature was invalid" from something weirder — even though the
    // client only ever sees one generic message (see next line).
    console.error('JWT verification failed:', err.message);

    // Step 6: Report a generic 401 to the client. We deliberately don't
    // leak *why* verification failed (e.g. "expired" vs "tampered") to
    // avoid giving attackers useful information about token internals.
    next(new ApiError(401, 'Invalid or expired token'));
  }
}

// Export the middleware so it can be `require`'d and plugged into routes,
// e.g.: router.get('/profile', verifyToken, profileHandler)
module.exports = verifyToken;