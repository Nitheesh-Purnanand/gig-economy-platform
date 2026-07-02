// Wraps an async controller so any thrown error/rejected promise
// automatically calls next(err) instead of crashing the process.
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = asyncHandler;