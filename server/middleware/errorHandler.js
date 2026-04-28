// errorHandler.js
// Global error handling middleware for Express.
// HOW EXPRESS ERROR MIDDLEWARE WORKS:
// Express identifies error middleware by its 4-parameter signature: (err, req, res, next). When any controller calls next(error),
// Express skips all regular middleware and routes, and jumps directly to this function. This means every controller only needs to call next(error) and this file handles formatting and logging uniformly.


const errorHandler = (err, req, res, next) => {
  // Log the full error stack in development so we can debug easily.
  // In production you'd send this to a logging service instead.
  console.error(`[ERROR] ${err.message}`);
  if (process.env.NODE_ENV !== "production") {
    console.error(err.stack);
  }

  // Determine the HTTP status code:
  // If the error has a statusCode property (set by us), use it.
  // Otherwise default to 500 (Internal Server Error).
  const statusCode = err.statusCode || 500;

  // Send a consistent JSON error response to the frontend.
  // We never expose raw error stacks to the client in production.
  res.status(statusCode).json({
    success: false,
    error: err.message || "An unexpected error occurred.",
    // Only include stack trace in development mode
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
};

export default errorHandler;
