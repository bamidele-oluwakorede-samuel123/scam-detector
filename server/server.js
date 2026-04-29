// server.js
// Application entry point.
// Connects to the database FIRST, then starts the HTTP server.
// ORDER MATTERS: If we start the server before the DB is ready,
// requests that arrive in that window would fail with DB errors.
// Awaiting connectDB() ensures we're ready before accepting traffic.

import connectDB from "./database/connection.js";
import app from "./app.js";
import aiConfig from "./config/aiConfig.js";

const startServer = async () => {
  // Connect to MongoDB first
  await connectDB();

  // Then start listening for HTTP requests
  app.listen(aiConfig.port, () => {
    console.log(`🚀 Server running on http://localhost:${aiConfig.port}`);
    console.log(`📊 API ready at http://localhost:${aiConfig.port}/api`);
  });
};

startServer();