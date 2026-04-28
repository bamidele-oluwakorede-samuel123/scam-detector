// connection.js
// Establishes and manages the MongoDB connection using Mongoose.
// Mongoose is an ODM (Object Document Mapper) — it lets us define
// schemas and interact with MongoDB using JavaScript objects
// instead of raw database queries.

import mongoose from "mongoose";
import aiConfig from "../config/aiConfig.js";

const connectDB = async () => {
  try {
    // mongoose.connect() returns a promise — we await it.
    // If the connection fails, the catch block handles it.
    const conn = await mongoose.connect(aiConfig.mongoUri);

    console.log(`✅ MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ MongoDB connection failed: ${error.message}`);

    // Exit the process with failure code (1).
    process.exit(1);
  }
};

export default connectDB;