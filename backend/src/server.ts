import { config } from "./config";

console.log("Running in:", config.NODE_ENV);
console.log("Database path:", config.DB_PATH);
console.log("API port:", config.API_PORT);