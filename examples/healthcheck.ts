// Connectivity check — verifies your SDK key authenticates and the WebSocket
// connects, without needing a registered service or any on-chain funds.
//   npm run health
import "dotenv/config";
import { AgentClient } from "@croo-network/sdk";
import { safeLogger } from "../src/log.js";

const client = new AgentClient(
  {
    baseURL: process.env.CROO_API_URL ?? "https://api.croo.network",
    wsURL: process.env.CROO_WS_URL ?? "wss://api.croo.network/ws",
    rpcURL: process.env.BASE_RPC_URL,
    logger: safeLogger,
  },
  process.env.CROO_SDK_KEY ?? "",
);

let ok = true;

try {
  const orders = await client.listOrders({ role: "provider" });
  console.log(`✓ auth OK — listOrders returned ${orders.length} order(s)`);
} catch (e) {
  ok = false;
  console.error("✗ auth / listOrders failed:", (e as Error).message);
}

try {
  const stream = await client.connectWebSocket();
  console.log("✓ websocket connected");
  stream.close();
} catch (e) {
  ok = false;
  console.error("✗ websocket failed:", (e as Error).message);
}

console.log(ok ? "\nHEALTHY — provider is ready to accept orders once a service is listed." : "\nUNHEALTHY — see errors above.");
process.exit(ok ? 0 : 1);
