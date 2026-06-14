import Anthropic from "@anthropic-ai/sdk";
import { KeyRunnerSDK } from "@launchiamenterprise/keyrunner-agentic-security";
import * as dotenv from "dotenv";
import * as http from "http";
import * as readline from "readline";

dotenv.config();

const anthropic = new Anthropic();
const kr = new KeyRunnerSDK();

let tools: Anthropic.Tool[] = [];
let ready = false;
let initError: string | null = null;

const PORT = parseInt(process.env.PORT ?? "3000", 10);

// ---------------------------------------------------------------------------
// Agent loop — returns the final text response
// ---------------------------------------------------------------------------

async function runAgent(userMessage: string, tools: Anthropic.Tool[]): Promise<string> {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`You: ${userMessage}`);
  console.log("─".repeat(60));

  const messages: Anthropic.MessageParam[] = [
    {
      role: "user",
      content: `The user said: "${userMessage}"\n\nDecide which Slack channel this belongs to and send it there.`,
    },
  ];

  while (true) {
    const response = await anthropic.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      tools,
      messages,
    });

    if (response.stop_reason === "end_turn") {
      const text = response.content
        .filter((b): b is Anthropic.TextBlock => b.type === "text")
        .map((b) => b.text.trim())
        .filter(Boolean)
        .join("\n");
      if (text) console.log(`\nAgent: ${text}`);
      console.log("─".repeat(60));
      return text;
    }

    if (response.stop_reason === "tool_use") {
      const thinkingText = response.content
        .filter((b): b is Anthropic.TextBlock => b.type === "text" && b.text.trim().length > 0)
        .map((b) => b.text.trim())
        .join("\n");
      // Fall back to the user's original message so the audit always has context
      const llmDirective = thinkingText || `User: ${userMessage}`;

      if (thinkingText) console.log(`\n[thinking] ${thinkingText}`);

      messages.push({ role: "assistant", content: response.content });
      const toolResults: Anthropic.ToolResultBlockParam[] = [];

      for (const block of response.content) {
        if (block.type !== "tool_use") continue;

        console.log(`\n[tool]   ${block.name}`);
        console.log(`[args]   ${JSON.stringify(block.input)}`);

        try {
          const result = await kr.execute(block.name, block.input as Record<string, unknown>, { llmDirective });
          console.log(`[status] ${result.status}`);
          // console.log(`[result] ${result.body}`);
          toolResults.push({ type: "tool_result", tool_use_id: block.id, content: result.body });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`[error]  ${msg}`);
          toolResults.push({ type: "tool_result", tool_use_id: block.id, content: msg, is_error: true });
        }
      }

      messages.push({ role: "user", content: toolResults });
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP server — POST /chat, GET /health
// ---------------------------------------------------------------------------

function startHttpServer(): void {
  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") {
      // Liveness: always 200 so k8s doesn't restart the pod during slow SDK init
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", ready, initError }));
      return;
    }

    if (req.method === "POST" && req.url === "/chat") {
      if (!ready) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: initError ?? "SDK not ready yet" }));
        return;
      }
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", async () => {
        try {
          const { message } = JSON.parse(body) as { message?: string };
          if (!message) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "message is required" }));
            return;
          }
          const reply = await runAgent(message, tools);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ reply }));
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: msg }));
        }
      });
      return;
    }

    res.writeHead(404);
    res.end();
  });

  server.listen(PORT, () => {
    console.log(`[server] Listening on :${PORT}  — POST /chat  GET /health`);
  });
}

// ---------------------------------------------------------------------------
// Local REPL — only when running interactively (not in k8s)
// ---------------------------------------------------------------------------

function startRepl(): void {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const prompt = (): void => {
    rl.question("\nYou: ", async (input) => {
      const message = input.trim();
      if (!message) { prompt(); return; }
      if (message.toLowerCase() === "exit") {
        kr.destroy();
        rl.close();
        return;
      }
      await runAgent(message, tools);
      prompt();
    });
  };

  console.log('\nAgent ready. Type a message and press Enter. Type "exit" to quit.');
  prompt();
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // Start HTTP server immediately so health probes pass during SDK init
  startHttpServer();

  try {
    console.log("[KeyRunner] Initializing SDK...");
    await kr.init();
    console.log("[KeyRunner] SDK ready.");

    const applyTools = (krTools: Awaited<ReturnType<typeof kr.getTools>>) => {
      tools = krTools.map((t) => ({
        name: t.name,
        description: t.description,
        input_schema: t.inputSchema as Anthropic.Tool["input_schema"],
      }));
      ready = tools.length > 0;
      initError = tools.length === 0 ? "No tools available — assign policies in the KeyRunner UI" : null;
      console.log(`[KeyRunner] Tools updated (${tools.length}): ${tools.map((t) => t.name).join(", ") || "none"}`);
    };

    const krTools = await kr.getTools();
    applyTools(krTools);

    // Keep tools in sync whenever the UI adds/removes tools or policies
    kr.onToolsChanged(applyTools);

    if (process.stdin.isTTY && ready) {
      startRepl();
    }
  } catch (err) {
    initError = err instanceof Error ? err.message : String(err);
    console.error("[KeyRunner] Init failed:", initError);
    // Don't exit — keep the HTTP server alive so /health stays up
    // and logs are visible via kubectl logs
  }
}

main().catch((err) => {
  console.error("[Fatal]", err);
  process.exit(1);
});
