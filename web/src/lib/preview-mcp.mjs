import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { inspectExample, previewAddress } from "./preview.mjs";

export function createPreviewMcp() {
  const server = new McpServer(
    { name: "rookstride-preview", version: "0.0.2" },
    {
      instructions:
        "Read-only fixture tools. No server is contacted and no operation can execute. Never request or include credentials. Use get_capabilities before inspect_example; explain example results as proposed behavior, not completed checks.",
    },
  );
  const annotations = {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  };
  const result = (data) => ({
    content: [{ type: "text", text: JSON.stringify(data) }],
    structuredContent: data,
  });
  server.registerTool(
    "get_capabilities",
    {
      title: "Rookstride preview capabilities",
      description:
        "List the actual capabilities and limits of the fixture preview.",
      inputSchema: z.object({}).strict(),
      annotations,
    },
    async () =>
      result({
        mode: "fixture",
        serverContacted: false,
        executionAvailable: false,
        address: previewAddress,
        scenarios: ["fresh", "existing", "unreachable", "changed-key"],
        credentialInput: false,
      }),
  );
  server.registerTool(
    "inspect_example",
    {
      title: "Inspect an example server",
      description:
        "Show a simulated fresh, occupied, unreachable or changed-identity inspection. Only the reserved example address is allowed. Never include secrets.",
      inputSchema: z
        .object({
          address: z.literal(previewAddress),
          scenario: z.enum(["fresh", "existing", "unreachable", "changed-key"]),
        })
        .strict(),
      annotations,
    },
    async (input) => result(inspectExample(input)),
  );
  return server;
}
