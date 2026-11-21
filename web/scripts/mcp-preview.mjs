import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createPreviewMcp } from "../src/lib/preview-mcp.mjs";

await createPreviewMcp().connect(new StdioServerTransport());
