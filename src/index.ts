import { AuthEntrypoint } from "./entrypoint";
import { Env } from "./types";

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    return new Response("Not found", { status: 404 });
  },
};

export { AuthEntrypoint };
