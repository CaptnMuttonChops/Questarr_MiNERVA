import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * Redirects plain-HTTP requests to the HTTPS listener once one is running.
 *
 * The HTTPS server only starts after its certificates are validated, well after
 * every route (and the SPA catch-all) is registered, so this middleware has to
 * be installed up front and switched on later: `getHttpsPort` returns the port
 * to redirect to, or null while redirection is off.
 */
export function createHttpsRedirect(getHttpsPort: () => number | null): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const httpsPort = getHttpsPort();
    if (httpsPort === null || req.secure || req.path === "/api/health") {
      return next();
    }
    // Validate hostname to prevent an open redirect via a crafted Host header.
    const rawHostname = req.hostname;
    const safeHostname = /^[a-zA-Z0-9.\-[\]]+$/.test(rawHostname) ? rawHostname : "localhost";
    // originalUrl keeps the base path (QUESTARR_BASE_PATH) and the query string.
    return res.redirect(`https://${safeHostname}:${httpsPort}${req.originalUrl}`);
  };
}
