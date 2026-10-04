import express from "express";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { serveStatic, withBaseHref } from "../vite.js";

const builtIndex = `<!doctype html>
<html lang="en">
  <head>
    <script type="module" crossorigin src="./assets/index-abc.js"></script>
  </head>
  <body><div id="root"></div></body>
</html>`;

describe("withBaseHref", () => {
  it("anchors relative asset URLs at the site root when no base path is set", () => {
    const html = withBaseHref(builtIndex, "");
    // A deep link such as /activity/imports must load /assets/..., not /activity/assets/...
    expect(html).toContain('<head>\n    <base href="/" />');
  });

  it("anchors them at QUESTARR_BASE_PATH behind a reverse proxy", () => {
    const html = withBaseHref(builtIndex, "/Questarr");
    expect(html).toContain('<base href="/Questarr/" />');
    expect(html.indexOf("<base")).toBeLessThan(html.indexOf("./assets/index-abc.js"));
  });
});

describe("serveStatic", () => {
  const distPath = mkdtempSync(path.join(tmpdir(), "questarr-dist-"));
  mkdirSync(path.join(distPath, "assets"));
  writeFileSync(path.join(distPath, "index.html"), builtIndex);
  writeFileSync(path.join(distPath, "assets", "index-abc.js"), "console.log('app');");

  const createApp = () => {
    const app = express();
    serveStatic(app, distPath);
    return app;
  };

  it.each(["/", "/activity/imports"])("serves index.html with the <base> at %s", async (url) => {
    const response = await request(createApp()).get(url);
    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain('<base href="/" />');
  });

  it("still serves built assets as files", async () => {
    const response = await request(createApp()).get("/assets/index-abc.js");
    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("javascript");
  });
});
