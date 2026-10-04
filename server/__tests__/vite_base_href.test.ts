import { describe, expect, it } from "vitest";
import { withBaseHref } from "../vite.js";

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
