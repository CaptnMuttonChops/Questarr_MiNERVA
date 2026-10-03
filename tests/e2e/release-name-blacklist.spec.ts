import { test, expect } from "@playwright/test";
import { uniqueId } from "./helpers";

test.describe("Release name blacklist journey", () => {
  test("saves case-insensitive terms and lets the user remove them again", async ({ page }) => {
    const term = `E2E-BLACKLIST-${uniqueId()}`;

    await page.goto("/settings");
    await page.getByRole("tab", { name: "Discovery & Downloads" }).click();

    const blacklistInput = page.getByLabel("Blacklisted Terms");
    await blacklistInput.fill(term.toLowerCase());
    await blacklistInput.press("Enter");
    await expect(page.getByText(term.toLowerCase(), { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Save Blacklist" }).click();
    await expect(page.getByText("Release Name Blacklist Saved", { exact: true })).toBeVisible();

    // Assert the server persisted the term, rather than only updating the local badge.
    const savedSettings = await page.request.get("/api/settings");
    expect(savedSettings.ok()).toBe(true);
    expect((await savedSettings.json()).releaseNameBlacklist).toBe(
      JSON.stringify([term.toLowerCase()])
    );

    await page.getByRole("button", { name: `Remove ${term.toLowerCase()}` }).click();
    await expect(page.getByText(term.toLowerCase(), { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Save Blacklist" }).click();
    await expect(page.getByText("Release Name Blacklist Saved", { exact: true })).toBeVisible();

    const clearedSettings = await page.request.get("/api/settings");
    expect(clearedSettings.ok()).toBe(true);
    expect((await clearedSettings.json()).releaseNameBlacklist).toBe("[]");
  });
});
