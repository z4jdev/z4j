/**
 * z4j E2E - MFA (TOTP) full lifecycle.
 *
 * The single highest-consequence auth flow the product ships: a user
 * turns on two-factor auth, gets locked to it on the next login, and
 * turns it back off. Every step is driven through the real dashboard
 * UI against a live brain, exactly the way an operator experiences it.
 *
 * Scenario (one cohesive session so the enrolled state is never left
 * dangling on the shared bootstrap admin):
 *
 *   1. Enroll   - Settings > Security: start enrollment, read the
 *                 secret the brain issued, submit a valid TOTP code,
 *                 capture the one-time recovery codes.
 *   2. Gate     - sign out, sign back in with the password ONLY, and
 *                 assert the app routes to the second-factor prompt
 *                 instead of the dashboard.
 *   3. Verify   - submit a fresh TOTP code on the prompt and assert
 *                 access is restored.
 *   4. Disable  - Settings > Security: disable MFA with password +
 *                 a fresh code, returning the admin to its clean
 *                 (no-MFA) starting state.
 *
 * The valid codes come from ``./totp`` - a stdlib-only RFC 6238
 * generator (no otplib) computed against the exact secret the brain
 * shows during enrollment, so this never touches a real phone. Codes
 * are computed at the moment of submission and re-rolled away from a
 * 30s step boundary (and away from any step already spent) so the
 * brain's +/-1 window and single-use anti-replay never flake the run.
 */
import type { Page } from "@playwright/test";
import { test, expect, ADMIN_EMAIL, ADMIN_PASSWORD } from "./fixtures";
import { totpAt, type TotpToken, TOTP_STEP_SECONDS } from "./totp";

const STEP_MS = TOTP_STEP_SECONDS * 1000;

/**
 * Compute a TOTP code that is safe to submit right now:
 *
 *  - not within ~2.5s of a 30s step boundary, so it cannot expire
 *    between compute and submit, and
 *  - not from a step we have already spent (``avoidCounter``), since
 *    the brain single-uses each step for anti-replay and would reject
 *    a re-presented code exactly like a wrong one.
 *
 * When the current window fails either test we wait just past the next
 * boundary (into a clean window) and recompute. At most one ~30s wait
 * is ever needed.
 */
async function freshTotp(
  page: Page,
  secretBase32: string,
  opts: { avoidCounter?: number } = {},
): Promise<TotpToken> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const nowMs = Date.now();
    const msToBoundary = STEP_MS - (nowMs % STEP_MS);
    const token = totpAt(secretBase32, nowMs);
    const tooCloseToBoundary = msToBoundary < 2500;
    const alreadySpent = token.counter === opts.avoidCounter;
    if (!tooCloseToBoundary && !alreadySpent) {
      return token;
    }
    // Roll into the next window (plus a small margin past the edge).
    await page.waitForTimeout(msToBoundary + 750);
  }
  // Should be unreachable; return a best-effort code rather than hang.
  return totpAt(secretBase32);
}

test.describe("mfa - TOTP lifecycle", () => {
  // Enrollment + two boundary-safe code waits can each cost up to a
  // 30s step; give the whole lifecycle comfortable headroom.
  test.setTimeout(180_000);

  test("enroll, gate on re-login, verify, disable", async ({ adminPage }) => {
    // ---------------------------------------------------------------
    // 1. ENROLL via Settings > Security
    // ---------------------------------------------------------------
    await adminPage.goto("/settings/security");
    await expect(
      adminPage.getByRole("heading", { name: /two-factor authentication/i }).first(),
    ).toBeVisible();

    // Clicking "Set up..." fires POST /auth/mfa/enroll-start. Capture
    // the response so we get the EXACT secret the brain stored as the
    // pending enrollment - the QR/secret shown on screen encodes this
    // same value, so the code we compute will verify.
    const enrollStartResponse = adminPage.waitForResponse(
      (r) =>
        r.url().includes("/auth/mfa/enroll-start") &&
        r.request().method() === "POST",
    );
    await adminPage
      .getByRole("button", { name: /set up two-factor authentication/i })
      .click();
    const secretBase32 = (
      (await (await enrollStartResponse).json()) as { secret_base32: string }
    ).secret_base32;
    expect(secretBase32).toMatch(/^[A-Z2-7]+$/);

    // The scan step is now showing; the 6-digit confirm field appears.
    const enrollCodeField = adminPage.getByLabel(
      /enter the 6-digit code from your app/i,
    );
    await expect(enrollCodeField).toBeVisible();

    const enrollToken = await freshTotp(adminPage, secretBase32);
    await enrollCodeField.fill(enrollToken.code);
    await adminPage
      .getByRole("button", { name: /confirm and activate/i })
      .click();

    // Enrollment succeeded => the recovery-codes panel renders once.
    await expect(
      adminPage.getByText(/save your recovery codes/i),
    ).toBeVisible();
    const codeCells = await adminPage.locator("code").allInnerTexts();
    const recoveryCodes = codeCells
      .map((t) => t.trim())
      .filter((t) => /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/i.test(t));
    // The brain mints 10 recovery codes by default; assert we captured
    // a full, single-use set rather than an empty/partial render.
    expect(recoveryCodes.length).toBe(10);

    // ---------------------------------------------------------------
    // 2. GATE - sign out, then sign in with the PASSWORD ONLY
    // ---------------------------------------------------------------
    await adminPage.getByRole("button", { name: /user menu/i }).click();
    await adminPage.getByRole("menuitem", { name: /sign out/i }).click();
    await expect(adminPage).toHaveURL(/\/login(\/|\?|$)/, { timeout: 10_000 });

    await adminPage.getByLabel(/email/i).fill(ADMIN_EMAIL);
    await adminPage
      .getByRole("textbox", { name: /password/i })
      .fill(ADMIN_PASSWORD);
    await adminPage.getByRole("button", { name: /sign in/i }).click();

    // Password alone must NOT land on the dashboard: the brain reports
    // mfa_required and the app routes to the second-factor prompt.
    await expect(adminPage).toHaveURL(/\/login\/mfa/, { timeout: 10_000 });
    await expect(
      adminPage.getByRole("heading", { name: /two-factor verification/i }),
    ).toBeVisible();

    // ---------------------------------------------------------------
    // 3. VERIFY - a fresh TOTP code restores access
    // ---------------------------------------------------------------
    const verifyToken = await freshTotp(adminPage, secretBase32);
    await adminPage.locator("#mfa-code").fill(verifyToken.code);
    await adminPage.getByRole("button", { name: /verify/i }).click();

    // Landed somewhere authenticated (index redirects to /home or the
    // single project), and the app chrome (user menu) is present.
    await expect(adminPage).toHaveURL(/\/(home|projects\/)/, {
      timeout: 10_000,
    });
    await expect(
      adminPage.getByRole("button", { name: /user menu/i }),
    ).toBeVisible();

    // ---------------------------------------------------------------
    // 4. DISABLE - password + a fresh code, then confirm MFA is off
    // ---------------------------------------------------------------
    await adminPage.goto("/settings/security");
    await expect(
      adminPage.getByText(/two-factor authentication is on/i),
    ).toBeVisible();

    await adminPage
      .getByRole("button", { name: /disable two-factor authentication/i })
      .click();
    const disableDialog = adminPage.getByRole("dialog");
    await disableDialog.getByLabel(/password/i).fill(ADMIN_PASSWORD);
    // A DIFFERENT step from the one the login verify just consumed, so
    // the brain's single-use anti-replay never rejects it.
    const disableToken = await freshTotp(adminPage, secretBase32, {
      avoidCounter: verifyToken.counter,
    });
    await disableDialog.locator("#disable-code").fill(disableToken.code);
    await disableDialog
      .getByRole("button", { name: "Disable", exact: true })
      .click();

    // Disable reloads the page; the enroll CTA returning proves MFA is
    // back off and the shared admin is left in its clean starting state.
    await expect(
      adminPage.getByRole("button", {
        name: /set up two-factor authentication/i,
      }),
    ).toBeVisible({ timeout: 15_000 });
  });
});
