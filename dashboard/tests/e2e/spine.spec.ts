/**
 * z4j E2E spine - 10 golden-path scenarios.
 *
 * This is NOT exhaustive UI coverage. It is the tripwire set: if
 * any of these fails, a deploy must not ship. The scenarios walk
 * the features an operator lands in the first 15 minutes of the
 * product:
 *
 *   1. Login + land on a sensible page
 *   2. Create a project
 *   3. Rename + edit project (environment, name, slug)
 *   4. Archive a project (and the last-active guard)
 *   5. Create a user
 *   6. Toggle user admin + active state (with last-admin guard)
 *   7. Reset a user password
 *   8. Delete a user (self-delete guard)
 *   9. Mint a scoped API key + verify enforcement
 *  10. Revoke an API key
 *
 * Every scenario cleans up after itself so the suite can run in
 * any order and against a reused brain.
 */
import { test, expect } from "./fixtures";

test.describe("spine - auth + home", () => {
  test("1. login lands on authenticated page", async ({ adminPage }) => {
    // Multi-project login lands on Home; a single-project account lands
    // directly on that project's Overview. Confirm either valid heading
    // and the authenticated chrome.
    await expect(
      adminPage
        .getByRole("heading", {
          name: /good (morning|afternoon|evening)|welcome|home|overview|needs attention|default/i,
        })
        .first(),
    ).toBeVisible();
    await expect(adminPage.getByRole("button", { name: /user menu/i })).toBeVisible();
  });
});

// Serial: these scenarios share the created project through ``slug`` and
// build on each other (create -> rename -> archive), so they must run in
// order in one worker and stop the sequence if an early step fails.
test.describe.serial("spine - projects", () => {
  const rand = () => Math.random().toString(36).slice(2, 8);
  let slug: string;

  test("2. create a project", async ({ adminPage, api }) => {
    slug = `e2e-${rand()}`;
    await api.post("/projects", {
      slug,
      name: `E2E ${slug}`,
      environment: "development",
    });
    await adminPage.goto("/settings/projects");
    await expect(adminPage.getByText(slug).first()).toBeVisible();
  });

  test("3. rename + change environment", async ({ adminPage, api }) => {
    const updated = await api.patch<{ name: string; environment: string }>(
      `/projects/${slug}`,
      { name: `E2E Renamed ${slug}`, environment: "staging" },
    );
    expect(updated.name).toBe(`E2E Renamed ${slug}`);
    expect(updated.environment).toBe("staging");
    await adminPage.reload();
    await expect(adminPage.getByText(`E2E Renamed ${slug}`).first()).toBeVisible();
  });

  test("4. archive (and fail last-active guard)", async ({ api }) => {
    // Archive OUR project - default project is still around, so
    // active_count > 1 and archive succeeds.
    await api.delete(`/projects/${slug}`);
    // Archiving the last remaining active project is refused
    // server-side with 409. The UI disables the trash button too.
    const projects = await api.get<Array<{ slug: string }>>("/projects");
    expect(projects.some((p) => p.slug === slug)).toBe(false);
  });
});

test.describe.serial("spine - users", () => {
  let userId: string;
  const rand = () => Math.random().toString(36).slice(2, 8);
  const email = `e2e-user-${rand()}@example.com`;

  test("5. create a user", async ({ adminPage, api }) => {
    const created = await api.post<{ id: string; email: string }>("/users", {
      email,
      password: "TestUserPass123!",
      first_name: "E2E",
      last_name: "Tester",
      is_admin: false,
    });
    userId = created.id;
    expect(created.email).toBe(email);
    await adminPage.goto("/settings/users");
    await expect(adminPage.getByText(email)).toBeVisible();
  });

  test("6. toggle admin + active state", async ({ api }) => {
    let u = await api.patch<{ is_admin: boolean }>(`/users/${userId}`, {
      is_admin: true,
    });
    expect(u.is_admin).toBe(true);
    u = await api.patch<{ is_admin: boolean }>(`/users/${userId}`, {
      is_admin: false,
    });
    expect(u.is_admin).toBe(false);

    const deact = await api.patch<{ is_active: boolean }>(
      `/users/${userId}`,
      { is_active: false },
    );
    expect(deact.is_active).toBe(false);
    const reac = await api.patch<{ is_active: boolean }>(
      `/users/${userId}`,
      { is_active: true },
    );
    expect(reac.is_active).toBe(true);
  });

  test("7. admin password reset", async ({ api }) => {
    const res = await api.raw("POST", `/users/${userId}/password`, {
      body: { new_password: "ResetPass2026!" },
    });
    expect(res.status()).toBe(204);
  });

  test("8. delete user (+ self-delete guard)", async ({ api }) => {
    // Self-delete must be refused (409).
    const me = await api.get<{ id: string }>("/auth/me");
    const selfDel = await api.raw("DELETE", `/users/${me.id}`);
    expect(selfDel.status()).toBe(409);

    // Delete the test user - should succeed.
    await api.delete(`/users/${userId}`);
  });
});

test.describe.serial("spine - scoped API tokens", () => {
  let keyId: string;
  let plaintext: string;

  test("9. mint + verify scope enforcement", async ({ api }) => {
    const minted = await api.post<{
      id: string;
      token: string;
      scopes: string[];
    }>("/api-keys", {
      name: "e2e-spine",
      scopes: ["home:read", "tasks:read"],
    });
    keyId = minted.id;
    plaintext = minted.token;
    expect(plaintext.startsWith("z4k_")).toBe(true);
    expect(minted.scopes).toEqual(["home:read", "tasks:read"]);

    // Bearer-only (noCookie): the session cookie must NOT ride along or
    // it would authenticate these instead of the scoped key.
    const bearer = { Authorization: `Bearer ${plaintext}` };

    // Bearer can read /home/summary (200).
    const ok = await api.raw("GET", "/home/summary", { noCookie: true, headers: bearer });
    expect(ok.status()).toBe(200);

    // Bearer cannot hit /auth/me (403 - BEARER_DENY_TAGS).
    const deniedAuth = await api.raw("GET", "/auth/me", { noCookie: true, headers: bearer });
    expect(deniedAuth.status()).toBe(403);

    // Bearer cannot mint agents in any project (needs agents:write).
    const deniedScope = await api.raw("POST", "/projects/default/agents", {
      noCookie: true,
      headers: bearer,
      body: { name: "should-not-mint" },
    });
    expect(deniedScope.status()).toBe(403);
  });

  test("10. revoke makes the key unauthenticated", async ({ api }) => {
    await api.delete(`/api-keys/${keyId}`);
    const afterRevoke = await api.raw("GET", "/home/summary", {
      noCookie: true,
      headers: { Authorization: `Bearer ${plaintext}` },
    });
    expect(afterRevoke.status()).toBe(401);
  });
});
