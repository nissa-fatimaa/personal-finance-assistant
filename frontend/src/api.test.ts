import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);
afterEach(() => fetchMock.mockReset());

const reply = (status: number, body?: unknown) =>
  Promise.resolve(new Response(body === undefined ? null : JSON.stringify(body), { status }));

describe("api client security behaviour", () => {
  it("sends the CSRF header and JSON type on state changes only", async () => {
    fetchMock.mockReturnValueOnce(reply(200, { mfa_required: false }));
    await api.login("a@example.invalid", "pw");
    const [, post] = fetchMock.mock.calls[0];
    expect(post.method).toBe("POST");
    expect(post.headers["X-Requested-With"]).toBe("pfa");
    expect(post.headers["Content-Type"]).toBe("application/json");
    expect(post.credentials).toBe("same-origin");

    fetchMock.mockReturnValueOnce(reply(200, { accounts: [] }));
    await api.accounts();
    const [path, get] = fetchMock.mock.calls[1];
    expect(path).toBe("/accounts");
    expect(get.headers).toEqual({});
  });

  it("surfaces server detail and status, including rate limiting", async () => {
    fetchMock.mockReturnValueOnce(reply(429, { detail: "too many attempts, try again later" }));
    await expect(api.login("a@example.invalid", "pw")).rejects.toMatchObject({
      name: "ApiError", status: 429, message: "too many attempts, try again later",
    });
  });

  it("maps network failures to a friendly status-0 error", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("offline"));
    const error = await api.me().catch(e => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(0);
  });

  it("keeps a generic message when the error body is not JSON", async () => {
    fetchMock.mockReturnValueOnce(Promise.resolve(new Response("<html>", { status: 502 })));
    await expect(api.me()).rejects.toMatchObject({ status: 502, message: "That request could not be completed." });
  });

  it("returns undefined for 204 and encodes path segments", async () => {
    fetchMock.mockReturnValueOnce(reply(204));
    await expect(api.staffAction("a/b?c", "lock")).resolves.toBeUndefined();
    expect(fetchMock.mock.calls[0][0]).toBe("/security/users/a%2Fb%3Fc/lock");
  });

  it("sends role changes with re-authentication fields via PUT", async () => {
    fetchMock.mockReturnValueOnce(reply(204));
    await api.changeRole("u1", "admin", "pw", "123456");
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/security/users/u1/role");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toEqual({ role: "admin", current_password: "pw", current_code: "123456" });
  });
});
