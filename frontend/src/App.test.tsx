import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, fireEvent, waitFor } from "@testing-library/react";
import App, { AdminPage, ChangePasswordPage, ChatConfirmationCard, ChatPage, DashboardPage, resetTokenFromFragment } from "./App";
import { api, type AuthUser, type Dashboard } from "./api";

afterEach(cleanup);

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    api: {
      dashboard: vi.fn(),
      transactions: vi.fn(),
      adminStats: vi.fn(),
      changePassword: vi.fn(),
      resetConfirm: vi.fn(),
      login: vi.fn(),
      register: vi.fn(),
      verifyMfa: vi.fn(),
      me: vi.fn(),
    },
  };
});

const dashboardFixture: Dashboard = {
  month: "2026-01",
  base_currency: "PKR",
  report_currency: "PKR",
  policy: "as_recorded",
  rates_snapshot: null,
  rates_snapshot_age_days: null,
  fx_snapshots: [],
  rate_sources: [],
  rate_attribution: "",
  rate_attribution_url: "",
  income_minor: null,
  expenses_minor: null,
  fees_minor: null,
  fees_currency: "PKR",
  categories: [],
  safe_to_spend_today_minor: null,
  safe_to_spend_currency: "PKR",
  forecast_minor: null,
  forecast_currency: "PKR",
  forecast_label: null,
  alerts: [],
  pending_count: 0,
  analytics_available: false,
  report_conversion_available: false,
  unavailable_currencies: [],
  fx_effects: [],
};

describe("Finwise key views", () => {
  it("opens the reset-email route and reads the token from its fragment", () => {
    window.history.replaceState(null, "", "/reset-password#token=fragment-token");
    render(<App/>);
    expect(screen.getByLabelText("Reset token")).toHaveValue("fragment-token");
    expect(screen.getByRole("button", {name: "Update password →"})).toBeInTheDocument();
    expect(resetTokenFromFragment("#token=a%2Bb")).toBe("a+b");
    window.history.replaceState(null, "", "/");
  });

  it("keeps password-change success visible after the asynchronous request", async () => {
    vi.mocked(api.changePassword).mockResolvedValue(undefined);
    render(<ChangePasswordPage/>);
    fireEvent.change(screen.getByLabelText("Current password"), {target: {value: "current-password"}});
    fireEvent.change(screen.getByLabelText("New password"), {target: {value: "new-strong-password"}});
    fireEvent.click(screen.getByRole("button", {name: "Update password"}));
    expect(await screen.findByText("Password updated. All sessions were revoked.")).toBeInTheDocument();
    expect(screen.getByLabelText("Current password")).toHaveValue("");
    expect(screen.getByRole("link", {name: "Sign in again"})).toHaveAttribute("href", "/login");
  });

  it("renders a dashboard empty state using API data only", async () => {
    vi.mocked(api.dashboard).mockResolvedValue(dashboardFixture);
    vi.mocked(api.transactions).mockResolvedValue({ month: "2026-01", transactions: [] });
    render(<DashboardPage />);
    expect(await screen.findByText("A clear view of your month.")).toBeInTheDocument();
    expect(await screen.findByText("Your ledger starts here")).toBeInTheDocument();
    expect(screen.getAllByText("Not available").length).toBeGreaterThan(0);
    expect(screen.getByRole("combobox", { name: "Report currency" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Rate policy" })).toBeInTheDocument();
  });

  it("shows a chat transaction draft with explicit confirmation actions", () => {
    const card = {
      txn_id: "draft",
      kind: "expense" as const,
      amount_minor: 0,
      currency: "PKR",
      merchant: "Merchant",
      category_id: null,
    };
    const confirm = vi.fn();
    const discard = vi.fn();
    render(<ChatConfirmationCard card={card} onConfirm={confirm} onDiscard={discard} />);
    expect(screen.getByRole("heading", { name: "Confirm this transaction" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Confirm & post" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Discard pending record" })).toBeInTheDocument();
    expect(screen.getByText(/stored as pending/)).toBeInTheDocument();
  });

  it("requires an undetected receipt date to be chosen and saved before confirmation", async () => {
    const saveDate = vi.fn().mockResolvedValue(undefined);
    const card = {
      txn_id: "receipt-draft",
      kind: "expense" as const,
      amount_minor: 1200,
      currency: "PKR",
      merchant: "Corner Cafe",
      category_id: null,
      txn_date: "2026-10-20",
      receipt_date_detected: false,
    };
    render(<ChatConfirmationCard card={card} onConfirm={vi.fn()} onDiscard={vi.fn()} onSaveDate={saveDate}/>);
    const confirm = screen.getByRole("button", { name: "Confirm & post" });
    expect(confirm).toBeDisabled();
    const date = screen.getByLabelText("Purchase date");
    fireEvent.change(date, { target: { value: "2026-10-19" } });
    expect(confirm).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Save date" }));
    await waitFor(() => expect(saveDate).toHaveBeenCalledWith("2026-10-19"));
    await waitFor(() => expect(confirm).toBeEnabled());
  });

  it("offers receipt review while keeping transaction chat visible offline", () => {
    render(<ChatPage />);
    expect(screen.getByLabelText(/Review a receipt/)).toHaveAttribute("type", "file");
    expect(screen.getByRole("textbox", { name: "Describe a transaction" })).toBeInTheDocument();
    expect(screen.getByText(/Local parsing works without AI/)).toBeInTheDocument();
  });

  it("keeps the admin view to operational counts with no financial detail", async () => {
    vi.mocked(api.adminStats).mockResolvedValue({ active_users: 0, txns_24h: 0, failed_logins_24h: 0 });
    const user: AuthUser = { user_id: "assigned", role: "admin", mfa_ok: true };
    render(<AdminPage user={user} />);
    expect(await screen.findByText("An operational view. Nothing personal.")).toBeInTheDocument();
    expect(screen.getByText("Active users")).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /merchant|amount/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /edit|delete/i })).not.toBeInTheDocument();
  });

  it("shows the server's rate-limit message on sign in without navigating", async () => {
    window.history.replaceState(null, "", "/login");
    vi.mocked(api.login).mockRejectedValue(new Error("too many attempts, try again later"));
    render(<App/>);
    fireEvent.change(screen.getByLabelText("Email address"), { target: { value: "a@example.invalid" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in →" }));
    expect(await screen.findByRole("status")).toHaveTextContent("too many attempts");
    expect(location.pathname).toBe("/login");
    window.history.replaceState(null, "", "/");
  });

  it("requires privacy consent and sends registration fields without AI consent by default", async () => {
    window.history.replaceState(null, "", "/signup");
    vi.mocked(api.register).mockResolvedValue({ message: "ok" });
    render(<App/>);
    fireEvent.change(screen.getByLabelText("Email address"), { target: { value: "new@example.invalid" } });
    fireEvent.change(screen.getByLabelText("Create password"), { target: { value: "Amber!Quartz-long-Compass9" } });
    fireEvent.change(screen.getByLabelText("Base currency"), { target: { value: "PKR" } });
    const privacy = screen.getByLabelText("I agree to the privacy terms");
    expect(privacy).toBeRequired();
    fireEvent.click(privacy);
    fireEvent.click(screen.getByRole("button", { name: "Create personal account →" }));
    await waitFor(() => expect(api.register).toHaveBeenCalledWith({
      email: "new@example.invalid", password: "Amber!Quartz-long-Compass9", base_currency: "PKR",
      privacy_consent: true, ai_consent: false,
    }));
    window.history.replaceState(null, "", "/");
  });

  it("shows an MFA failure without leaking which factor failed", async () => {
    window.history.replaceState(null, "", "/mfa");
    vi.mocked(api.verifyMfa).mockRejectedValue(new Error("invalid MFA verification"));
    render(<App/>);
    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and continue →" }));
    expect(await screen.findByRole("status")).toHaveTextContent("invalid MFA verification");
    window.history.replaceState(null, "", "/");
  });

  it("keeps staff out of personal-finance pages", async () => {
    window.history.replaceState(null, "", "/ledger");
    vi.mocked(api.me).mockResolvedValue({ user_id: "s1", role: "security_owner", mfa_ok: true, mfa_enabled: true, ai_consent: false } as AuthUser);
    render(<App/>);
    expect(await screen.findByText("This page isn’t part of your workspace.")).toBeInTheDocument();
    expect(api.transactions).not.toHaveBeenCalled();
    window.history.replaceState(null, "", "/");
  });
});
