import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AccountsPanel, MfaDisablePanel, MfaQrCode, StaffUsersPanel, secretFromUri, totpQrDataUrl } from "./panels";
import { api } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    api: {
      accounts: vi.fn(), createAccount: vi.fn(), deleteMoneyAccount: vi.fn(),
      disableMfa: vi.fn(), staffUsers: vi.fn(), staffAction: vi.fn(), changeRole: vi.fn(),
    },
  };
});
afterEach(() => { cleanup(); vi.clearAllMocks(); });

const uri = "otpauth://totp/Finwise:a%40example.invalid?secret=JBSWY3DPEHPK3PXP&issuer=Finwise";
const staffUser = {
  user_id: "u-1", email_masked: "a***@example.invalid", role: "user" as const, status: "active" as const,
  temporarily_locked: false, mfa_enabled: true, created_at: "2026-10-01T00:00:00Z",
};

describe("MFA enrolment QR", () => {
  it("renders a local QR image and the manual key", () => {
    expect(totpQrDataUrl(uri)).toMatch(/^data:image\/gif;base64,/);
    expect(secretFromUri(uri)).toBe("JBSWY3DPEHPK3PXP");
    expect(secretFromUri("not a uri")).toBe("");
    render(<MfaQrCode uri={uri} />);
    expect(screen.getByAltText("Authenticator QR code")).toHaveAttribute("src", expect.stringMatching(/^data:image/));
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
  });
});

describe("AccountsPanel", () => {
  it("lists accounts and adds a new one", async () => {
    vi.mocked(api.accounts)
      .mockResolvedValueOnce({ accounts: [] })
      .mockResolvedValueOnce({ accounts: [{ account_id: "a1", name: "HBL", type: "bank", currency: "PKR" }] });
    vi.mocked(api.createAccount).mockResolvedValue({ account_id: "a1", name: "HBL", type: "bank", currency: "PKR" });
    render(<AccountsPanel />);
    expect(await screen.findByText("No accounts yet.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Account name"), { target: { value: "HBL" } });
    fireEvent.change(screen.getByLabelText("Type"), { target: { value: "bank" } });
    fireEvent.click(screen.getByRole("button", { name: "Add account" }));
    await waitFor(() => expect(api.createAccount).toHaveBeenCalledWith({ name: "HBL", type: "bank", currency: "PKR" }));
    expect(await screen.findByText("HBL")).toBeInTheDocument();
  });

  it("shows the server error when listing fails", async () => {
    vi.mocked(api.accounts).mockRejectedValue(new Error("authentication required"));
    render(<AccountsPanel />);
    expect(await screen.findByRole("alert")).toHaveTextContent("authentication required");
  });
});

describe("MfaDisablePanel", () => {
  it("requires password and code, then reports success", async () => {
    const done = vi.fn();
    vi.mocked(api.disableMfa).mockResolvedValue(undefined);
    render(<MfaDisablePanel onDone={done} />);
    fireEvent.click(screen.getByRole("button", { name: "Turn off MFA" }));
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "pw" } });
    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm and turn off" }));
    await waitFor(() => expect(api.disableMfa).toHaveBeenCalledWith("pw", "123456"));
    expect(done).toHaveBeenCalled();
    expect(await screen.findByRole("status")).toHaveTextContent("now off");
  });
});

describe("StaffUsersPanel", () => {
  it("is read-only for admin", async () => {
    vi.mocked(api.staffUsers).mockResolvedValue({ users: [staffUser] });
    render(<StaffUsersPanel canManage={false} />);
    expect(await screen.findByText("a***@example.invalid")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock" })).toBeNull();
  });

  it("lets a security owner lock after confirmation and change roles with re-auth", async () => {
    vi.mocked(api.staffUsers).mockResolvedValue({ users: [staffUser] });
    vi.mocked(api.staffAction).mockResolvedValue(undefined);
    vi.mocked(api.changeRole).mockResolvedValue(undefined);
    const confirm = vi.fn(() => true); window.confirm = confirm;
    render(<StaffUsersPanel canManage />);
    fireEvent.click(await screen.findByRole("button", { name: "Lock" }));
    await waitFor(() => expect(api.staffAction).toHaveBeenCalledWith("u-1", "lock"));
    expect(confirm).toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Change role" }));
    fireEvent.change(screen.getByLabelText("New role"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Your password"), { target: { value: "pw" } });
    fireEvent.change(screen.getByLabelText("Your authenticator code"), { target: { value: "654321" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm role change" }));
    await waitFor(() => expect(api.changeRole).toHaveBeenCalledWith("u-1", "admin", "pw", "654321"));
  });

  it("does nothing when the operator cancels", async () => {
    vi.mocked(api.staffUsers).mockResolvedValue({ users: [staffUser] });
    window.confirm = vi.fn(() => false);
    render(<StaffUsersPanel canManage />);
    fireEvent.click(await screen.findByRole("button", { name: "Force reset" }));
    expect(api.staffAction).not.toHaveBeenCalled();
  });
});
