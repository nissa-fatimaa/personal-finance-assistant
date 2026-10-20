import { useEffect, useState, type FormEvent } from "react";
import qrcode from "qrcode-generator";
import { api, type MoneyAccount, type Role, type StaffUserRecord } from "./api";

const accountTypes: MoneyAccount["type"][] = ["cash", "bank", "card", "wallet"];
const currencies = ["PKR", "USD", "EUR", "GBP", "AED", "SAR", "CAD", "AUD", "CNY", "JPY"];
const errorText = (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback);

/** Builds an otpauth:// QR code locally; the secret never leaves the browser. */
export function totpQrDataUrl(uri: string): string {
  const qr = qrcode(0, "M");
  qr.addData(uri);
  qr.make();
  return qr.createDataURL(4, 8);
}

export function secretFromUri(uri: string): string {
  try {
    return new URL(uri).searchParams.get("secret") ?? "";
  } catch {
    return "";
  }
}

export function MfaQrCode({ uri }: { uri: string }) {
  const secret = secretFromUri(uri);
  return (
    <div className="stack">
      <img src={totpQrDataUrl(uri)} alt="Authenticator QR code" width={200} height={200} style={{ imageRendering: "pixelated" }} />
      <p className="fine">Scan with Google Authenticator, Microsoft Authenticator or similar. Can’t scan? Enter this key manually: <code>{secret}</code></p>
    </div>
  );
}

export function useAccounts() {
  const [accounts, setAccounts] = useState<MoneyAccount[]>([]);
  const [error, setError] = useState("");
  const reload = async () => {
    try { setAccounts((await api.accounts()).accounts); setError(""); }
    catch (e) { setError(errorText(e, "Unable to load accounts.")); }
  };
  useEffect(() => { void reload(); }, []);
  return { accounts, error, reload };
}

export function AccountsPanel() {
  const { accounts, error, reload } = useAccounts();
  const [message, setMessage] = useState("");
  const add = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    try {
      await api.createAccount({
        name: String(f.get("name")),
        type: String(f.get("type")) as MoneyAccount["type"],
        currency: String(f.get("currency")),
      });
      form.reset(); setMessage("Account added."); await reload();
    } catch (err) { setMessage(errorText(err, "Unable to add account.")); }
  };
  const remove = async (account: MoneyAccount) => {
    if (!window.confirm(`Remove ${account.name}? Past transactions keep their history.`)) return;
    try { await api.deleteMoneyAccount(account.account_id); setMessage("Account removed."); await reload(); }
    catch (err) { setMessage(errorText(err, "Unable to remove account.")); }
  };
  return (
    <section id="accounts" className="card">
      <h2>Money accounts</h2>
      <p className="fine">Cash, bank, card or wallet. Names are encrypted with your personal key.</p>
      {error && <div className="notice error" role="alert">{error}</div>}
      {message && <div className="notice" role="status">{message}</div>}
      {accounts.length ? (
        <div className="table-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Currency</th><th>Action</th></tr></thead>
          <tbody>{accounts.map(a => <tr key={a.account_id}><td>{a.name}</td><td>{a.type}</td><td>{a.currency}</td>
            <td><button className="btn" onClick={() => void remove(a)}>Remove</button></td></tr>)}</tbody></table></div>
      ) : <div className="empty">No accounts yet.</div>}
      <form className="form-grid" style={{ marginTop: 12 }} onSubmit={add} aria-label="Add account">
        <label>Account name<input name="name" required maxLength={100} /></label>
        <label>Type<select name="type">{accountTypes.map(t => <option key={t}>{t}</option>)}</select></label>
        <label>Currency<select name="currency">{currencies.map(c => <option key={c}>{c}</option>)}</select></label>
        <button className="btn primary">Add account</button>
      </form>
    </section>
  );
}

export function MfaDisablePanel({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      await api.disableMfa(String(f.get("current_password")), String(f.get("current_code")));
      setOpen(false); setMessage("Two-step verification is now off."); onDone();
    } catch (err) { setMessage(errorText(err, "Unable to turn off two-step verification.")); }
  };
  return (
    <>
      <button className="btn" onClick={() => setOpen(!open)}>Turn off MFA</button>
      {message && <div className="notice" role="status">{message}</div>}
      {open && (
        <form className="stack" style={{ marginTop: 12 }} onSubmit={submit} aria-label="Turn off MFA">
          <label>Current password<input name="current_password" type="password" required autoComplete="current-password" /></label>
          <label>Authenticator code<input name="current_code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required autoComplete="one-time-code" /></label>
          <button className="btn danger">Confirm and turn off</button>
        </form>
      )}
    </>
  );
}

export function StaffUsersPanel({ canManage }: { canManage: boolean }) {
  const [users, setUsers] = useState<StaffUserRecord[]>([]);
  const [message, setMessage] = useState("");
  const [roleTarget, setRoleTarget] = useState<StaffUserRecord | null>(null);
  const reload = async () => {
    try { setUsers((await api.staffUsers()).users); }
    catch (e) { setMessage(errorText(e, "Unable to load accounts.")); }
  };
  useEffect(() => { void reload(); }, []);
  const act = async (user: StaffUserRecord, action: "lock" | "unlock" | "force-reset") => {
    const label = action === "force-reset" ? "force a password reset for" : action;
    if (!window.confirm(`Really ${label} ${user.email_masked}? This is recorded in the audit log.`)) return;
    try { await api.staffAction(user.user_id, action); setMessage(`Done: ${action} ${user.email_masked}.`); await reload(); }
    catch (e) { setMessage(errorText(e, "Action failed.")); }
  };
  const changeRole = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!roleTarget) return;
    const f = new FormData(e.currentTarget);
    try {
      await api.changeRole(roleTarget.user_id, String(f.get("role")) as Role,
        String(f.get("current_password")), String(f.get("current_code")));
      setMessage(`Role updated for ${roleTarget.email_masked}.`); setRoleTarget(null); await reload();
    } catch (err) { setMessage(errorText(err, "Role change failed.")); }
  };
  return (
    <section className="card" style={{ marginTop: 15 }}>
      <h2>Account status</h2>
      <p className="fine">Status metadata only: masked email, role, lock and MFA state. No financial data is available to staff.</p>
      {message && <div className="notice" role="status">{message}</div>}
      <div className="table-wrap"><table><thead><tr><th>Account</th><th>Role</th><th>Status</th><th>MFA</th>{canManage && <th>Actions</th>}</tr></thead>
        <tbody>{users.map(u => <tr key={u.user_id}>
          <td>{u.email_masked}</td><td>{u.role}</td>
          <td>{u.status}{u.temporarily_locked ? " · temporarily locked" : ""}</td>
          <td>{u.mfa_enabled ? "On" : "Off"}</td>
          {canManage && <td><div className="inline">
            {u.status === "locked"
              ? <button className="btn" onClick={() => void act(u, "unlock")}>Unlock</button>
              : <button className="btn" onClick={() => void act(u, "lock")}>Lock</button>}
            <button className="btn" onClick={() => void act(u, "force-reset")}>Force reset</button>
            <button className="btn" onClick={() => setRoleTarget(u)}>Change role</button>
          </div></td>}
        </tr>)}</tbody></table></div>
      {canManage && roleTarget && (
        <form className="stack" style={{ marginTop: 12 }} onSubmit={changeRole} aria-label="Change role">
          <h3>Change role for {roleTarget.email_masked}</h3>
          <p className="fine">Re-enter your password and a current authenticator code. Staff roles require the target to have MFA enabled.</p>
          <label>New role<select name="role" defaultValue={roleTarget.role}><option>user</option><option>security_owner</option><option>admin</option></select></label>
          <label>Your password<input name="current_password" type="password" required autoComplete="current-password" /></label>
          <label>Your authenticator code<input name="current_code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required /></label>
          <div className="inline"><button type="button" className="btn" onClick={() => setRoleTarget(null)}>Cancel</button><button className="btn primary">Confirm role change</button></div>
        </form>
      )}
    </section>
  );
}
