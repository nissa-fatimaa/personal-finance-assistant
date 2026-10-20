import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, type AuthUser, type Dashboard, type Transaction, type Category, type Bill, type Budget, type BudgetSuggestions, type SessionRecord, type AuditEvent, type Policy } from "./api";
import { amountToMinor, currencyExponent, formatMoney } from "./money";
import { AccountsPanel, MfaDisablePanel, MfaQrCode, StaffUsersPanel, useAccounts } from "./panels";

const paths = [
  ["Overview", "/"], ["Transactions", "/ledger"], ["Assistant", "/assistant"],
  ["Budgets", "/plan"], ["Bills", "/bill-calendar"], ["Reports", "/reports"],
  ["Insights", "/insights"], ["Settings", "/settings"], ["Change password", "/settings/password"],
];
const currencies = ["PKR", "USD", "EUR", "GBP", "AED", "SAR", "CAD", "AUD", "CNY", "JPY"];
const localDate = () => {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
};
const monthNow = () => localDate().slice(0, 7);
const money = formatMoney;
const minorToInput = (minor: number | null | undefined, currency: string) => {
  if (minor == null) return "";
  const exponent = currencyExponent(currency);
  const scale = 10 ** exponent;
  const whole = Math.floor(minor / scale);
  const fraction = exponent
    ? `.${String(minor % scale).padStart(exponent, "0")}`
    : "";
  return `${whole}${fraction}`;
};
export function resetTokenFromFragment(hash: string) {
  const fragment = hash.startsWith("#") ? hash.slice(1) : hash;
  return new URLSearchParams(fragment).get("token") ?? "";
}
function useLoad<T>(loader: () => Promise<T>, deps: unknown[] = [], skip = false) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revision, refresh] = useState(0);
  useEffect(() => {
    if (skip) {
      setData(null);
      setError("");
      setLoading(false);
      return;
    }
    let active = true;
    setLoading(true); setError("");
    loader().then(value => { if (active) setData(value); }).catch(e => { if (active) setError(e instanceof Error ? e.message : "Unable to load this page."); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  // Loader functions intentionally are captured by their stable dependency list.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, revision, skip]);
  return { data, error, loading, reload: () => refresh(v => v + 1) };
}
function Frame({ user, title, children }: { user: AuthUser | null; title: string; children: ReactNode }) {
  const isAdmin = user?.role === "admin" || user?.role === "security_owner";
  const nav = isAdmin
    ? user?.role === "security_owner" ? [["Security overview", "/security"], ["Audit log", "/security-audit"]] : [["System overview", "/admin"]]
    : paths;
  return <div className="shell"><aside className="sidebar">
    <a href="/" className="brand"><span className="brand-mark" aria-hidden="true">F</span>Finwise</a>
    <div><div className="side-kicker">{isAdmin ? "Operations" : "Your finances"}</div><span className="side-tag">{isAdmin ? user?.role?.replace("_", " ") : "Personal workspace"}</span></div>
    <nav className="nav" aria-label="Main navigation">{nav.map(([label, href]) => <a key={href} className={location.pathname === href ? "active" : ""} href={href}>{label}</a>)}</nav>
    <div className="side-note">{isAdmin ? "Operational counts and sanitised security only. No access to financial data." : "Only your own financial data belongs in this workspace."}</div>
    <div className="side-user">{isAdmin ? "Administrative workspace" : user?.user_id ?? "Personal workspace"}<br />Server-assigned · {user?.role ?? "user"}
      <a href="/login" onClick={e => { e.preventDefault(); void api.logout().finally(() => { location.href = "/login"; }); }}>Sign out ↗</a>
    </div>
  </aside><main className="workspace">
    <div className="topline"><span>Finwise / {isAdmin ? "Operations" : "Personal workspace"} / {title}</span><span>{user?.role === "user" ? "PRIVATE WORKSPACE" : "ROLE-RESTRICTED VIEW"}</span></div>
     <div className="content">{children}<div className="footer">FINWISE / PERSONAL FINANCE WORKSPACE <span>　/　 Private by design</span><br/><a href="https://www.exchangerate-api.com" target="_blank" rel="noreferrer">Rate source attribution: Exchange Rate API</a></div></div>
  </main></div>;
}
function PageHead({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return <header className="page-head"><div><h1>{title}</h1>{description && <p className="subtitle">{description}</p>}</div>{action}</header>;
}
function Status({ text }: { text: string }) { return <span className="status">{text}</span>; }
function LoadState({ loading, error, retry }: { loading: boolean; error: string; retry: () => void }) {
  if (loading) return <div className="card" aria-label="Loading"><div className="metric-label">Loading your workspace</div><div className="fine">Your private data is being retrieved…</div></div>;
  if (error) return <div className="notice error" role="alert">{error}<button className="btn" onClick={retry} style={{ marginLeft: 12 }}>Try again</button></div>;
  return null;
}
function Metric({ label, value, detail, dark = false }: { label: string; value: string; detail?: string; dark?: boolean }) {
  return <div className={`card${dark ? " green" : ""}`}><div className="metric-label">{label}</div><div className="metric">{value}</div>{detail && <div className="fine">{detail}</div>}</div>;
}
export function DashboardPage() {
  const [month, setMonth] = useState(monthNow);
  const [currency, setCurrency] = useState("");
  const [policy, setPolicy] = useState<Policy>("as_recorded");
  const dash = useLoad<Dashboard>(() => api.dashboard(month, currency || undefined, policy), [month, currency, policy]);
  const tx = useLoad<{ transactions: Transaction[] }>(() => api.transactions(month), [month]);
  const d = dash.data;
  if (dash.loading || dash.error || !d) return <><PageHead title="A clear view of your month." description="Your money, in perspective."/><LoadState loading={dash.loading} error={dash.error} retry={dash.reload}/></>;
  const cats = d.categories ?? [];
  return <><PageHead title="A clear view of your month." description="Your own ledger, thoughtful budgets and a clear view of what comes next." action={<a className="btn primary" href="/transactions/new">+ Add transaction</a>}/>
     <div className="inline" style={{ marginBottom: 16 }}>
       <label>Month<input aria-label="Month" type="month" value={month} onChange={e => setMonth(e.target.value)}/></label>
       <label>Report currency<select aria-label="Report currency" value={currency || d.report_currency} onChange={e => setCurrency(e.target.value)}>{currencies.map(c => <option key={c}>{c}</option>)}</select></label>
       <label>Rate policy<select aria-label="Rate policy" value={policy} onChange={e => setPolicy(e.target.value as Policy)}><option value="as_recorded">As recorded</option><option value="current">Current</option></select></label>
       <span className="fine">Base currency: {d.base_currency} · policy: {d.policy}</span>
     </div>
    <div className="grid cols-3">
       <Metric dark label="Income" value={money(d.income_minor, d.report_currency)} detail="Recorded income in this period"/>
       <Metric label="Net spending" value={money(d.expenses_minor, d.report_currency)} detail="Posted expenses, less refunds"/>
      <Metric label="Safe to spend today" value={money(d.safe_to_spend_today_minor, d.safe_to_spend_currency)} detail="Based on your current category limits"/>
    </div>
    <div className="grid cols-2" style={{ marginTop: 15 }}>
      <section className="card"><h2>Room to breathe</h2><p className="fine">Category spending and limits for this month</p>
        {cats.length ? <div className="stack">{cats.map(c => <div key={c.category_id} className="calc-row"><b>{c.name}</b><span>{money(c.spent_minor, c.currency)} spent</span><span>{money(c.limit_minor, c.currency)} limit</span><Status text={c.status}/></div>)}</div> : <div className="empty"><h3>No category activity</h3><p>When your ledger includes category data, it will appear here.</p></div>}
      </section>
      <section className="card sage"><h2>Looking ahead</h2><div className="metric">{money(d.forecast_minor, d.forecast_currency)}</div><p className="fine">{d.forecast_label ?? "Forecast availability is determined by your transaction history."}</p><a className="btn" href="/insights">Inspect the facts</a></section>
    </div>
    <section className="card" style={{marginTop:15}}><h2>Alerts</h2>{d.alerts.length ? d.alerts.map((a,i)=><p key={`${a.category_id}-${i}`}>{cats.find(c=>c.category_id===a.category_id)?.name ?? "Category"} · {a.status}</p>) : <div className="empty">No alerts returned for this period.</div>}</section>
     <section className="card" style={{ marginTop: 15 }}><div className="page-head"><div><h2>Recent activity</h2><p className="fine">Your own records in the selected month</p></div><a href="/ledger">Full ledger →</a></div>
      <LoadState loading={tx.loading} error={tx.error} retry={tx.reload}/>
      {!tx.loading && !tx.error && (tx.data?.transactions.length ? <div className="table-wrap"><table><thead><tr><th>Date</th><th>Merchant</th><th>Original</th><th>Status</th></tr></thead><tbody>{tx.data.transactions.slice(0, 6).map(t => <tr key={t.txn_id}><td>{t.txn_date}</td><td>{t.merchant ?? t.kind}</td><td>{money(t.amount_minor, t.currency)}</td><td>{t.status}</td></tr>)}</tbody></table></div> : <div className="empty"><h3>Your ledger starts here</h3><p>There are no records in this period.</p><a className="btn primary" href="/transactions/new">Add a transaction</a></div>)}
    </section>
     <div className="fine" style={{ marginTop: 12 }}>Fees: {money(d.fees_minor, d.fees_currency)} · Analytics {d.analytics_available ? "available" : "not available"} · FX snapshot: {d.rates_snapshot ?? "not available"} {d.rates_snapshot_age_days === null ? "" : `(${d.rates_snapshot_age_days} days old)`} · {d.rate_sources.join(", ") || "No rate source used"}</div>
  </>;
}
export function ChatConfirmationCard({ card, onConfirm, onDiscard, onSaveDate }: {
  card: NonNullable<Awaited<ReturnType<typeof api.chat>>["confirmation_card"]>;
  onConfirm: () => void;
  onDiscard: () => void;
  onSaveDate?: (txnDate: string) => Promise<void>;
}) {
  const [txnDate, setTxnDate] = useState(
    card.receipt_date_detected === false ? "" : card.txn_date ?? "",
  );
  const [savedDate, setSavedDate] = useState(
    card.receipt_date_detected === false ? "" : card.txn_date ?? "",
  );
  const [dateError, setDateError] = useState("");
  const [savingDate, setSavingDate] = useState(false);
  useEffect(() => {
    const proposedDate = card.receipt_date_detected === false ? "" : card.txn_date ?? "";
    setTxnDate(proposedDate);
    setSavedDate(card.receipt_date_detected === false ? "" : proposedDate);
    setDateError("");
  }, [card.txn_id, card.txn_date, card.receipt_date_detected]);
  const saveDate = async () => {
    if (!txnDate || !onSaveDate) return;
    setSavingDate(true);
    setDateError("");
    try {
      await onSaveDate(txnDate);
      setSavedDate(txnDate);
    } catch (error) {
      setDateError(error instanceof Error ? error.message : "Unable to save this date.");
    } finally {
      setSavingDate(false);
    }
  };
  const dateUnsaved = txnDate !== savedDate;
  const receiptDateNeedsChoice = card.receipt_date_detected === false && !savedDate;
  return <div className="card" aria-label="Confirm this transaction"><h2>Confirm this transaction</h2><div className="metric">{money(card.amount_minor, card.currency)}</div><p>{card.merchant} · {card.kind}</p>
    {card.receipt_date_detected !== undefined && <div className="stack" style={{ maxWidth: 320, marginTop: 12 }}>
      <label>Purchase date<input type="date" aria-label="Purchase date" value={txnDate} onChange={event => setTxnDate(event.target.value)}/></label>
      {card.receipt_date_detected === false && <p className="fine">{savedDate ? "No clear date was printed; your selected date is saved." : "No clear date was found. Choose a date; this draft will stay pending until you save one."}</p>}
      {dateUnsaved && <button className="btn" type="button" disabled={!txnDate || savingDate} onClick={() => void saveDate()}>{savingDate ? "Saving date…" : "Save date"}</button>}
      {dateError && <div className="notice error" role="alert">{dateError}</div>}
    </div>}
    <Status text="Pending review"/><div className="inline" style={{ marginTop: 15 }}><button className="btn primary" disabled={dateUnsaved || receiptDateNeedsChoice || savingDate} onClick={onConfirm}>Confirm & post</button><button className="btn" onClick={onDiscard}>Discard pending record</button></div><p className="fine" style={{ marginTop: 12 }}>This record is stored as pending and excluded from calculations until you confirm it.</p></div>;
}
function AuthPage({ kind }: { kind: string }) {
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setBusy(true); setMessage("");
    const f = new FormData(e.currentTarget);
    try {
      if (kind === "signup") {
        await api.register({ email: String(f.get("email")), password: String(f.get("password")), base_currency: String(f.get("currency")), privacy_consent: f.get("privacy") === "on", ai_consent: f.get("ai") === "on" });
        setMessage("Your account request is complete. You can now sign in.");
      } else if (kind === "forgot") {
        const res = await api.resetRequest(String(f.get("email"))); setMessage(res.message);
      } else if (kind === "reset") {
        await api.resetConfirm(String(f.get("token")), String(f.get("password"))); setMessage("Password updated. Sign in to continue.");
      } else if (kind === "mfa") {
        await api.verifyMfa(String(f.get("code"))); location.href = "/";
      } else {
        const res = await api.login(String(f.get("email")), String(f.get("password")));
        location.href = res.mfa_required ? "/mfa" : "/";
      }
    } catch (error) { setMessage(error instanceof Error ? error.message : "That request could not be completed."); }
    finally { setBusy(false); }
  };
  const signUp = kind === "signup", forgot = kind === "forgot", reset = kind === "reset", mfa = kind === "mfa";
  const heading = signUp ? "Start with a clean page." : forgot ? "A fresh start, when you need it." : reset ? "Choose a new password." : mfa ? "One more layer of care." : "Your money, in perspective.";
  return <div className="auth"><aside className="auth-brand"><a href="/" className="brand"><span className="brand-mark" aria-hidden="true">F</span>Finwise</a><div className="eyebrow" style={{ marginTop: 42, color: "#d1ded6" }}>A clearer relationship with money</div><h1>A little clarity.<br/>A lot more possibility.</h1><p>Your daily ledger, thoughtful budgets and a finance assistant that asks before it acts.</p><div className="auth-principles"><h2>Make room for what matters.</h2><p>01　 Know where it goes</p><p>02　 Plan at your own pace</p><p>03　 Stay in control</p></div><div className="side-user">Personal by design. Your finances are never visible to administrators or security owners.</div></aside>
    <main className="auth-form"><div className="auth-inner"><div className="eyebrow">{signUp ? "Get started / Personal account" : mfa ? "Verification / Shared authentication" : "Welcome / Shared sign in"}</div><h1>{heading}</h1><p className="subtitle">{signUp ? "Public registration creates a user account, with access only to your own finances." : mfa ? "Enter the current code from your authenticator to complete sign in." : "Sign in to continue to your assigned workspace."}</p>
      <form className="stack" onSubmit={submit}>
        {!mfa && !reset && <label>Email address<input type="email" name="email" required autoComplete="email"/></label>}
        {reset && <label>Reset token<input name="token" required autoComplete="one-time-code" defaultValue={resetTokenFromFragment(location.hash) || new URLSearchParams(location.search).get("token") || ""}/></label>}
        {(kind === "login" || signUp) && <label>{signUp ? "Create password" : "Password"}<input type="password" name="password" required minLength={signUp ? 12 : 1} autoComplete={signUp ? "new-password" : "current-password"}/></label>}
        {reset && <label>New password<input type="password" name="password" required minLength={12} autoComplete="new-password"/></label>}
        {mfa && <label>Authenticator code<input name="code" inputMode="numeric" pattern="[0-9]{6}" minLength={6} maxLength={6} required autoComplete="one-time-code"/></label>}
        {signUp && <><label>Base currency<select name="currency" required defaultValue=""><option value="" disabled>Choose your base currency</option>{currencies.map(c => <option key={c}>{c}</option>)}</select></label><label><span><input style={{ width: "auto" }} type="checkbox" name="ai"/> Allow optional AI assistance</span></label><label><span><input style={{ width: "auto" }} type="checkbox" name="privacy" required/> I agree to the privacy terms</span></label></>}
        {message && <div className="notice" role="status">{message}</div>}
        <button className="btn primary" disabled={busy}>{busy ? "Please wait…" : signUp ? "Create personal account →" : forgot ? "Send recovery instructions →" : reset ? "Update password →" : mfa ? "Verify and continue →" : "Sign in →"}</button>
      </form>
      <p className="fine" style={{ marginTop: 16 }}>{kind === "login" && <a href="/forgot">Forgot password?</a>} {kind === "login" && "　·　"}{!signUp && !mfa && <a href="/signup">Create a personal account ↗</a>}{signUp && <a href="/login">Already have an account? Sign in ↗</a>}{mfa && <a href="/login">Back to sign in ↗</a>}{forgot && <a href="/login">Back to sign in ↗</a>}{reset && <a href="/login">Return to sign in ↗</a>}</p>
      <div className="auth-foot">Static interface backed by your assigned account and server-side permissions.</div></div></main></div>;
}
function AddTransaction({ edit = false, txnId }: { edit?: boolean; txnId?: string }) {
  const cats = useLoad<{ categories: Category[] }>(() => api.categories());
  const existing = useLoad<Transaction>(
    () => api.transaction(txnId ?? ""),
    [txnId],
    !edit || !txnId,
  );
  const [kind, setKind] = useState<Transaction["kind"]>("expense");
  const [currency, setCurrency] = useState("PKR");
  const [categoryId, setCategoryId] = useState("");
  const [accountId, setAccountId] = useState("");
  const moneyAccounts = useAccounts();
  const [amountText, setAmountText] = useState("");
  const [feeText, setFeeText] = useState("");
  const [error, setError] = useState("");
  const [draft, setDraft] = useState<NonNullable<Awaited<ReturnType<typeof api.chat>>["confirmation_card"]> | null>(null);
  const [posted, setPosted] = useState(false);
  useEffect(() => {
    if (!existing.data) return;
    setKind(existing.data.kind);
    setCurrency(existing.data.currency);
    setCategoryId(existing.data.category_id ?? "");
    setAccountId(existing.data.account_id ?? "");
    setAmountText(minorToInput(existing.data.amount_minor, existing.data.currency));
    setFeeText(minorToInput(existing.data.fee_minor, existing.data.currency));
  }, [existing.data]);
  const save = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setError("");
    const f = new FormData(e.currentTarget);
    const amount = amountToMinor(String(f.get("amount")), currency);
    if (amount === null) { setError("Enter an amount with the correct currency precision."); return; }
    const feeValue = String(f.get("fee") || "").trim();
    let fee: number | undefined;
    if (feeValue) {
      const parsedFee = amountToMinor(feeValue, currency);
      if (parsedFee === null) { setError("Enter a fee with the correct currency precision."); return; }
      fee = parsedFee;
    }
    try {
      const merchant = String(f.get("merchant"));
      const txnDate = String(f.get("date"));
      const category = String(f.get("category") || "") || undefined;
      const note = String(f.get("note") || "") || undefined;
      if (edit && txnId && existing.data) {
        await api.updateTransaction(txnId, {
          kind,
          amount_minor: amount,
          currency,
          merchant,
          txn_date: txnDate,
          category_id: category,
          account_id: accountId || undefined,
          note,
          fee_minor: fee,
          fx_override_rate: existing.data.fx_override_rate ?? undefined,
        });
        location.href = "/ledger";
        return;
      }
      const result = await api.createTransaction({
        kind,
        amount_minor: amount,
        currency,
        merchant,
        txn_date: txnDate,
        category_id: category,
        account_id: accountId || undefined,
        note,
        fee_minor: fee,
      });
      setDraft({ txn_id: result.txn_id, kind, amount_minor: amount, currency, merchant, category_id: category ?? null });
    } catch (e2) { setError(e2 instanceof Error ? e2.message : "Unable to save this transaction."); }
  };
  if (edit && existing.loading) return <><PageHead title="Correct a saved transaction."/><div className="card">Loading your transaction…</div></>;
  if (edit && existing.error) return <><PageHead title="Correct a saved transaction."/><LoadState loading={false} error={existing.error} retry={existing.reload}/><a className="btn" href="/ledger">Return to your ledger</a></>;
  if (edit && !existing.data) return <><PageHead title="Correct a saved transaction."/><div className="card">This transaction is unavailable.</div><a className="btn" href="/ledger">Return to your ledger</a></>;
  const record = edit ? existing.data : null;
  const confirm = async () => {
    if (!draft) return;
    try { await api.confirmTransaction(draft.txn_id); setDraft(null); setPosted(true); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to confirm this transaction."); }
  };
  const discard = async () => {
    if (!draft || !window.confirm("Discard this stored pending transaction?")) return;
    try { await api.deleteTransaction(draft.txn_id); setDraft(null); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to discard this transaction."); }
  };
  return <><PageHead title={edit ? "Correct a saved transaction." : "Every detail, before it’s recorded."} description={edit ? "Update the details in your personal ledger." : "Create a transaction, review it, then confirm."}/>
    {error && <div className="notice error" role="alert">{error}</div>}
    {posted ? <div className="notice">Transaction confirmed and posted. <a href="/ledger">Review your ledger →</a></div> : draft ? <ChatConfirmationCard card={draft} onConfirm={() => void confirm()} onDiscard={() => void discard()}/> : <div className="grid cols-2">
      <form className="card stack" onSubmit={save}><h2>Transaction details</h2><div className="tabs" role="group" aria-label="Transaction type">{(["expense","income","refund","transfer"] as const).map(k => <button type="button" key={k} aria-pressed={kind === k} onClick={() => setKind(k)}>{k === "expense" ? "Spending" : k[0].toUpperCase()+k.slice(1)}</button>)}</div>
        <div className="form-grid"><label>Original amount<input name="amount" inputMode="decimal" required aria-label="Original amount" value={edit ? amountText : undefined} defaultValue={edit ? undefined : ""} onChange={edit ? e => setAmountText(e.target.value) : undefined}/></label><label>Currency<select value={currency} onChange={e => setCurrency(e.target.value)}>{currencies.map(c => <option key={c}>{c}</option>)}</select></label><label>Date<input name="date" type="date" required defaultValue={record?.txn_date ?? localDate()}/></label><label>Merchant<input name="merchant" required maxLength={200} defaultValue={record?.merchant ?? ""}/></label><label>Category<select name="category" value={categoryId} onChange={e => setCategoryId(e.target.value)}><option value="">Choose category</option>{cats.data?.categories.map(c => <option key={c.category_id} value={c.category_id}>{c.name}</option>)}</select></label><label>Account (optional)<select name="account" value={accountId} onChange={e => setAccountId(e.target.value)}><option value="">No account</option>{moneyAccounts.accounts.map(a => <option key={a.account_id} value={a.account_id}>{a.name} · {a.type}</option>)}</select></label><label>Separate fee (optional)<input name="fee" inputMode="decimal" placeholder="0.00" value={edit ? feeText : undefined} defaultValue={edit ? undefined : ""} onChange={edit ? e => setFeeText(e.target.value) : undefined}/></label></div>
        <label>Private note (optional)<textarea name="note" maxLength={1000} defaultValue={record?.note ?? ""}/></label><div className="inline"><a className="btn" href="/ledger">Cancel</a><button className="btn primary">{edit ? "Save changes" : "Review transaction"}</button></div>
      </form>
      <section className="card sage"><h2>{edit ? "Your ledger remains yours" : "Review before confirming"}</h2><p className="fine">{edit ? "Your correction is saved only to your own posted transaction. If the corrected details duplicate another active record, the update will be rejected." : "The transaction is stored in pending status after you submit this form. Pending records are excluded from calculations until confirmed."}</p></section>
    </div>}</>;
}
function TransactionsPage() {
  const [month, setMonth] = useState(monthNow); const [search, setSearch] = useState("");
  const records = useLoad(() => api.transactions(month), [month]);
  const dashboard = useLoad<Dashboard>(() => api.dashboard(month), [month]);
  const rows = records.data?.transactions.filter(t => `${t.merchant ?? ""} ${t.note ?? ""} ${t.kind}`.toLowerCase().includes(search.toLowerCase())) ?? [];
  const remove = async (transaction: Transaction) => {
    if (!window.confirm("Soft-delete this transaction from your ledger?")) return;
    try { await api.deleteTransaction(transaction.txn_id); records.reload(); dashboard.reload(); }
    catch (e) { window.alert(e instanceof Error ? e.message : "Unable to remove this transaction."); }
  };
  return <><PageHead title="Your ledger." description="A record of what happened, with originals kept intact." action={<a className="btn primary" href="/transactions/new">+ Add transaction</a>}/><div className="grid cols-3"><Metric label="Records in period" value={records.data ? String(records.data.transactions.length) : "Not available"}/><Metric label="Posted records" value={records.data ? String(records.data.transactions.filter(x => x.status === "posted").length) : "Not available"}/><Metric label="Awaiting confirmation" value={dashboard.data ? String(dashboard.data.pending_count) : "Not available"}/></div>
    <div className="inline" style={{ margin: "18px 0" }}><label>Search your records<input value={search} onChange={e => setSearch(e.target.value)} placeholder="Merchant, note or kind"/></label><label>Period<input type="month" value={month} onChange={e => setMonth(e.target.value)}/></label></div>
    <LoadState loading={records.loading} error={records.error} retry={records.reload}/>
    <LoadState loading={dashboard.loading} error={dashboard.error} retry={dashboard.reload}/>
     {!records.loading && !records.error && <section className="card"><div className="table-wrap"><table><thead><tr><th>Date / reference</th><th>Merchant / kind</th><th>Original</th><th>Fee</th><th>Status</th><th>Actions</th></tr></thead><tbody>{rows.map(t => <tr key={t.txn_id}><td>{t.txn_date} · {t.txn_id}</td><td>{t.merchant ?? "—"} / {t.kind}</td><td>{money(t.amount_minor,t.currency)}</td><td>{t.fee_minor === null ? "—" : money(t.fee_minor,t.currency)}</td><td>{t.status}</td><td><a className="btn" href={`/transactions/${encodeURIComponent(t.txn_id)}/edit`}>Edit</a> <button className="btn danger" onClick={() => void remove(t)}>Delete</button></td></tr>)}</tbody></table></div>{!rows.length && <div className="empty"><h3>No matching records</h3><p>Try a different month or search term.</p></div>}</section>}
  </>;
}
export function ChatPage() {
  const [message, setMessage] = useState(""); const [result, setResult] = useState<(Awaited<ReturnType<typeof api.chat>> & Awaited<ReturnType<typeof api.reviewReceipt>>) | null>(null); const [err, setErr] = useState("");
  const [working, setWorking] = useState(false);
  const send = async (e: FormEvent) => { e.preventDefault(); setWorking(true); setErr(""); try { setResult(await api.chat(message)); } catch(e2) { setErr(e2 instanceof Error ? e2.message : "Assistant unavailable."); } finally { setWorking(false); } };
  const reviewReceipt = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault(); setWorking(true); setErr("");
    const file = new FormData(e.currentTarget).get("receipt");
    if (!(file instanceof File)) { setErr("Choose a receipt file first."); setWorking(false); return; }
    try { setResult(await api.reviewReceipt(file)); }
    catch (e2) { setErr(e2 instanceof Error ? e2.message : "Receipt review failed."); }
    finally { setWorking(false); }
  };
  const confirm = async () => { if (!result?.confirmation_card) return; try { await api.confirmTransaction(result.confirmation_card.txn_id); setResult(null); setMessage(""); } catch (e) { setErr(e instanceof Error ? e.message : "Confirmation failed."); } };
  const saveReceiptDate = async (txnDate: string) => {
    if (!result?.confirmation_card) return;
    await api.updatePendingDate(result.confirmation_card.txn_id, txnDate);
  };
  const discard = async () => { if (!result?.confirmation_card || !window.confirm("Discard this stored pending transaction?")) return; try { await api.deleteTransaction(result.confirmation_card.txn_id); setResult(null); } catch(e) { setErr(e instanceof Error ? e.message : "Pending transaction could not be discarded."); } };
  const receiptReview = result?.receipt_review;
  return <><PageHead title="A thoughtful second pair of eyes." description="Draft a transaction in your own words or review a receipt. AI assistance is optional."/><div className="grid cols-2"><section className="card stack"><div className="page-head"><h2>Today’s conversation</h2><Status text="Manual / regex mode"/></div><div className="notice warn">Local parsing works without AI. Optional extraction or wording is used only when a provider is configured and you have enabled AI consent.</div>
      {message && <div className="card sage">{message}</div>}{err && <div className="notice error" role="alert">{err}</div>}
      {result?.clarification && <div className="notice">Please clarify: {(result.missing ?? []).join(", ") || "more detail is needed"}.</div>}
      {receiptReview && <div className={`notice ${receiptReview.reconciliation === "mismatch" ? "warn" : "sage"}`} role="status">
        Receipt total check · {receiptReview.reconciliation}. {receiptReview.reconciliation === "mismatch" ? "The displayed total does not match the itemized subtotal and tax. This record will stay pending unless you explicitly confirm it." : receiptReview.reconciliation === "unverified" ? "The receipt total could not be fully reconciled. Review it carefully before confirming." : "The displayed total matches the itemized subtotal and tax."}
      </div>}
      {result?.confirmation_card && <ChatConfirmationCard card={result.confirmation_card} onConfirm={() => void confirm()} onDiscard={() => void discard()} onSaveDate={result.receipt_review ? saveReceiptDate : undefined}/>}
      {!result?.confirmation_card && <><form className="inline" onSubmit={send}><label style={{ flex: 1 }}>Describe a transaction<textarea required value={message} onChange={e => setMessage(e.target.value)} placeholder="For example: spent 850 on petrol"/></label><button disabled={working} className="btn primary">{working ? "Sending…" : "Send ↑"}</button></form><form className="inline" onSubmit={reviewReceipt}><label style={{ flex: 1 }}>Review a receipt (PDF, PNG, JPEG or TIFF)<input type="file" name="receipt" accept=".pdf,.png,.jpg,.jpeg,.tif,.tiff,application/pdf,image/png,image/jpeg,image/tiff" required/></label><button disabled={working} className="btn">{working ? "Reviewing…" : "Review receipt"}</button></form><p className="fine">Receipt files are discarded after review. If a total is recognized, only a pending draft is saved; it cannot affect reports until you confirm it.</p></>}
      <p className="fine">Every parsed transaction requires your confirmation. There is no auto-posting.</p>
    </section><aside className="stack"><div className="card"><h2>Available here</h2><p>Draft a transaction with rule-based parsing</p><p>Review the draft before posting</p><p>Use manual forms and deterministic reports</p></div><div className="card sage"><h2>You’re always the author</h2><p className="fine">Your approval is required before a transaction can post.</p><a className="btn" href="/settings">Manage AI consent</a></div></aside></div></>;
}
function BudgetsPage() {
  const [period, setPeriod] = useState(monthNow); const budget = useLoad<{period:string;budgets:Budget[]}>(() => api.budgets(period), [period]); const suggestions = useLoad<BudgetSuggestions>(() => api.budgetSuggestions(period), [period]); const cats = useLoad<{categories:Category[]}>(() => api.categories()); const dash = useLoad<Dashboard>(() => api.dashboard(period), [period]);
  const [error, setError] = useState("");
  const save = async (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const f = new FormData(e.currentTarget); if(!dash.data){setError("Base currency is not available. Try again when dashboard data loads.");return;} const limit = amountToMinor(String(f.get("limit")), dash.data.base_currency); if (limit === null) { setError("Enter a valid limit using the base currency precision."); return; } try { await api.saveBudget({ category_id:String(f.get("category")), period, limit_minor:limit }); setError(""); budget.reload(); } catch (e2) { setError(e2 instanceof Error ? e2.message : "Unable to save budget."); } };
  const approve = async (categoryId: string, category: string) => {
    if (!window.confirm(`Approve the suggested limit for ${category}?`)) return;
    try { await api.approveBudgetSuggestion(categoryId, period); budget.reload(); suggestions.reload(); setError(""); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to approve this suggestion."); }
  };
  const suggestionReason = suggestions.data?.reason === "insufficient_history"
    ? "More monthly history is needed before a suggestion can be calculated."
    : suggestions.data?.reason === "fx_rate_unavailable"
      ? "A required exchange rate is unavailable; no limit has been estimated."
      : "No category history is available for a suggestion.";
  return <><PageHead title="A budget that gives you room." description="Monthly limits are a guide, not a judgment."/><label style={{ maxWidth:220, marginBottom:15 }}>Period<input type="month" value={period} onChange={e => setPeriod(e.target.value)}/></label><LoadState loading={budget.loading} error={budget.error} retry={budget.reload}/><LoadState loading={dash.loading} error={dash.error} retry={dash.reload}/><div className="grid cols-2"><section className="card"><h2>All categories</h2>{budget.data?.budgets.length ? <div className="table-wrap"><table><thead><tr><th>Category</th><th>Monthly limit</th></tr></thead><tbody>{budget.data.budgets.map(b => <tr key={b.category_id}><td>{b.category}</td><td>{dash.data ? money(b.limit_minor,dash.data.base_currency) : "Currency unavailable"}</td></tr>)}</tbody></table></div> : !budget.loading && <div className="empty"><h3>No monthly limits yet</h3><p>Choose a category and set a limit when you're ready.</p></div>}</section><form className="card stack" onSubmit={save}><h2>Set a monthly limit</h2><label>Category<select name="category" required>{cats.data?.categories.map(c => <option key={c.category_id} value={c.category_id}>{c.name}</option>)}</select></label><p className="fine">Limit in your base currency{dash.data ? ` · ${dash.data.base_currency}` : ""}</p><label>Limit<input name="limit" inputMode="decimal" required/></label>{error && <div role="alert" className="notice error">{error}</div>}<button className="btn primary" disabled={!dash.data}>Save monthly limit</button></form></div>
    <section className="card sage" style={{marginTop:15}}><h2>Suggested limits</h2><p className="fine">Suggestions are never applied until you approve each category.</p><LoadState loading={suggestions.loading} error={suggestions.error} retry={suggestions.reload}/>{suggestions.data?.available && suggestions.data.suggestions.length ? suggestions.data.suggestions.map(s=><div key={s.category_id} className="calc-row"><b>{s.category}</b><span>{dash.data ? money(s.limit_minor,dash.data.base_currency) : "Currency unavailable"}</span><span>{s.scaled_to_ceiling ? "Scaled to the available ceiling" : "Based on your history"}</span><button className="btn primary" disabled={!dash.data} title={!dash.data ? "Base currency must load before approving" : undefined} onClick={()=>void approve(s.category_id,s.category)}>Approve suggestion</button></div>) : !suggestions.loading && !suggestions.error && <div className="empty">{suggestionReason}</div>}{error&&<div role="alert" className="notice error">{error}</div>}</section>
  </>;
}
function BillsPage() {
  const bills = useLoad<{bills:Bill[]}>(() => api.bills()); const [message, setMessage] = useState("");
  const add = async (e: FormEvent<HTMLFormElement>) => { e.preventDefault(); const f = new FormData(e.currentTarget); const currency = String(f.get("currency")); const amount = amountToMinor(String(f.get("amount")),currency); if (amount === null) { setMessage("Enter a valid amount."); return; } try { await api.createBill({ biller:String(f.get("biller")), amount_minor:amount,currency,next_due_date:String(f.get("date")),recurrence:String(f.get("recurrence")) }); setMessage(""); bills.reload(); e.currentTarget.reset(); } catch(e2) { setMessage(e2 instanceof Error ? e2.message : "Unable to add bill."); } };
  const remove = async (bill:Bill) => { if (!window.confirm(`Delete ${bill.biller}? This cannot be undone.`)) return; try { await api.deleteBill(bill.bill_id); bills.reload(); } catch(e) { setMessage(e instanceof Error ? e.message : "Unable to delete bill."); } };
  return <><PageHead title="Nothing slips through the month." description="Track your own bills. A bill is not a posted transaction."/><LoadState loading={bills.loading} error={bills.error} retry={bills.reload}/><div className="grid cols-2"><section className="card"><h2>Upcoming</h2>{bills.data?.bills.length ? <div className="table-wrap"><table><thead><tr><th>Biller</th><th>Due date</th><th>Original</th><th>Recurrence</th><th>Actions</th></tr></thead><tbody>{bills.data.bills.map(b=><tr key={b.bill_id}><td>{b.biller}</td><td>{b.next_due_date}</td><td>{money(b.amount_minor,b.currency)}</td><td>{b.recurrence}</td><td><button className="btn" onClick={()=>void remove(b)}>Delete</button></td></tr>)}</tbody></table></div> : !bills.loading && <div className="empty"><h3>No bills to track</h3><p>Add a bill to keep its due date in view.</p></div>}</section><form onSubmit={add} className="card stack"><h2>Add a bill</h2><label>Biller<input name="biller" required/></label><div className="form-grid"><label>Amount<input name="amount" required inputMode="decimal"/></label><label>Currency<select name="currency">{currencies.map(c=><option key={c}>{c}</option>)}</select></label><label>Next due date<input name="date" required type="date"/></label><label>Recurrence<select name="recurrence"><option>monthly</option><option>weekly</option><option>yearly</option><option>one-time</option></select></label></div>{message&&<div role="alert" className="notice error">{message}</div>}<button className="btn primary">Add bill</button></form></div></>;
}
function ReportsPage() {
  const [month, setMonth] = useState(monthNow);
  const [currency, setCurrency] = useState("");
  const [policy, setPolicy] = useState<Policy>("as_recorded");
  const dash = useLoad<Dashboard>(() => api.dashboard(month, currency || undefined, policy), [month, currency, policy]);
  if (dash.loading || dash.error || !dash.data) return <><PageHead title="Different currencies. One clear picture."/><LoadState loading={dash.loading} error={dash.error} retry={dash.reload}/></>;
  const d = dash.data;
  return <><PageHead title="Different currencies. One clear picture." description="Read-time reporting preserves every original amount and currency."/>
    <div className="inline" style={{marginBottom:15}}><label>Month<input type="month" value={month} onChange={e=>setMonth(e.target.value)}/></label><label>Report currency<select value={currency || d.report_currency} onChange={e=>setCurrency(e.target.value)}>{currencies.map(c=><option key={c}>{c}</option>)}</select></label><label>Rate policy<select value={policy} onChange={e=>setPolicy(e.target.value as Policy)}><option value="as_recorded">As recorded</option><option value="current">Current</option></select></label></div>
    <div className="grid cols-3"><Metric dark label="Reporting currency" value={d.report_currency}/><Metric label="Conversion policy" value={d.policy}/><Metric label="Analytics" value={d.analytics_available ? "Available" : "Not available"}/></div>
    <div className="notice warn" style={{margin:"15px 0"}}>Rates and conversions are presented only when supplied by the service. No missing rate is estimated here. Snapshot: {d.rates_snapshot ?? "not available"}{d.rates_snapshot_age_days === null ? "" : ` · ${d.rates_snapshot_age_days} days old`}</div>
    <section className="card"><h2>Currency effects</h2>{d.fx_effects.length ? <div className="table-wrap"><table><thead><tr><th>Currency</th><th>Volume effect</th><th>Rate effect</th><th>Base change</th><th>Identity</th></tr></thead><tbody>{d.fx_effects.map((fx,i)=><tr key={`${fx.currency}-${i}`}><td>{fx.currency} → {fx.base_currency}</td><td>{money(fx.volume_effect_minor,fx.base_currency)}</td><td>{money(fx.rate_effect_minor,fx.base_currency)}</td><td>{money(fx.base_change_minor,fx.base_currency)}</td><td>{fx.exact_identity ? "Exact" : "Not exact"}</td></tr>)}</tbody></table></div>:<div className="empty"><h3>No currency comparisons</h3><p>The API has not returned currency effects for this period.</p></div>}</section></>;
}
function InsightsPage() {
  const dash = useLoad<Dashboard>(() => api.dashboard(monthNow()));
  const insightData = useLoad(() => api.insights(monthNow()));
  const [expanded, setExpanded] = useState(false);
  if(dash.loading||dash.error||!dash.data)return <><PageHead title="The reasoning, not just the result."/><LoadState loading={dash.loading} error={dash.error} retry={dash.reload}/></>;
  const d=dash.data;
  return <><PageHead title="The reasoning, not just the result." description="Your own data. Deterministic facts. Explanations you can inspect."/><div className="grid cols-2"><section className="card sage"><div className="eyebrow">Dashboard facts · {d.month}</div><h2>What your month currently shows</h2><p>Expenses: {money(d.expenses_minor,d.report_currency)}. Income: {money(d.income_minor,d.report_currency)}.</p><p className="fine">Only values and facts returned by your dashboard are shown. No additional analysis is inferred.</p></section><section className="card"><h2>Month-end estimate</h2><div className="metric">{money(d.forecast_minor,d.forecast_currency)}</div><p className="fine">{d.forecast_label ?? "Forecast label not provided."}</p></section></div>
     <section className="card" style={{marginTop:15}}><h2>Verified guidance</h2><LoadState loading={insightData.loading} error={insightData.error} retry={insightData.reload}/>{insightData.data?.insights.length ? insightData.data.insights.map((item,i)=><div className="notice sage" key={`${item.kind}-${i}`}><p>{item.wording}</p><p className="fine">Computed from your saved budget facts · wording source: {item.source}</p></div>) : !insightData.loading && !insightData.error ? <div className="empty"><p>No budget categories are currently above their planned pace.</p></div> : null}</section>
    <section className="card" style={{marginTop:15}}><button className="btn" aria-expanded={expanded} onClick={()=>setExpanded(v=>!v)}>{expanded ? "Hide calculation facts" : "How is this calculated?"}</button>{expanded&&<div style={{marginTop:15}}><div className="eyebrow">Dashboard API facts · {d.month}</div><div className="calc-row"><b>Income</b><span>{money(d.income_minor,d.report_currency)}</span><span>API total · {d.policy}</span></div><div className="calc-row"><b>Expenses</b><span>{money(d.expenses_minor,d.report_currency)}</span><span>API total · {d.policy}</span></div><div className="calc-row"><b>Category limits</b><span>{d.categories.length} categories</span><span>Returned by dashboard</span></div><div className="calc-row"><b>Safe to spend</b><span>{money(d.safe_to_spend_today_minor,d.safe_to_spend_currency)}</span><span>Returned by dashboard</span></div>{d.categories.map(c=><div key={c.category_id} className="calc-row"><b>{c.name}</b><span>{c.pace ? `Pace ${c.pace}` : "Pace unavailable"}</span><span>Daily cap {money(c.daily_cap_minor,c.currency)}</span></div>)}{d.fx_effects.map((fx,i)=><div key={`${fx.currency}-${i}`} className="calc-row"><b>{fx.currency} FX decomposition</b><span>Volume {money(fx.volume_effect_minor,fx.base_currency)}</span><span>Rate {money(fx.rate_effect_minor,fx.base_currency)}</span></div>)}<p className="fine">Values and explanatory facts are supplied by the dashboard API; missing rates and calculations are not estimated in the interface.</p></div>}</section>
    <div className="grid cols-2" style={{marginTop:15}}><section className="card"><h2>Category facts</h2>{d.categories.length?d.categories.map(c=><div key={c.category_id} className="calc-row"><b>{c.name}</b><span>{money(c.spent_minor,c.currency)} spent</span><span>{c.status}</span></div>):<div className="empty">No category facts supplied.</div>}</section><section className="card sage"><h2>Alerts</h2>{d.alerts.length ? d.alerts.map((a,i)=><p key={`${a.category_id}-${i}`}>{d.categories.find(c=>c.category_id===a.category_id)?.name ?? "Category"} · {a.status}</p>) : <div className="empty">No alerts returned for this period.</div>}</section></div></>;
}
function SettingsPage({ user }: { user:AuthUser|null }) {
  const settings=useLoad<{ai_consent:boolean;mfa_enabled:boolean}>(()=>api.settings());
  const sessions=useLoad<{sessions:SessionRecord[]}>(()=>api.sessions());
  const [msg,setMsg]=useState("");
  const [dataAction,setDataAction]=useState<"export"|"delete"|null>(null);
  const [dataBusy,setDataBusy]=useState(false);
  const consent=async(enabled:boolean)=>{try{await api.setAiConsent(enabled);settings.reload();setMsg("Your AI preference was updated.");}catch(e){setMsg(e instanceof Error?e.message:"Unable to update preference.");}};
  const revoke=async(s:SessionRecord)=>{if(!window.confirm(s.is_current?"Sign out this session?":"Revoke this session?"))return;try{if(s.is_current){await api.revokeCurrent();location.href="/login";return;}await api.revokeSession(s.session_id);sessions.reload();setMsg("Session revoked.");}catch(e){setMsg(e instanceof Error?e.message:"Unable to revoke session.");}};
  const exportData=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const form=e.currentTarget;const values=new FormData(form);setDataBusy(true);try{const file=await api.exportAccountData(String(values.get("current_password")),String(values.get("current_code")||"")||undefined);const url=URL.createObjectURL(file);const link=document.createElement("a");link.href=url;link.download="account-export.json";document.body.append(link);link.click();link.remove();window.setTimeout(()=>URL.revokeObjectURL(url),1000);form.reset();setDataAction(null);setMsg("Your account export has downloaded.");}catch(e){setMsg(e instanceof Error?e.message:"Unable to export your data.");}finally{setDataBusy(false);}};
  const deleteAccount=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();if(!window.confirm("Permanently delete your account and sign out all devices? This cannot be undone."))return;const values=new FormData(e.currentTarget);setDataBusy(true);try{await api.deleteAccount(String(values.get("current_password")),String(values.get("confirmation")),String(values.get("current_code")||"")||undefined);location.href="/login";}catch(e){setMsg(e instanceof Error?e.message:"Unable to delete your account.");setDataBusy(false);}};
  return <><PageHead title="Your profile. Your boundaries." description="Manage your own account, sessions and privacy choices."/>
    <nav className="tabs" aria-label="Settings sections"><a href="#profile">Profile & privacy</a><a href="#accounts">Accounts</a><a href="#security">Security & sessions</a><a href="#data">Your data</a></nav>
    {msg&&<div className="notice" role="status">{msg}</div>}
    <div className="grid cols-2">
      <div className="stack">
        <AccountsPanel/>
        <section id="profile" className="card"><h2>Personal profile</h2><div className="fine">Account ID · {user?.user_id ?? "Assigned by server"}<br/>Role · {user?.role ?? "user"}<br/>Base currency · Set during registration</div></section>
        <section id="security" className="card"><h2>Security & sessions</h2><p>Authenticator MFA · {settings.data ? settings.data.mfa_enabled ? "Enabled" : "Not enabled" : "Loading…"}</p><div className="inline">{settings.data?.mfa_enabled ? (user?.role === "user" ? <MfaDisablePanel onDone={settings.reload}/> : <span className="fine">MFA is mandatory for your role.</span>) : <a className="btn" href="/mfa/enroll">Set up MFA</a>}<a className="btn" href="/forgot">Reset password</a></div><LoadState loading={sessions.loading} error={sessions.error} retry={sessions.reload}/>{sessions.data?.sessions.length ? <div className="table-wrap"><table><thead><tr><th>Session</th><th>Last activity</th><th>Action</th></tr></thead><tbody>{sessions.data.sessions.map(s=><tr key={s.session_id}><td>{s.is_current?"This browser · current":s.session_id}</td><td>{s.last_seen_at}</td><td><button className="btn" onClick={()=>void revoke(s)}>{s.is_current?"Sign out":"Revoke"}</button></td></tr>)}</tbody></table></div>:!sessions.loading&&!sessions.error&&<div className="empty">No active sessions provided.</div>}</section>
      </div>
      <div className="stack">
        <section className="card"><h2>Optional AI, your choice</h2><LoadState loading={settings.loading} error={settings.error} retry={settings.reload}/>{settings.data&&<><p>AI assistance · {settings.data.ai_consent ? "On" : "Off"}</p><label><span><input type="checkbox" style={{width:"auto"}} checked={settings.data.ai_consent} onChange={e=>void consent(e.target.checked)}/> I choose to enable optional AI processing.</span></label></>}<p className="fine">AI processing requires both your consent and a configured provider. Without both, parsing and insights use deterministic local rules.</p></section>
        <section id="data" className="card"><h2>Your data, in plain language</h2><p className="fine">Export a copy of your saved account data, or permanently delete your account. Both actions require your current password and, when enabled, an authenticator code.</p>
          <div className="inline"><button className="btn" onClick={()=>setDataAction(dataAction==="export"?null:"export")}>Export my data</button><button className="btn danger" onClick={()=>setDataAction(dataAction==="delete"?null:"delete")}>Delete my account</button></div>
          {dataAction==="export"&&<form className="stack" style={{marginTop:16}} onSubmit={exportData}><h3>Confirm export</h3><label>Current password<input name="current_password" type="password" required autoComplete="current-password"/></label><label>Authenticator code, if enabled<input name="current_code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code"/></label><div className="inline"><button className="btn" type="button" onClick={()=>setDataAction(null)}>Cancel</button><button className="btn primary" disabled={dataBusy}>{dataBusy?"Preparing…":"Download my data"}</button></div></form>}
          {dataAction==="delete"&&<form className="stack" style={{marginTop:16}} onSubmit={deleteAccount}><h3>Delete this account</h3><p className="fine">This permanently signs you out everywhere and makes your encrypted account data unrecoverable. Limited security audit records may remain. Type DELETE to confirm.</p><label>Type DELETE<input name="confirmation" required pattern="DELETE" autoComplete="off"/></label><label>Current password<input name="current_password" type="password" required autoComplete="current-password"/></label><label>Authenticator code, if enabled<input name="current_code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code"/></label><div className="inline"><button className="btn" type="button" onClick={()=>setDataAction(null)}>Cancel</button><button className="btn danger" disabled={dataBusy}>{dataBusy?"Deleting…":"Permanently delete account"}</button></div></form>}
        </section>
      </div>
    </div>
  </>;
}
export function ChangePasswordPage() {
  const [message,setMessage]=useState("");
  const [changed,setChanged]=useState(false);
  const submit=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const formElement=e.currentTarget;const form=new FormData(formElement);try{await api.changePassword(String(form.get("current")),String(form.get("next")),String(form.get("code")||"")||undefined);formElement.reset();setMessage("Password updated. All sessions were revoked.");setChanged(true);}catch(err){setMessage(err instanceof Error?err.message:"Unable to update password.");}};
  return <><PageHead title="Choose a new password." description="Only you can change the password for your personal account."/><form className="card stack" style={{maxWidth:600}} onSubmit={submit}><label>Current password<input name="current" type="password" required autoComplete="current-password"/></label><label>New password<input name="next" type="password" minLength={12} required autoComplete="new-password"/></label><label>Authenticator code, if required<input name="code" inputMode="numeric" autoComplete="one-time-code"/></label>{message&&<div role="status" className="notice">{message}{changed&&<> <a href="/login">Sign in again</a></>}</div>}<div className="inline"><a href="/settings" className="btn">Cancel</a><button className="btn primary">Update password</button></div></form></>;
}
export function AdminPage({user}:{user:AuthUser}) {
  const stats=useLoad(()=>api.adminStats());
  if(user.role!=="admin")return <Denied/>;
  return <><PageHead title="An operational view. Nothing personal." description="Read-only system statistics, counts only."/><div className="notice">Read-only by design. Financial records, individual finances, chat, audit events and security actions are not available to admin.</div><LoadState loading={stats.loading} error={stats.error} retry={stats.reload}/>{stats.data&&<div className="grid cols-3" style={{marginTop:15}}><Metric dark label="Active users" value={String(stats.data.active_users)}/><Metric label="Transactions · 24h" value={String(stats.data.txns_24h)}/><Metric label="Failed logins · 24h" value={String(stats.data.failed_logins_24h)}/></div>}<StaffUsersPanel canManage={false}/><section className="card admin" style={{marginTop:15}}><h2>Your permission boundary</h2><p className="fine">Counts only. No amounts, merchants, personal text, transaction list or edit controls are shown in this role.</p></section></>;
}
function AuditPage({user}:{user:AuthUser}) {
  const audit=useLoad<{events:AuditEvent[]}>(()=>api.auditEvents());
  if(user.role!=="security_owner")return <Denied/>;
  return <><PageHead title="An audit trail with less exposure." description="Sanitised security events · security owner only."/><LoadState loading={audit.loading} error={audit.error} retry={audit.reload}/>{audit.data&&<section className="card"><h2>Security events</h2>{audit.data.events.length?<div className="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Result</th></tr></thead><tbody>{audit.data.events.map(ev=><tr key={ev.id}><td>{ev.ts}</td><td>{ev.action}</td><td>{ev.result}</td></tr>)}</tbody></table></div>:<div className="empty"><h3>No audit events</h3><p>No sanitised security events were returned.</p></div>}</section>}<StaffUsersPanel canManage/><div className="notice sage" style={{marginTop:15}}>This view contains security events only, never financial records or transaction details.</div></>;
}
function Denied() { return <div className="card"><div className="eyebrow">404 · Resource unavailable</div><h1>This page isn’t part of your workspace.</h1><p>We don’t reveal whether another person’s record exists.</p><a className="btn primary" href="/">Return to my workspace →</a></div>; }
function MfaEnroll() {
  const [uri,setUri]=useState("");const[error,setError]=useState("");
  const begin=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const f=new FormData(e.currentTarget);try{const r=await api.beginMfa(String(f.get("password")),String(f.get("current_code")||"")||undefined);setUri(r.provisioning_uri);setError("");}catch(e2){setError(e2 instanceof Error?e2.message:"Unable to begin MFA setup.");}};
  const finish=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await api.confirmMfa(String(f.get("code")));location.href="/settings";}catch(e2){setError(e2 instanceof Error?e2.message:"MFA confirmation failed.");}};
  return <><PageHead title="One more layer of care." description="Set up your authenticator and verify a current code."/><div className="card" style={{maxWidth:650}}><form className="stack" onSubmit={begin}><label>Current password<input type="password" name="password" required autoComplete="current-password"/></label><label>Current authenticator code, if already enabled<input type="text" name="current_code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code"/></label><button className="btn primary">Begin secure setup</button></form>{uri&&<><MfaQrCode uri={uri}/><form onSubmit={finish} className="stack"><label>Authenticator code<input name="code" inputMode="numeric" pattern="[0-9]{6}" required/></label><button className="btn primary">Confirm MFA</button></form></>}{error&&<div className="notice error" role="alert">{error}</div>}</div></>;
}
function App() {
  const path=location.pathname;
  const isAuth=["/login","/signup","/forgot","/reset","/reset-password","/mfa"].includes(path);
  const authKind=path==="/signup"?"signup":path==="/forgot"?"forgot":path==="/reset"||path==="/reset-password"?"reset":path==="/mfa"?"mfa":"login";
  const me=useLoad<AuthUser>(()=>api.me(),[],isAuth);
  if(isAuth)return <AuthPage kind={authKind}/>;
  if(me.loading)return <main className="content"><div className="card" aria-label="Loading workspace"><div className="metric-label">Opening your workspace</div><div className="fine">Checking your assigned role…</div></div></main>;
  if(me.error)return <AuthPage kind="login"/>;
  const user=me.data;
  if(user?.role==="admin"&&!path.startsWith("/admin"))return <Frame user={user} title="Access denied"><Denied/></Frame>;
  if(user?.role==="security_owner"&&!path.startsWith("/security"))return <Frame user={user} title="Access denied"><Denied/></Frame>;
  let page:ReactNode;
  if(path==="/admin"||path==="/admin/")page=user?<AdminPage user={user}/>:<Denied/>;
  else if(path==="/security-audit")page=user?<AuditPage user={user}/>:<Denied/>;
  else if(path==="/security")page=user?.role==="security_owner"?<AuditPage user={user}/>:<Denied/>;
  else if(path==="/transactions/new")page=<AddTransaction/>;
  else if(path==="/mfa/enroll")page=<MfaEnroll/>;
  else if(path==="/settings/password")page=<ChangePasswordPage/>;
  else if(path.startsWith("/transactions/")&&path.endsWith("/edit"))page=<AddTransaction edit txnId={path.split("/")[2]}/>;
  else if(path==="/ledger")page=<TransactionsPage/>;
  else if(path==="/assistant")page=<ChatPage/>;
  else if(path==="/plan")page=<BudgetsPage/>;
  else if(path==="/bill-calendar")page=<BillsPage/>;
  else if(path==="/reports")page=<ReportsPage/>;
  else if(path==="/insights")page=<InsightsPage/>;
  else if(path==="/settings")page=<SettingsPage user={user}/>;
  else if(user?.role==="admin"||user?.role==="security_owner")page=<Denied/>;
  else page=<DashboardPage/>;
  return <Frame user={user} title={path.replace("/", "") || "Overview"}>{page}</Frame>;
}
export default App;
