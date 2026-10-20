export type Role = "user" | "admin" | "security_owner";
export type Policy = "as_recorded" | "current";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  const mutating = !["GET", "HEAD", "OPTIONS"].includes(method);
  if (mutating) {
    headers["Content-Type"] = "application/json";
    headers["X-Requested-With"] = "pfa";
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError("The service could not be reached. Try again.", 0);
  }
  if (!response.ok) {
    let message = "That request could not be completed.";
    try {
      const error = (await response.json()) as { detail?: unknown; message?: unknown };
      if (typeof error.detail === "string") message = error.detail;
      else if (typeof error.message === "string") message = error.message;
    } catch {
      // Keep the generic message if the server returned a non-JSON error page.
    }
    throw new ApiError(message, response.status);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const query = (params: Record<string, string | undefined>) => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined) search.set(key, value);
  });
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
};

export interface AuthUser {
  user_id: string;
  role: Role;
  mfa_ok: boolean;
  mfa_enabled?: boolean;
  ai_consent?: boolean;
}

export interface Category {
  category_id: string;
  name: string;
}

export interface DashboardCategory {
  category_id: string;
  name: string;
  limit_minor: number;
  spent_minor: number | null;
  status: string;
  pace: string | null;
  daily_cap_minor: number | null;
  currency: string;
}

export interface FxEffect {
  currency: string;
  base_currency: string;
  previous_month: string;
  month: string;
  volume_effect_minor: number;
  rate_effect_minor: number;
  base_change_minor: number;
  exact_identity: boolean;
}

export interface Dashboard {
  month: string;
  base_currency: string;
  report_currency: string;
  policy: Policy;
  rates_snapshot: string | null;
  rates_snapshot_age_days: number | null;
  fx_snapshots: Array<{
    date: string;
    age_days: number;
    source: string;
    estimated: boolean;
  }>;
  rate_sources: string[];
  rate_attribution: string;
  rate_attribution_url: string;
  income_minor: number | null;
  expenses_minor: number | null;
  fees_minor: number | null;
  fees_currency: string;
  categories: DashboardCategory[];
  safe_to_spend_today_minor: number | null;
  safe_to_spend_currency: string;
  forecast_minor: number | null;
  forecast_currency: string;
  forecast_label: string | null;
  alerts: Array<{ category_id: string; status: string }>;
  pending_count: number;
  analytics_available: boolean;
  report_conversion_available: boolean;
  unavailable_currencies: string[];
  fx_effects: FxEffect[];
}

export interface Transaction {
  txn_id: string;
  category_id: string | null;
  account_id: string | null;
  kind: "expense" | "income" | "refund" | "transfer";
  status: "posted" | "pending";
  currency: string;
  amount_minor: number;
  merchant: string | null;
  note: string | null;
  fee_minor: number | null;
  txn_date: string;
  fx_date: string;
  fx_override_rate: string | null;
  fx_rate_source: string | null;
  source: string;
}

export interface Budget {
  budget_id?: string;
  category_id: string;
  category: string;
  limit_minor: number;
}

export interface BudgetSuggestions {
  period: string;
  available: boolean;
  reason: string | null;
  expected_monthly_income_minor?: number | null;
  suggestions: Array<{
    category_id: string;
    category: string;
    limit_minor: number;
    scaled_to_ceiling: boolean;
  }>;
}

export interface Bill {
  bill_id: string;
  biller: string;
  amount_minor: number;
  currency: string;
  next_due_date: string;
  recurrence: string;
  is_active: boolean;
}

export interface SessionRecord {
  session_id: string;
  is_current: boolean;
  issued_at: string;
  last_seen_at: string;
  expires_at: string;
  revoked_at: string | null;
  mfa_ok: boolean;
}

export interface AuditEvent {
  id: number;
  ts: string;
  action: string;
  result: string;
}

export interface MoneyAccount {
  account_id: string;
  name: string;
  type: "cash" | "bank" | "card" | "wallet";
  currency: string;
}

export interface StaffUserRecord {
  user_id: string;
  email_masked: string;
  role: Role;
  status: "active" | "locked";
  temporarily_locked: boolean;
  mfa_enabled: boolean;
  created_at: string;
}

const json = <T,>(path: string, body: unknown, method = "POST") =>
  request<T>(path, method, body);

export const api = {
  register: (body: {
    email: string;
    password: string;
    base_currency: string;
    privacy_consent: boolean;
    ai_consent: boolean;
  }) => json<{ message: string }>("/auth/register", body),
  login: (email: string, password: string) =>
    json<{ mfa_required: boolean }>("/auth/login", { email, password }),
  me: () => request<AuthUser>("/auth/me"),
  verifyMfa: (code: string) =>
    json<{ authenticated: boolean }>("/auth/mfa/verify", { code }),
  beginMfa: (current_password: string, current_code?: string) =>
    json<{ provisioning_uri: string }>("/auth/mfa/enroll", {
      current_password,
      current_code,
    }),
  confirmMfa: (code: string) =>
    json<void>("/auth/mfa/confirm", { code }),
  resetRequest: (email: string) =>
    json<{ message: string }>("/auth/password/reset", { email }),
  resetConfirm: (token: string, new_password: string) =>
    json<void>("/auth/password/reset/confirm", { token, new_password }),
  changePassword: (current_password: string, new_password: string, current_code?: string) =>
    json<void>("/auth/password/change", {
      current_password,
      new_password,
      current_code,
    }),
  logout: () => json<void>("/auth/logout", {}),
  revokeCurrent: () => json<void>("/auth/sessions/revoke-current", {}),
  sessions: () => request<{ sessions: SessionRecord[] }>("/auth/sessions"),
  revokeSession: (sessionId: string) =>
    json<void>(`/auth/sessions/${encodeURIComponent(sessionId)}/revoke`, {}),
  exportAccountData: async (current_password: string, current_code?: string) => {
    let response: Response;
    try {
      response = await fetch("/me/export", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Requested-With": "pfa",
        },
        credentials: "same-origin",
        body: JSON.stringify({ current_password, current_code }),
      });
    } catch {
      throw new ApiError("The service could not be reached. Try again.", 0);
    }
    if (!response.ok) {
      let message = "That request could not be completed.";
      try {
        const error = (await response.json()) as { detail?: unknown };
        if (typeof error.detail === "string") message = error.detail;
      } catch {
        // Keep the generic message if the server returned a non-JSON error page.
      }
      throw new ApiError(message, response.status);
    }
    return response.blob();
  },
  deleteAccount: (
    current_password: string,
    confirmation: string,
    current_code?: string,
  ) =>
    json<void>("/me/delete", {
      current_password,
      current_code,
      confirmation,
    }),
  categories: () => request<{ categories: Category[] }>("/categories"),
  dashboard: (month: string, currency?: string, policy?: Policy) =>
    request<Dashboard>(
      `/dashboard${query({ month, currency, policy })}`,
    ),
  transactions: (month: string) =>
    request<{ month: string; transactions: Transaction[] }>(
      `/transactions${query({ month })}`,
    ),
  transaction: (transactionId: string) =>
    request<Transaction>(`/transactions/${encodeURIComponent(transactionId)}`),
  createTransaction: (body: {
    kind: Transaction["kind"];
    amount_minor: number;
    currency: string;
    merchant: string;
    txn_date: string;
    category_id?: string;
    account_id?: string;
    note?: string;
    fee_minor?: number;
  }) => json<{ txn_id: string; status: string }>("/transactions", body),
  updateTransaction: (transactionId: string, body: {
    kind: Transaction["kind"];
    amount_minor: number;
    currency: string;
    merchant: string;
    txn_date: string;
    category_id?: string;
    account_id?: string;
    note?: string;
    fee_minor?: number;
    fx_override_rate?: string;
  }) =>
    json<{ txn_id: string; status: string }>(
      `/transactions/${encodeURIComponent(transactionId)}`,
      body,
      "PUT",
    ),
  updatePendingDate: (transactionId: string, txn_date: string) =>
    json<{ txn_id: string; status: string; txn_date: string }>(
      `/transactions/${encodeURIComponent(transactionId)}/date`,
      { txn_date },
      "PUT",
    ),
  confirmTransaction: (transactionId: string) =>
    json<{ txn_id: string; status: string }>(
      `/transactions/${encodeURIComponent(transactionId)}/confirm`,
      {},
    ),
  deleteTransaction: (transactionId: string) =>
    json<void>(`/transactions/${encodeURIComponent(transactionId)}`, {}, "DELETE"),
  budgets: (period: string) =>
    request<{ period: string; budgets: Budget[] }>(`/budgets${query({ period })}`),
  saveBudget: (body: { category_id: string; period: string; limit_minor: number }) =>
    json<Budget>("/budgets", body, "PUT"),
  budgetSuggestions: (period: string) =>
    request<BudgetSuggestions>(`/budgets/suggestions${query({ period })}`),
  approveBudgetSuggestion: (categoryId: string, period: string) =>
    json<Budget>(
      `/budgets/suggestions/${encodeURIComponent(categoryId)}/approve`,
      { period },
    ),
  bills: () => request<{ bills: Bill[] }>("/bills"),
  createBill: (body: {
    biller: string;
    amount_minor: number;
    currency: string;
    next_due_date: string;
    recurrence: string;
  }) => json<Bill>("/bills", body),
  deleteBill: (billId: string) =>
    json<void>(`/bills/${encodeURIComponent(billId)}`, {}, "DELETE"),
  chat: (message: string) =>
    json<{
      clarification?: boolean;
      missing?: string[];
      confirmation_required?: boolean;
      confirmation_card?: {
        txn_id: string;
        kind: Transaction["kind"];
        amount_minor: number;
        currency: string;
        merchant: string;
        category_id: string | null;
        txn_date?: string;
        receipt_date_detected?: boolean;
      };
    }>("/chat", { message }),
  reviewReceipt: async (file: File) => {
    const contentBase64 = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const dataUrl = String(reader.result ?? "");
        const comma = dataUrl.indexOf(",");
        if (comma < 0) reject(new Error("Unable to read this receipt."));
        else resolve(dataUrl.slice(comma + 1));
      };
      reader.onerror = () => reject(new Error("Unable to read this receipt."));
      reader.readAsDataURL(file);
    });
    const extension = file.name.toLowerCase().split(".").pop();
    const contentType =
      file.type ||
      (extension === "pdf" ? "application/pdf" :
        extension === "png" ? "image/png" :
          extension === "jpg" || extension === "jpeg" ? "image/jpeg" :
            extension === "tif" || extension === "tiff" ? "image/tiff" : "");
    return json<{
      clarification?: boolean;
      missing?: string[];
      confirmation_required?: boolean;
      confirmation_card?: {
        txn_id: string;
        kind: Transaction["kind"];
        amount_minor: number;
        currency: string;
        merchant: string;
        category_id: string | null;
        txn_date?: string;
        receipt_date_detected?: boolean;
      };
      receipt_review?: {
        text_source: string;
        status: "pending";
        purchase_date: string | null;
        reconciliation: "matched" | "mismatch" | "unverified";
        subtotal_minor: number | null;
        tax_minor: number | null;
        expected_total_minor: number | null;
        printed_total_minor: number;
      };
    }>("/receipts/review", {
      filename: file.name,
      content_type: contentType,
      content_base64: contentBase64,
    });
  },
  insights: (month?: string) =>
    request<{
      month: string;
      insights: {
        kind: string;
        source: "llm" | "template";
        wording: string;
        facts: Record<string, string | number>;
      }[];
    }>(`/api/insights${month ? `?month=${encodeURIComponent(month)}` : ""}`),
  settings: () => request<{ ai_consent: boolean; mfa_enabled: boolean }>("/me/settings"),
  setAiConsent: (enabled: boolean) =>
    json<{ ai_consent: boolean }>("/me/ai-consent", { enabled }, "PUT"),
  adminStats: () =>
    request<{ active_users: number; txns_24h: number; failed_logins_24h: number }>(
      "/admin/stats",
    ),
  auditEvents: () =>
    request<{ events: AuditEvent[] }>("/security/audit"),
  accounts: () => request<{ accounts: MoneyAccount[] }>("/accounts"),
  createAccount: (body: { name: string; type: MoneyAccount["type"]; currency: string }) =>
    json<MoneyAccount>("/accounts", body),
  deleteMoneyAccount: (accountId: string) =>
    json<void>(`/accounts/${encodeURIComponent(accountId)}`, {}, "DELETE"),
  disableMfa: (current_password: string, current_code: string) =>
    json<void>("/auth/mfa/disable", { current_password, current_code }),
  staffUsers: () => request<{ users: StaffUserRecord[] }>("/security/users"),
  staffAction: (userId: string, action: "lock" | "unlock" | "force-reset") =>
    json<void>(`/security/users/${encodeURIComponent(userId)}/${action}`, {}),
  changeRole: (userId: string, role: Role, current_password: string, current_code: string) =>
    json<void>(
      `/security/users/${encodeURIComponent(userId)}/role`,
      { role, current_password, current_code },
      "PUT",
    ),
};
