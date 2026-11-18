/* Small frontend controller.
   The bearer token is kept in memory rather than localStorage, so refreshing
   the page signs the user out. Active users are kept signed in through
   /auth/refresh after an explicit "Stay signed in" prompt. */
"use strict";

const SESSION_WARNING_SECONDS = 120;
const DRAFT_PREFIX = "tradedesk-draft:";
const REPORT_SECTIONS = [
  "work_performed",
  "findings_observations",
  "recommendations",
  "suggested_follow_up",
];
// Draft placeholder text from the server. Shown as an empty field so an
// untouched placeholder never reaches the client PDF.
const PLACEHOLDERS = new Set([
  "Not separately specified in the supplied notes.",
  "Confirm follow-up needs with the customer if applicable.",
]);

let accessToken = null;
let accountKey = null;
let customers = [];
let jobs = [];
let activeReport = null;
let warningTimer = null;
let expiryTimer = null;

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

class SessionExpiredError extends Error {}

let noticeTimer = null;

function showNotice(message, kind = "success") {
  const notice = $("#notice");
  notice.textContent = message; // textContent prevents HTML injection from API data.
  notice.className = `notice ${kind}`;
  notice.setAttribute("role", kind === "error" ? "alert" : "status");
  // The notice stays pinned to the top of the screen (audit U8), so success
  // messages clear themselves; errors stay until the next action.
  clearTimeout(noticeTimer);
  if (kind === "success") {
    noticeTimer = setTimeout(() => { notice.textContent = ""; }, 8000);
  }
}

// Busy states (re-audit U-N1, audit U13). While a request runs, the form's
// buttons (or the clicked button's row) are disabled, so a double click or a
// second Enter cannot create a duplicate customer, job, task, or report.
function guarded(handler) {
  return async (event) => {
    const target = event.currentTarget;
    if (target.dataset.busy === "true") {
      event.preventDefault();
      return;
    }
    const row = target.tagName === "FORM" ? target : (target.closest(".button-row") || target);
    const controls = target.tagName === "BUTTON" && row === target
      ? [target]
      : Array.from(row.querySelectorAll("button"));
    const wasDisabled = controls.map((control) => control.disabled);
    target.dataset.busy = "true";
    row.setAttribute("aria-busy", "true");
    for (const control of controls) control.disabled = true;
    try {
      await handler(event);
    } finally {
      delete target.dataset.busy;
      row.removeAttribute("aria-busy");
      controls.forEach((control, index) => { control.disabled = wasDisabled[index]; });
      if (row.closest && row.closest("#reportArea")) syncReportButtons();
    }
  };
}

function formObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const sentToken = accessToken;
  if (sentToken) headers.Authorization = `Bearer ${sentToken}`;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401 && sentToken) {
    endSession({ expired: true });
    throw new SessionExpiredError("Your session ended. Sign in again to continue.");
  }
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    // Show server validation messages without dumping raw response or stack traces.
    const detail = data && typeof data.detail === "string" ? data.detail : "Request failed. Please check your input.";
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return data;
}

function reportError(error, fallback) {
  // A session-expiry notice has already been shown.
  if (error instanceof SessionExpiredError) return;
  showNotice(error.message || fallback, "error");
}

// Panels

const PANELS = ["#authPanel", "#verificationPanel", "#forgotPanel", "#resetPanel", "#appPanel"];

function showPanel(id) {
  for (const panel of PANELS) $(panel).classList.toggle("hidden", panel !== id);
  $("#logoutButton").classList.toggle("hidden", id !== "#appPanel");
}

function showVerificationPanel(message) {
  showPanel("#verificationPanel");
  $("#verificationMessage").textContent = message;
}

for (const button of $$(".back-to-sign-in")) {
  button.addEventListener("click", () => showPanel("#authPanel"));
}

$("#forgotPasswordLink").addEventListener("click", () => {
  const email = $("#authForm").elements.email.value;
  if (email) $("#forgotForm").elements.email.value = email;
  showPanel("#forgotPanel");
});

// Session lifecycle

function tokenSubject(token) {
  try {
    const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return String(JSON.parse(atob(payload)).sub || "");
  } catch {
    return "";
  }
}

function startSession(tokenResponse) {
  accessToken = tokenResponse.access_token;
  accountKey = tokenSubject(accessToken);
  scheduleSessionTimers(tokenResponse.expires_in_seconds);
}

function clearSessionTimers() {
  clearTimeout(warningTimer);
  clearTimeout(expiryTimer);
  warningTimer = null;
  expiryTimer = null;
  $("#sessionBanner").classList.add("hidden");
}

function scheduleSessionTimers(expiresInSeconds) {
  clearSessionTimers();
  const seconds = Number(expiresInSeconds) || 0;
  const warnIn = Math.max(seconds - SESSION_WARNING_SECONDS, 0) * 1000;
  warningTimer = setTimeout(() => {
    $("#sessionBanner").classList.remove("hidden");
  }, warnIn);
  expiryTimer = setTimeout(() => endSession({ expired: true }), seconds * 1000);
}

$("#staySignedInButton").addEventListener("click", guarded(async () => {
  try {
    const data = await api("/auth/refresh", { method: "POST" });
    startSession(data);
    showNotice("You're still signed in.");
  } catch (error) {
    reportError(error, "Could not extend your session.");
  }
}));

function clearDrafts() {
  try {
    for (const key of Object.keys(sessionStorage)) {
      if (key.startsWith(DRAFT_PREFIX)) sessionStorage.removeItem(key);
    }
  } catch { /* storage unavailable */ }
}

function resetSelect(select, label) {
  select.replaceChildren();
  addOption(select, "", label);
}

// Remove every trace of the signed-in account from the page (audit S1).
function clearAccountUi() {
  customers = [];
  jobs = [];
  activeReport = null;
  for (const list of ["#customerList", "#jobList", "#taskList", "#reportHistory"]) {
    $(list).replaceChildren();
  }
  resetSelect($("#jobCustomer"), "Create a customer first");
  resetSelect($("#reportJob"), "Create a job first");
  resetSelect($("#taskJob"), "Create a job first");
  for (const form of ["#customerForm", "#jobForm", "#reportForm", "#taskForm", "#authForm", "#resetForm"]) {
    $(form).reset();
  }
  for (const section of REPORT_SECTIONS) $(`#section_${section}`).value = "";
  $("#reportArea").classList.add("hidden");
}

function endSession({ expired = false } = {}) {
  if (!accessToken && !expired) return;
  accessToken = null;
  accountKey = null;
  clearSessionTimers();
  // Keep unsaved report edits after an expiry so they can be restored on
  // sign-in in this tab; discard them on an explicit sign-out.
  if (!expired) clearDrafts();
  clearAccountUi();
  showPanel("#authPanel");
  if (expired) {
    showNotice("Your session ended. Sign in again to continue; unsaved report edits in this tab will be restored.", "error");
  }
}

$("#logoutButton").addEventListener("click", async () => {
  try {
    if (accessToken) await api("/auth/logout", { method: "POST" });
    showNotice("Signed out.");
  } catch (error) {
    if (!(error instanceof SessionExpiredError)) {
      showNotice("Server sign-out could not be confirmed. This browser session was cleared.", "error");
    }
  }
  clearDrafts();
  endSession();
});

// Sign in, registration, verification, password reset

function addOption(select, value, label) {
  const option = document.createElement("option");
  option.value = String(value);
  option.textContent = label; // Never use untrusted API values as HTML.
  select.append(option);
}

$("#authForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const mode = event.submitter?.dataset.mode || "login";
  const credentials = formObject(form);

  try {
    const data = await api(`/auth/${mode === "register" ? "register" : "login"}`, {
      method: "POST",
      body: JSON.stringify(credentials),
    });

    if (mode === "register") {
      $("#resendVerificationForm").elements.email.value = credentials.email;
      form.reset();
      showVerificationPanel("Your account was created. Check your email for a verification link before signing in.");
      showNotice("Account created. Email verification is required.");
      return;
    }

    form.reset();
    startSession(data);
    showPanel("#appPanel");
    await refreshAll();
    showNotice("Signed in.");
  } catch (error) {
    if (mode !== "register" && error.status === 403) {
      // Unverified account (audit U12): go straight to the resend screen
      // instead of leaving the user on sign-in with no way forward.
      $("#resendVerificationForm").elements.email.value = credentials.email;
      showVerificationPanel("Your email address isn't verified yet. Open the link we emailed you, or send a new one below.");
      showNotice(error.message, "error");
      return;
    }
    reportError(error, "Unable to sign in.");
  }
}));

$("#resendVerificationForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  try {
    const response = await api("/auth/resend-verification", {
      method: "POST",
      body: JSON.stringify(formObject(event.currentTarget)),
    });
    showNotice(response.message || "If the account requires verification, an email will be sent.");
  } catch {
    showNotice("Unable to process the request. Please try again later.", "error");
  }
}));

$("#forgotForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    const response = await api("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify(formObject(form)),
    });
    form.reset();
    showNotice(response.message || "If an account exists for that email, a reset link will be sent.");
  } catch (error) {
    reportError(error, "Unable to process the request. Please try again later.");
  }
}));

let resetToken = null;

$("#resetForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  if (data.new_password !== data.confirm_password) {
    showNotice("The two passwords don't match.", "error");
    return;
  }
  try {
    const response = await api("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token: resetToken, new_password: data.new_password }),
    });
    resetToken = null;
    form.reset();
    showPanel("#authPanel");
    showNotice(response.message || "Password updated. You can now sign in.");
  } catch (error) {
    reportError(error, "This reset link is invalid or expired. Request a new one.");
  }
}));

async function handleLinkFragment() {
  const hash = window.location.hash;
  if (!hash) return;

  // Remove the token from the address bar and history before any request.
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
  const params = new URLSearchParams(hash.slice(1));

  const reset = params.get("reset");
  if (reset) {
    resetToken = reset;
    showPanel("#resetPanel");
    return;
  }

  if (!params.has("verify")) return;
  const token = params.get("verify");
  if (!token) {
    showVerificationPanel("This verification link could not be processed. You can request a new link below.");
    return;
  }

  showVerificationPanel("Verifying your email address...");
  try {
    await api("/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) });
    showPanel("#authPanel");
    showNotice("Email verified successfully. You can now sign in.");
  } catch {
    showVerificationPanel("This verification link is invalid or expired. You can request a new link below.");
    showNotice("Email verification could not be completed.", "error");
  }
}

// Customers and jobs

async function refreshCustomers() {
  customers = await api("/customers");
  $("#customerList").replaceChildren();
  const select = $("#jobCustomer");
  select.replaceChildren();
  if (!customers.length) addOption(select, "", "Create a customer first");
  for (const customer of customers) {
    const li = document.createElement("li");
    li.textContent = `${customer.name}${customer.email ? " · " + customer.email : ""}`;
    $("#customerList").append(li);
    addOption(select, customer.id, customer.name);
  }
}

// Jobs are labelled with their customer (re-audit U-N3): two customers can
// each have a "Water heater replacement" job, and "(#1)" vs "(#2)" did not
// say which was which.
function customerName(customerId) {
  const customer = customers.find((item) => item.id === customerId);
  return customer ? customer.name : "Unknown customer";
}

function jobLabel(job) {
  return `${job.title} — ${customerName(job.customer_id)}`;
}

async function refreshJobs() {
  jobs = await api("/jobs");
  for (const selector of ["#reportJob", "#taskJob"]) {
    const select = $(selector);
    const previous = select.value;
    select.replaceChildren();
    if (!jobs.length) addOption(select, "", "Create a job first");
    for (const job of jobs) addOption(select, job.id, jobLabel(job));
    if (jobs.some((job) => String(job.id) === previous)) select.value = previous;
  }
  $("#jobList").replaceChildren();
  for (const job of jobs) {
    const li = document.createElement("li");
    li.textContent = `${jobLabel(job)} · ${job.trade_type} · ${job.status}`;
    $("#jobList").append(li);
  }
}

async function refreshAll() {
  await refreshCustomers();
  await refreshJobs();
  await refreshReportHistory($("#reportJob").value);
  await refreshTasks($("#taskJob").value);
}

$("#customerForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  for (const key of Object.keys(data)) {
    if (typeof data[key] === "string" && !data[key].trim()) delete data[key];
  }
  try {
    await api("/customers", { method: "POST", body: JSON.stringify(data) });
    form.reset();
    await refreshCustomers();
    showNotice("Customer saved.");
  } catch (error) {
    reportError(error, "Unable to save customer.");
  }
}));

$("#jobForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  data.customer_id = Number(data.customer_id);
  for (const key of ["description", "notes"]) {
    if (!data[key]?.trim()) data[key] = null;
  }
  try {
    await api("/jobs", { method: "POST", body: JSON.stringify(data) });
    form.reset();
    await refreshJobs();
    await refreshReportHistory($("#reportJob").value);
    await refreshTasks($("#taskJob").value);
    showNotice("Job saved.");
  } catch (error) {
    reportError(error, "Unable to save job.");
  }
}));

// Reports

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function parseSections(content) {
  try {
    const data = JSON.parse(content);
    if (data && typeof data === "object" && !Array.isArray(data)) return data;
  } catch { /* legacy plain-text report */ }
  return { work_performed: String(content || "") };
}

function draftKey(reportId) {
  return `${DRAFT_PREFIX}${accountKey}:${reportId}`;
}

function readSectionFields() {
  const sections = {};
  for (const section of REPORT_SECTIONS) sections[section] = $(`#section_${section}`).value.trim();
  return sections;
}

function storeDraft() {
  if (!activeReport || activeReport.status !== "Draft") return;
  try {
    sessionStorage.setItem(draftKey(activeReport.id), JSON.stringify(readSectionFields()));
  } catch { /* storage unavailable */ }
}

function dropDraft(reportId) {
  try { sessionStorage.removeItem(draftKey(reportId)); } catch { /* ignore */ }
}

function showReport(report) {
  activeReport = report;
  const saved = parseSections(report.generated_content);
  let restored = null;
  if (report.status === "Draft") {
    try { restored = JSON.parse(sessionStorage.getItem(draftKey(report.id)) || "null"); } catch { restored = null; }
  }
  const values = restored || saved;
  const isDraft = report.status === "Draft";
  for (const section of REPORT_SECTIONS) {
    const field = $(`#section_${section}`);
    const value = typeof values[section] === "string" ? values[section] : "";
    field.value = PLACEHOLDERS.has(value) ? "" : value;
    field.readOnly = !isDraft;
    // "Leave blank to omit" is an instruction for drafts; a locked report
    // says plainly that the empty section is not on the PDF.
    if (field.dataset.draftPlaceholder === undefined) field.dataset.draftPlaceholder = field.placeholder;
    field.placeholder = isDraft ? field.dataset.draftPlaceholder : "Not included in the PDF.";
  }
  $("#reportNumber").textContent = `#${report.id}`;
  $("#reportStatus").textContent = report.status;
  $("#reportGuidance").textContent = isDraft
    ? "Review each section. Leave a section blank to leave it off the PDF."
    : "This report is approved and locked. Download the PDF to share it with your customer.";
  syncReportButtons();
  $("#reportArea").classList.remove("hidden");
  if (restored) showNotice("Restored your unsaved edits for this report. Save to keep them.");
}

function syncReportButtons() {
  const isDraft = Boolean(activeReport) && activeReport.status === "Draft";
  $("#saveReportButton").disabled = !isDraft;
  $("#approveReportButton").disabled = !isDraft;
  $("#pdfButton").disabled = !activeReport || activeReport.status !== "Approved";
}

for (const section of REPORT_SECTIONS) {
  $(`#section_${section}`).addEventListener("input", storeDraft);
}

async function refreshReportHistory(jobId) {
  const list = $("#reportHistory");
  list.replaceChildren();
  if (!jobId) return;
  const reports = await api(`/jobs/${encodeURIComponent(jobId)}/reports`);
  if (!reports.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No reports yet for this job.";
    list.append(li);
    return;
  }
  for (const report of reports) {
    const li = document.createElement("li");
    li.className = "record-row";
    const text = document.createElement("span");
    text.textContent = `Report #${report.id} · ${report.status} · ${formatDate(report.updated_at)}`;
    const actions = document.createElement("span");
    actions.className = "button-row";
    const open = document.createElement("button");
    open.type = "button";
    open.className = "secondary";
    open.textContent = report.status === "Draft" ? "Edit" : "View";
    open.setAttribute("aria-label", `${open.textContent} report #${report.id}`);
    open.addEventListener("click", () => showReport(report));
    actions.append(open);
    if (report.status === "Approved") {
      const download = document.createElement("button");
      download.type = "button";
      download.className = "secondary";
      download.textContent = "Download PDF";
      download.setAttribute("aria-label", `Download PDF for report #${report.id}`);
      download.addEventListener("click", () => downloadPdf(report.id));
      actions.append(download);
    }
    li.append(text, actions);
    list.append(li);
  }
}

$("#reportJob").addEventListener("change", async (event) => {
  $("#reportArea").classList.add("hidden");
  activeReport = null;
  try { await refreshReportHistory(event.currentTarget.value); }
  catch (error) { reportError(error, "Unable to load reports."); }
});

$("#reportForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  try {
    const report = await api(`/jobs/${encodeURIComponent(data.job_id)}/reports/draft`, {
      method: "POST",
      body: JSON.stringify({ notes: data.notes }),
    });
    form.elements.notes.value = "";
    showReport(report);
    await refreshReportHistory(data.job_id);
    showNotice("Draft created. Review every detail before approval.");
  } catch (error) {
    reportError(error, "Unable to create report draft.");
  }
}));

$("#saveReportButton").addEventListener("click", guarded(async () => {
  if (!activeReport) return;
  const reportId = activeReport.id;
  try {
    const report = await api(`/reports/${encodeURIComponent(reportId)}`, {
      method: "PATCH",
      body: JSON.stringify({ generated_content: JSON.stringify(readSectionFields()) }),
    });
    dropDraft(reportId);
    showReport(report);
    await refreshReportHistory(report.job_id);
    showNotice("Draft edits saved.");
  } catch (error) {
    reportError(error, "Unable to save edits.");
  }
}));

$("#approveReportButton").addEventListener("click", guarded(async () => {
  if (!activeReport) return;
  const reportId = activeReport.id;
  // Approval locks the report for good (re-audit U-N2), so confirm first.
  if (!window.confirm(`Approve report #${reportId}? Approved reports are locked and can't be edited.`)) return;
  try {
    // Save the current text first so what was reviewed is what gets approved.
    await api(`/reports/${encodeURIComponent(reportId)}`, {
      method: "PATCH",
      body: JSON.stringify({ generated_content: JSON.stringify(readSectionFields()) }),
    });
    const report = await api(`/reports/${encodeURIComponent(reportId)}/approve`, { method: "POST" });
    dropDraft(reportId);
    showReport(report);
    await refreshReportHistory(report.job_id);
    showNotice("Report approved. You can now download the PDF.");
  } catch (error) {
    reportError(error, "Unable to approve report.");
  }
}));

async function downloadPdf(reportId) {
  try {
    const response = await fetch(`/reports/${encodeURIComponent(reportId)}/pdf`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (response.status === 401) {
      endSession({ expired: true });
      return;
    }
    if (!response.ok) throw new Error("PDF download failed. Confirm the report is approved.");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `tradedesk-report-${reportId}.pdf`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    reportError(error, "PDF download failed.");
  }
}

$("#pdfButton").addEventListener("click", guarded(async () => {
  if (activeReport) await downloadPdf(activeReport.id);
}));

// Tasks

async function refreshTasks(jobId) {
  $("#taskList").replaceChildren();
  if (!jobId) return;
  const tasks = await api(`/jobs/${encodeURIComponent(jobId)}/tasks`);
  for (const task of tasks) {
    const li = document.createElement("li");
    li.textContent = `${task.title} · ${task.status}${task.due_at ? " · due " + formatDate(task.due_at) : ""}`;
    if (task.status !== "Completed") {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "secondary";
      button.textContent = "Mark complete";
      button.setAttribute("aria-label", `Mark "${task.title}" complete`);
      button.addEventListener("click", async () => {
        try {
          await api(`/tasks/${encodeURIComponent(task.id)}`, {
            method: "PATCH",
            body: JSON.stringify({ status: "Completed" }),
          });
          await refreshTasks(jobId);
          showNotice("Task marked complete.");
        } catch (error) {
          reportError(error, "Unable to update task.");
        }
      });
      li.append(document.createTextNode(" "), button);
    }
    $("#taskList").append(li);
  }
}

$("#taskForm").addEventListener("submit", guarded(async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formObject(form);
  const payload = { title: data.title.trim() };
  if (data.due_at) payload.due_at = new Date(data.due_at).toISOString();
  try {
    await api(`/jobs/${encodeURIComponent(data.job_id)}/tasks`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    form.elements.title.value = "";
    form.elements.due_at.value = "";
    await refreshTasks(data.job_id);
    showNotice("Follow-up task created.");
  } catch (error) {
    reportError(error, "Unable to create follow-up task.");
  }
}));

$("#taskJob").addEventListener("change", async (event) => {
  try { await refreshTasks(event.currentTarget.value); }
  catch (error) { reportError(error, "Unable to load tasks."); }
});

showPanel("#authPanel");
handleLinkFragment();
// Links opened in an already-open TradeDesk tab change only the fragment.
window.addEventListener("hashchange", handleLinkFragment);
