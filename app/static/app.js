/* Small frontend controller.
   The bearer token is kept in memory rather than localStorage. Refreshing the
   page logs the user out; this is a deliberate safer default for this demo.
   Production authentication should use a reviewed secure session design. */
"use strict";

let accessToken = null;
let customers = [];
let jobs = [];
let activeReportId = null;
const $ = (selector) => document.querySelector(selector);

function showNotice(message, kind = "success") {
  const notice = $("#notice");
  notice.textContent = message; // textContent prevents HTML injection from API data.
  notice.className = `notice ${kind}`;
}

function formObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(path, { ...options, headers });
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    // Show server validation messages without dumping raw response or stack traces.
    const detail = data && typeof data.detail === "string" ? data.detail : "Request failed. Please check your input.";
    throw new Error(detail);
  }
  return data;
}

function setAuthenticated(value) {
  $("#authPanel").classList.toggle("hidden", value);
  $("#appPanel").classList.toggle("hidden", !value);
  $("#logoutButton").classList.toggle("hidden", !value);
}

function addOption(select, value, label) {
  const option = document.createElement("option");
  option.value = String(value);
  option.textContent = label; // Never use untrusted API values as HTML.
  select.append(option);
}

async function refreshCustomers() {
  customers = await api("/customers");
  $("#customerList").replaceChildren();
  $("#jobCustomer").replaceChildren();
  if (!customers.length) addOption($("#jobCustomer"), "", "Create a customer first");
  for (const customer of customers) {
    const li = document.createElement("li");
    li.textContent = `${customer.name}${customer.email ? " · " + customer.email : ""}`;
    $("#customerList").append(li);
    addOption($("#jobCustomer"), customer.id, customer.name);
  }
}

async function refreshJobs() {
  jobs = await api("/jobs");
  for (const selector of ["#reportJob", "#taskJob"]) {
    const select = $(selector);
    select.replaceChildren();
    if (!jobs.length) addOption(select, "", "Create a job first");
    for (const job of jobs) addOption(select, job.id, `${job.title} (#${job.id})`);
  }
  $("#jobList").replaceChildren();
  for (const job of jobs) {
    const li = document.createElement("li");
    li.textContent = `${job.title} · ${job.trade_type} · ${job.status}`;
    $("#jobList").append(li);
  }
}

async function refreshTasks(jobId) {
  if (!jobId) return;
  const tasks = await api(`/jobs/${encodeURIComponent(jobId)}/tasks`);
  $("#taskList").replaceChildren();
  for (const task of tasks) {
    const li = document.createElement("li");
    li.textContent = `${task.title} · ${task.status}${task.due_at ? " · due " + task.due_at : ""}`;
    if (task.status !== "Completed") {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "secondary";
      button.textContent = "Mark complete";
      button.addEventListener("click", async () => {
        try {
          await api(`/tasks/${encodeURIComponent(task.id)}`, {
            method: "PATCH", body: JSON.stringify({ status: "Completed" })
          });
          await refreshTasks(jobId);
          showNotice("Task marked complete.");
        } catch (error) { showNotice(error.message, "error"); }
      });
      li.append(document.createTextNode(" "), button);
    }
    $("#taskList").append(li);
  }
}

async function refreshAll() {
  await refreshCustomers();
  await refreshJobs();
}

$("#authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitter = event.submitter;
  const mode = submitter?.dataset.mode || "login";
  try {
    const data = await api(`/auth/${mode === "register" ? "register" : "login"}`, {
      method: "POST", body: JSON.stringify(formObject(event.currentTarget))
    });
    accessToken = data.access_token;
    setAuthenticated(true);
    await refreshAll();
    showNotice(mode === "register" ? "Account created and signed in." : "Signed in.");
  } catch (error) { showNotice(error.message, "error"); }
});

$("#logoutButton").addEventListener("click", () => {
  accessToken = null;
  customers = [];
  jobs = [];
  activeReportId = null;
  $("#reportArea").classList.add("hidden");
  setAuthenticated(false);
  showNotice("Signed out.");
});

$("#customerForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  // Keep a reference to the form before any asynchronous operations.
  const form = event.currentTarget;

  console.log("[Customer] Submit started");

  const data = formObject(form);

  // Remove empty optional fields.
  for (const key of Object.keys(data)) {
    if (typeof data[key] === "string" && !data[key].trim()) {
      delete data[key];
    }
  }

  try {
    // Save the customer through the API.
    const customer = await api("/customers", {
      method: "POST",
      body: JSON.stringify(data),
    });

    console.log("[Customer] API success:", customer);

    // Reset the form only after the API confirms success.
    form.reset();
    console.log("[Customer] Form reset successful");

    // Refresh the customer list.
    await refreshCustomers();
    console.log("[Customer] Customer list refreshed");

    showNotice("Customer saved.");
  } catch (error) {
    console.error("[Customer] Operation failed:", error);

    // Keep the form data if saving or refreshing fails.
    showNotice(error.message || "Unable to save customer.", "error");
  }
});

$("#jobForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  // Save the form reference before asynchronous operations.
  const form = event.currentTarget;

  console.log("[Job] Submit started");

  const data = formObject(form);

  // Convert customer ID to a number.
  data.customer_id = Number(data.customer_id);

  // Convert empty optional fields to null.
  for (const key of ["description", "notes"]) {
    if (!data[key]?.trim()) {
      data[key] = null;
    }
  }

  try {
    console.log("[Job] Sending request:", data);

    const job = await api("/jobs", {
      method: "POST",
      body: JSON.stringify(data),
    });

    console.log("[Job] API success:", job);

    // Reset only after the API confirms success.
    form.reset();
    console.log("[Job] Form reset successful");

    // Refresh the jobs list.
    await refreshJobs();
    console.log("[Job] Jobs list refreshed");

    showNotice("Job saved.");
  } catch (error) {
    console.error("[Job] Operation failed:", error);
    showNotice(error.message || "Unable to save job.", "error");
  }
});

$("#reportForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  // Save the form reference before asynchronous operations.
  const form = event.currentTarget;

  console.log("[Report] Submit started");

  const data = formObject(form);
  const jobId = data.job_id;

  try {
    console.log("[Report] Creating draft for job:", jobId);

    const report = await api(
      `/jobs/${encodeURIComponent(jobId)}/reports/draft`,
      {
        method: "POST",
        body: JSON.stringify({
          notes: data.notes,
        }),
      }
    );
    // Update the active report.
    activeReportId = report.id;

    $("#reportContent").value = report.generated_content;
    $("#reportStatus").textContent = report.status;

    // Display the report area.
    $("#reportArea").classList.remove("hidden");

    // Enable review and save actions.
    $("#approveReportButton").disabled = false;
    $("#saveReportButton").disabled = false;

    // Keep PDF export disabled until approval.
    $("#pdfButton").disabled = true;

    // Reset the report form after successful draft creation.
    form.reset();
    console.log("[Report] Form reset successful");

    showNotice("Draft created. Review every detail before approval.");
  } catch (error) {
    console.error("[Report] Operation failed:", error);
    showNotice(error.message || "Unable to create report draft.", "error");
  }
});

$("#saveReportButton").addEventListener("click", async () => {
  if (!activeReportId) return;
  try {
    const report = await api(`/reports/${encodeURIComponent(activeReportId)}`, {
      method: "PATCH", body: JSON.stringify({ generated_content: $("#reportContent").value })
    });
    $("#reportStatus").textContent = report.status;
    showNotice("Draft edits saved.");
  } catch (error) { showNotice(error.message, "error"); }
});

$("#approveReportButton").addEventListener("click", async () => {
  if (!activeReportId) return;
  try {
    const report = await api(`/reports/${encodeURIComponent(activeReportId)}/approve`, { method: "POST" });
    $("#reportStatus").textContent = report.status;
    $("#approveReportButton").disabled = true;
    $("#saveReportButton").disabled = true;
    $("#pdfButton").disabled = false;
    showNotice("Report approved. You can now download the PDF.");
  } catch (error) { showNotice(error.message, "error"); }
});

$("#pdfButton").addEventListener("click", async () => {
  if (!activeReportId) return;
  try {
    const response = await fetch(`/reports/${encodeURIComponent(activeReportId)}/pdf`, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error("PDF download failed. Confirm the report is approved.");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `tradedesk-report-${activeReportId}.pdf`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) { showNotice(error.message, "error"); }
});

$("#taskForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  // Save the form reference before asynchronous operations.
  const form = event.currentTarget;

  console.log("[Task] Submit started");

  const data = formObject(form);
  const jobId = data.job_id;

  // Build the task payload.
  const payload = {
    title: data.title.trim(),
  };

  // Convert the due date to ISO format when provided.
  if (data.due_at) {
    payload.due_at = new Date(data.due_at).toISOString();
  }

  try {
    console.log("[Task] Sending request:", payload);

    const task = await api(
      `/jobs/${encodeURIComponent(jobId)}/tasks`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );

    console.log("[Task] API success:", task);

    // Reset the form after successful creation.
    form.reset();
    console.log("[Task] Form reset successful");

    // Refresh tasks for the selected job.
    await refreshTasks(jobId);
    console.log("[Task] Tasks list refreshed");

    showNotice("Follow-up task created.");
  } catch (error) {
    console.error("[Task] Operation failed:", error);
    showNotice(error.message || "Unable to create follow-up task.", "error");
  }
});

$("#taskJob").addEventListener("change", async (event) => {
  try { await refreshTasks(event.currentTarget.value); }
  catch (error) { showNotice(error.message, "error"); }
});

setAuthenticated(false);
