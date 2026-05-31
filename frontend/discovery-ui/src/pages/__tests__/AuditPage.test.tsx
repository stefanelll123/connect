import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AuditPage } from "../AuditPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/audit", () => ({
  listAuditEvents: vi.fn(),
  getTamperCheckStatus: vi.fn(),
  exportAuditEventsJSONL: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

import {
  listAuditEvents,
  getTamperCheckStatus,
  exportAuditEventsJSONL,
} from "../../api/audit";

const mockList = vi.mocked(listAuditEvents);
const mockTamper = vi.mocked(getTamperCheckStatus);
const mockExport = vi.mocked(exportAuditEventsJSONL);

// ── Fixtures ──────────────────────────────────────────────────────────────────

const EVENTS = [
  {
    event_id: "a1",
    ts: "2024-03-01T12:00:00Z",
    action: "credential.issue",
    actor_id: "hash1234abcdef",
    actor_type: "user",
    target_type: "credential",
    target_id: "svc-123",
  },
  {
    event_id: "a2",
    ts: "2024-03-01T11:00:00Z",
    action: "auth.login",
    actor_id: "hash5678ghijkl",
    actor_type: "user",
    target_type: "sentinel",
    target_id: "user-456",
  },
];

const LIST_RESPONSE = { items: EVENTS, count: 2, next_cursor: undefined };
const LIST_RESPONSE_PAGINATED = {
  items: EVENTS,
  count: 100,
  next_cursor: "cursor-abc",
};

const TAMPER_OK = {
  events_checked: 500,
  tampered_count: 0,
  first_tampered_event_id: null,
};

const TAMPER_SOME_TAMPERED = {
  events_checked: 100,
  tampered_count: 5,
  first_tampered_event_id: "evt-broken-42",
};

function renderPage() {
  return render(
    <MemoryRouter>
      <AuditPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("AuditPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockList.mockResolvedValue(LIST_RESPONSE);
    mockTamper.mockResolvedValue(TAMPER_OK);
    mockExport.mockResolvedValue(undefined);
  });

  it("renders audit event rows with action chips", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("credential.issue")).toBeDefined());
    expect(screen.getByText("auth.login")).toBeDefined();
  });

  it("renders actor_id truncated to 8 chars", async () => {
    renderPage();
    await waitFor(() => screen.getByText("credential.issue"));
    expect(screen.getByText("hash1234")).toBeDefined();
    expect(screen.getByText("hash5678")).toBeDefined();
  });

  it("shows all events count header", async () => {
    renderPage();
    await waitFor(() => screen.getByText(/Showing 1/i));
    expect(screen.getByText(/of 2 events/i)).toBeDefined();
  });

  it("shows Load more button when next_cursor is present", async () => {
    mockList.mockResolvedValue(LIST_RESPONSE_PAGINATED);
    renderPage();
    await waitFor(() => screen.getByRole("button", { name: /load more/i }));
  });

  it("calls listAuditEvents with cursor on Load more click", async () => {
    mockList.mockResolvedValue(LIST_RESPONSE_PAGINATED);
    renderPage();
    const loadMoreBtn = await waitFor(() => screen.getByRole("button", { name: /load more/i }));
    // Clear mock call history so we only track the "load more" call
    mockList.mockClear();
    mockList.mockResolvedValue({ ...LIST_RESPONSE_PAGINATED, next_cursor: undefined });
    fireEvent.click(loadMoreBtn);
    await waitFor(() =>
      expect(mockList).toHaveBeenCalledWith(
        expect.objectContaining({ cursor: "cursor-abc" }),
      ),
    );
  });

  it("shows JSONL export progress and calls exportAuditEventsJSONL", async () => {
    mockExport.mockImplementation((_params, onProgress) => {
      onProgress(500);
      return Promise.resolve();
    });
    renderPage();
    await waitFor(() => screen.getByRole("button", { name: /export jsonl/i }));
    fireEvent.click(screen.getByRole("button", { name: /export jsonl/i }));
    await waitFor(() => expect(mockExport).toHaveBeenCalled());
  });

  it("shows tamper ok status with shield icon text", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Hash chain OK")).toBeDefined());
  });

  it("shows tamper error for some tampered events", async () => {
    mockTamper.mockResolvedValue(TAMPER_SOME_TAMPERED);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/broken at event evt-broken-42/i)).toBeDefined(),
    );
  });

  it("shows tamper error status with first_tampered_event_id — no auto-dismiss", async () => {
    mockTamper.mockResolvedValue(TAMPER_SOME_TAMPERED);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/broken at event evt-broken-42/i)).toBeDefined(),
    );
    // No close button — the error persists
    expect(screen.queryByRole("button", { name: /close/i })).toBeNull();
  });
});
