import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ServicesPage } from "../ServicesPage";

// ── Module mocks ──────────────────────────────────────────────────────────────

vi.mock("../../api/services", () => ({
  listServices: vi.fn(),
  createService: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

import { listServices, createService } from "../../api/services";

const mockListServices = vi.mocked(listServices);
const mockCreateService = vi.mocked(createService);

// ── Fixtures ──────────────────────────────────────────────────────────────────

const SERVICES = [
  {
    id: "svc-uuid-001",
    app_id: "alpha-app",
    service_id: "alpha-api",
    env: "prod" as const,
    display_name: "Alpha API",
    owner_did: "did:web:owner.example.com",
    is_active: true,
    description: "Alpha service",
    created_at: null,
    updated_at: null,
    status: "active" as const,
  },
  {
    id: "svc-uuid-002",
    app_id: "beta-app",
    service_id: "beta-svc",
    env: "dev" as const,
    display_name: "Beta SVC",
    owner_did: "did:web:beta.example.com",
    is_active: true,
    description: null,
    created_at: null,
    updated_at: null,
    status: "degraded" as const,
  },
];

function makeResponse(items = SERVICES) {
  return { items, total_count: items.length, next_cursor: null };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <ServicesPage />
    </MemoryRouter>,
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("ServicesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListServices.mockResolvedValue(makeResponse());
    mockCreateService.mockResolvedValue(SERVICES[0]);
  });

  it("renders service rows after data loads", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("alpha-api")).toBeDefined());
    expect(screen.getByText("beta-svc")).toBeDefined();
  });

  it("shows 'No services found' when list is empty", async () => {
    mockListServices.mockResolvedValue(makeResponse([]));
    renderPage();
    await waitFor(() => expect(screen.getByText("No services found.")).toBeDefined());
  });

  it("filters results by search input", async () => {
    renderPage();
    await waitFor(() => screen.getByText("alpha-api"));
    const input = screen.getByPlaceholderText(/search/i);
    fireEvent.change(input, { target: { value: "beta" } });
    expect(screen.queryByText("alpha-api")).toBeNull();
    expect(screen.getByText("beta-svc")).toBeDefined();
  });

  it("opens create modal when Add Service button is clicked", async () => {
    renderPage();
    await waitFor(() => screen.getByText("alpha-api"));
    fireEvent.click(screen.getByText(/new service/i));
    expect(screen.getByRole("dialog")).toBeDefined();
  });

  it("validates service_id against [a-z0-9-]+ regex", async () => {
    renderPage();
    await waitFor(() => screen.getByText("alpha-api"));
    fireEvent.click(screen.getByText(/new service/i));
    const idInput = screen.getByLabelText(/service id/i);
    fireEvent.change(idInput, { target: { value: "Invalid_ID" } });
    await waitFor(() =>
      expect(screen.getByText(/lowercase alphanumeric/i)).toBeDefined(),
    );
  });

  it("calls createService on valid form submission", async () => {
    renderPage();
    await waitFor(() => screen.getByText("alpha-api"));
    fireEvent.click(screen.getByText(/new service/i));

    fireEvent.change(screen.getByLabelText(/service id/i), {
      target: { value: "new-svc" },
    });
    fireEvent.change(screen.getByLabelText(/owner did/i), {
      target: { value: "did:web:new.example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));

    await waitFor(() => expect(mockCreateService).toHaveBeenCalledOnce());
  });

  it("renders StatusChip for each status value", async () => {
    renderPage();
    await waitFor(() => screen.getByText("Active"));
    expect(screen.getByText("Degraded")).toBeDefined();
  });

  it("pagination controls are rendered", async () => {
    renderPage();
    await waitFor(() => screen.getByText("alpha-api"));
    // MUI TablePagination renders displayed rows count (1–2 of 2)
    const pagination = document.querySelector(".MuiTablePagination-displayedRows");
    expect(pagination).not.toBeNull();
  });
});
