import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AuthContextProps } from "react-oidc-context";

// Helpers
type AuthState = Partial<Pick<AuthContextProps, "isAuthenticated" | "isLoading">> & {
  signinRedirect?: () => void;
};

const mockUseAuth = vi.fn<[], AuthState>();

vi.mock("react-oidc-context", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-oidc-context")>();
  return {
    ...actual,
    useAuth: () => mockUseAuth(),
    AuthProvider: ({ children }: { children: unknown }) => <>{children}</>,
  };
});

vi.mock("../../api/client", () => ({
  apiClient: { get: vi.fn(), post: vi.fn() },
  registerAuthHandlers: vi.fn(),
}));

// Import AFTER mocks are set up
import { ProtectedRoute } from "./ProtectedRoute";

function renderWithRouter(authState: AuthState) {
  mockUseAuth.mockReturnValue({
    isAuthenticated: false,
    isLoading: false,
    signinRedirect: vi.fn(),
    ...authState,
  });

  return render(
    <MemoryRouter initialEntries={["/protected"]}>
      <Routes>
        <Route element={<ProtectedRoute />}>
          <Route path="/protected" element={<div>Protected Content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("ProtectedRoute", () => {
  it("shows spinner while auth is loading", () => {
    renderWithRouter({ isLoading: true, isAuthenticated: false });
    // CircularProgress renders an svg role="progressbar"
    expect(document.querySelector('[role="progressbar"]')).not.toBeNull();
    expect(screen.queryByText("Protected Content")).toBeNull();
  });

  it("calls signinRedirect when not authenticated", () => {
    const signinRedirect = vi.fn();
    renderWithRouter({ isAuthenticated: false, isLoading: false, signinRedirect });
    expect(signinRedirect).toHaveBeenCalledOnce();
    expect(screen.queryByText("Protected Content")).toBeNull();
  });

  it("renders Outlet (protected content) when authenticated", () => {
    renderWithRouter({ isAuthenticated: true, isLoading: false });
    expect(screen.getByText("Protected Content")).toBeDefined();
  });

  it("does not call signinRedirect when already authenticated", () => {
    const signinRedirect = vi.fn();
    renderWithRouter({ isAuthenticated: true, isLoading: false, signinRedirect });
    expect(signinRedirect).not.toHaveBeenCalled();
  });

  it("does not call signinRedirect while still loading", () => {
    const signinRedirect = vi.fn();
    renderWithRouter({ isLoading: true, isAuthenticated: false, signinRedirect });
    expect(signinRedirect).not.toHaveBeenCalled();
  });

  it("renders nothing (null) while redirecting an unauthenticated user", () => {
    const signinRedirect = vi.fn();
    const { container } = renderWithRouter({
      isAuthenticated: false,
      isLoading: false,
      signinRedirect,
    });
    // After signinRedirect, ProtectedRoute returns null → no protected content rendered
    expect(container.querySelector(".MuiBox-root")).toBeNull();
    expect(screen.queryByText("Protected Content")).toBeNull();
  });

  it("re-renders spinner when auth transitions to loading", () => {
    mockUseAuth.mockReturnValueOnce({ isLoading: true, isAuthenticated: false });
    const { rerender } = render(
      <MemoryRouter initialEntries={["/protected"]}>
        <Routes>
          <Route element={<ProtectedRoute />}>
            <Route path="/protected" element={<div>Protected Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
    expect(document.querySelector('[role="progressbar"]')).not.toBeNull();

    mockUseAuth.mockReturnValueOnce({ isLoading: false, isAuthenticated: true });
    rerender(
      <MemoryRouter initialEntries={["/protected"]}>
        <Routes>
          <Route element={<ProtectedRoute />}>
            <Route path="/protected" element={<div>Protected Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText("Protected Content")).toBeDefined();
  });
});
