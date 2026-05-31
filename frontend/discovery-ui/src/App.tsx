import React from "react";
import { createBrowserRouter, RouterProvider, Navigate } from "react-router-dom";
import { AuthProvider } from "react-oidc-context";
import { ThemeProvider, CssBaseline } from "@mui/material";
import { theme } from "./theme/theme";
import { oidcConfig } from "./auth/oidcConfig";
import { ProtectedRoute } from "./auth/ProtectedRoute";
import { AuthCallbackPage } from "./pages/AuthCallbackPage";
import { AppShell } from "./components/AppShell";
import { AppsPage } from "./pages/AppsPage";
import { ServicesPage } from "./pages/ServicesPage";
import { SentinelsPage } from "./pages/SentinelsPage";
import { CredentialsPage } from "./pages/CredentialsPage";
import { RevocationsPage } from "./pages/RevocationsPage";
import { ChainPage } from "./pages/ChainPage";
import { AuditPage } from "./pages/AuditPage";

const ProtectedLayout: React.FC = () => (
  <AppShell>
    <ProtectedRoute />
  </AppShell>
);

const router = createBrowserRouter([
  { path: "/", element: <Navigate to="/services" replace /> },
  { path: "/auth/callback", element: <AuthCallbackPage /> },
  {
    element: <ProtectedLayout />,
    children: [
      { path: "/apps", element: <AppsPage /> },
      { path: "/services", element: <ServicesPage /> },
      { path: "/sentinels", element: <SentinelsPage /> },
      { path: "/credentials", element: <CredentialsPage /> },
      { path: "/revocations", element: <RevocationsPage /> },
      { path: "/chain", element: <ChainPage /> },
      { path: "/audit", element: <AuditPage /> },
    ],
  },
]);

const App: React.FC = () => (
  <AuthProvider {...oidcConfig}>
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <RouterProvider router={router} />
    </ThemeProvider>
  </AuthProvider>
);

export default App;
