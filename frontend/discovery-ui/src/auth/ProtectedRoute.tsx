import React, { useEffect } from "react";
import { Outlet } from "react-router-dom";
import { useAuth } from "react-oidc-context";
import CircularProgress from "@mui/material/CircularProgress";
import Box from "@mui/material/Box";
import { registerAuthHandlers } from "../api/client";

export const ProtectedRoute: React.FC = () => {
  const { isAuthenticated, isLoading, signinRedirect, signinSilent, user } = useAuth();

  useEffect(() => {
    registerAuthHandlers(
      () => user,
      () => signinSilent(),
      () => signinRedirect(),
    );
  }, [user, signinSilent, signinRedirect]);

  if (isLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!isAuthenticated) {
    signinRedirect();
    return null;
  }

  return <Outlet />;
};
