import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "light",
    primary: { main: "#1565C0" },
    secondary: { main: "#0288D1" },
    error: { main: "#C62828" },
  },
  typography: {
    fontFamily: "Inter, Roboto, sans-serif",
  },
  components: {
    MuiTableCell: {
      styleOverrides: {
        head: { fontWeight: 600 },
      },
    },
  },
});

// Status chip color mapping
export const STATUS_COLORS = {
  active: "success",
  degraded: "warning",
  offline: "error",
  pending: "default",
  expired: "default",
  revoked: "error",
} as const;
