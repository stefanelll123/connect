import React, { useEffect, useState } from "react";
import Box from "@mui/material/Box";
import CircularProgress from "@mui/material/CircularProgress";
import Tooltip from "@mui/material/Tooltip";
import Typography from "@mui/material/Typography";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import ShieldIcon from "@mui/icons-material/Shield";
import { getTamperCheckStatus, type TamperCheckResult } from "../../api/audit";

const REFRESH_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export const TamperDetectionStatus: React.FC = () => {
  const [result, setResult] = useState<TamperCheckResult | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = () => {
    getTamperCheckStatus()
      .then(setResult)
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, REFRESH_INTERVAL_MS);
    return () => clearInterval(id);
  }, []);

  if (loading) return <CircularProgress size={16} />;
  if (!result) return null;

  if (result.tampered_count === 0) {
    return (
      <Tooltip title={`${result.events_checked} events checked — no tampering detected`}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, color: "success.main" }}>
          <ShieldIcon fontSize="small" />
          <Typography variant="body2">Hash chain OK</Typography>
        </Box>
      </Tooltip>
    );
  }

  // tampering detected — no auto-dismiss
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        gap: 0.5,
        color: "error.main",
        bgcolor: "error.light",
        px: 1.5,
        py: 0.5,
        borderRadius: 1,
      }}
    >
      <ErrorOutlineIcon fontSize="small" />
      <Typography variant="body2" fontWeight="medium">
        Hash chain broken at event {result.first_tampered_event_id}. Contact security team immediately.
      </Typography>
    </Box>
  );
};
