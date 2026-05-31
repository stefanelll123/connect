import React, { useCallback, useEffect, useState } from "react";
import Box from "@mui/material/Box";
import Card from "@mui/material/Card";
import CardContent from "@mui/material/CardContent";
import Chip from "@mui/material/Chip";
import CircularProgress from "@mui/material/CircularProgress";
import Grid from "@mui/material/Grid";
import Typography from "@mui/material/Typography";
import { ChainEventsTable } from "../components/chain/ChainEventsTable";
import { getChainStatus, type ChainStatus } from "../api/chain";
const REFRESH_INTERVAL_MS = 30_000;

const RpcStatusChip: React.FC<{ available: boolean }> = ({ available }) => {
  const color = available ? "success" : "error";
  return <Chip label={available ? "ONLINE" : "OFFLINE"} size="small" color={color} />;
};

export const ChainPage: React.FC = () => {
  const [status, setStatus] = useState<ChainStatus | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(() => {
    getChainStatus()
      .then((s) => setStatus(s))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, REFRESH_INTERVAL_MS);
    return () => clearInterval(id);
  }, [fetchData]);

  if (loading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", mt: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Chain Dashboard
      </Typography>

      {status && (
        <Grid container spacing={2} sx={{ mb: 3 }}>
          {/* Network Info */}
          <Grid item xs={12} md={6}>
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                  Network Info
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">Network</Typography>
                    <Typography variant="body2">{status.network}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">Chain ID</Typography>
                    <Typography variant="body2">{status.chain_id}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <Typography variant="body2" color="text.secondary">RPC Status</Typography>
                    <RpcStatusChip available={status.is_available} />
                  </Box>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">Blockchain Integration</Typography>
                    <Typography variant="body2">{status.blockchain_integration_enabled ? "Enabled" : "Disabled"}</Typography>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Sync Status */}
          <Grid item xs={12} md={6}>
            <Card variant="outlined">
              <CardContent>
                <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                  Sync Status
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                    <Typography variant="body2" color="text.secondary">Last Indexed Block</Typography>
                    <Typography variant="body2">{status.indexer_last_block.toLocaleString()}</Typography>
                  </Box>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <Typography variant="body2" color="text.secondary">Policy Cache</Typography>
                    <Chip
                      label={status.policy_cache.is_stale ? "STALE" : "FRESH"}
                      size="small"
                      color={status.policy_cache.is_stale ? "warning" : "success"}
                    />
                  </Box>
                  {status.policy_cache.cache_age_seconds !== null && (
                    <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                      <Typography variant="body2" color="text.secondary">Cache Age</Typography>
                      <Typography variant="body2">{Math.round(status.policy_cache.cache_age_seconds)}s</Typography>
                    </Box>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      <Typography variant="h6" gutterBottom>
        Recent Events
      </Typography>
      <ChainEventsTable />
    </Box>
  );
};
