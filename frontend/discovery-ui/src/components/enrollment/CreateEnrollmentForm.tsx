import React, { useState } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import MenuItem from "@mui/material/MenuItem";
import Select from "@mui/material/Select";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import Alert from "@mui/material/Alert";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import IconButton from "@mui/material/IconButton";
import Tooltip from "@mui/material/Tooltip";
import { createEnrollment, EnrollmentToken } from "../../api/sentinels";

interface Props {
  open: boolean;
  onClose: () => void;
}

export const CreateEnrollmentForm: React.FC<Props> = ({ open, onClose }) => {
  const [serviceId, setServiceId] = useState("");
  const [env, setEnv] = useState<"prod" | "test" | "dev">("dev");
  const [role, setRole] = useState<"producer" | "consumer">("consumer");
  const [expiryMinutes, setExpiryMinutes] = useState(60);
  const [result, setResult] = useState<EnrollmentToken | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const handleCreate = async () => {
    setError("");
    try {
      const res = await createEnrollment({ service_id: serviceId, env, role, expires_in_seconds: expiryMinutes * 60 });
      setResult(res);
    } catch (e) {
      setError("Failed to create enrollment token.");
    }
  };

  const handleCopy = async () => {
    if (result?.token) {
      await navigator.clipboard.writeText(result.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDone = () => {
    setResult(null);
    setServiceId("");
    setError("");
    onClose();
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Create Enrollment Token</DialogTitle>
      <DialogContent>
        {!result ? (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="Service ID"
              value={serviceId}
              onChange={(e) => setServiceId(e.target.value)}
              required
              inputProps={{ pattern: "[a-z0-9-]+", maxLength: 64 }}
              helperText="Lowercase alphanumeric and hyphens only"
            />
            <FormControl>
              <InputLabel>Environment</InputLabel>
              <Select value={env} label="Environment" onChange={(e) => setEnv(e.target.value as typeof env)}>
                <MenuItem value="dev">dev</MenuItem>
                <MenuItem value="test">test</MenuItem>
                <MenuItem value="prod">prod</MenuItem>
              </Select>
            </FormControl>
            <FormControl>
              <InputLabel>Role</InputLabel>
              <Select value={role} label="Role" onChange={(e) => setRole(e.target.value as typeof role)}>
                <MenuItem value="consumer">consumer</MenuItem>
                <MenuItem value="producer">producer</MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Expiry (minutes)"
              type="number"
              value={expiryMinutes}
              onChange={(e) => setExpiryMinutes(Math.min(60, Math.max(1, Number(e.target.value))))}
              inputProps={{ min: 1, max: 60 }}
              helperText="1–60 minutes"
            />
          </Box>
        ) : (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <Alert severity="warning">
              This token is displayed <strong>only once</strong> and cannot be retrieved again.
              Transmit it via a secure channel only.
            </Alert>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <TextField
                label="Enrollment Token"
                value={result.token}
                fullWidth
                InputProps={{ readOnly: true, sx: { fontFamily: "monospace" } }}
              />
              <Tooltip title={copied ? "Copied!" : "Copy token"}>
                <IconButton onClick={handleCopy} aria-label="Copy token">
                  <ContentCopyIcon />
                </IconButton>
              </Tooltip>
            </Box>
            <Typography variant="body2" color="text.secondary">
              Expires: {new Date(result.expires_at).toLocaleString()}
            </Typography>
            {result.status === "pending" && (
              <Alert severity="info">This enrollment requires admin approval before it can be used.</Alert>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        {!result ? (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button onClick={handleCreate} variant="contained" disabled={!serviceId}>
              Create Token
            </Button>
          </>
        ) : (
          <Button onClick={handleDone} variant="contained">
            Done
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};
