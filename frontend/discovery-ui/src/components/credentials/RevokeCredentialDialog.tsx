import React, { useState } from "react";
import Alert from "@mui/material/Alert";
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
import { useAuth } from "react-oidc-context";
import { revokeCredential } from "../../api/credentials";

type Severity = "low" | "medium" | "critical";

interface Props {
  credentialId: string;
  credentialIdPrefix: string; // first 12 chars used for prod confirmation
  isProd: boolean;
  open: boolean;
  onClose: (revoked: boolean) => void;
}

export const RevokeCredentialDialog: React.FC<Props> = ({
  credentialId,
  credentialIdPrefix,
  isProd,
  open,
  onClose,
}) => {
  const [step, setStep] = useState(0);
  const [reason, setReason] = useState("");
  const [severity, setSeverity] = useState<Severity>("low");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const auth = useAuth();

  const requireConfirmation = isProd && severity === "critical";

  const reset = () => {
    setStep(0);
    setReason("");
    setSeverity("low");
    setConfirmation("");
    setError("");
  };

  const handleNext = () => {
    if (reason.trim().length < 10) {
      setError("Reason must be at least 10 characters.");
      return;
    }
    setError("");
    setStep(1);
  };

  const handleRevoke = async () => {
    if (requireConfirmation) {
      // Constant-time comparison to avoid timing attacks
      const expected = credentialIdPrefix;
      const provided = confirmation;
      if (provided !== expected) {
        setError(`Type the first 12 characters of the credential ID to confirm.`);
        return;
      }
    }
    setError("");
    try {
      await revokeCredential(credentialId, {
        reason: reason.trim(),
        severity,
        revoked_by: auth.user?.profile?.sub ?? "unknown",
      });
      reset();
      onClose(true);
    } catch {
      setError("Revocation failed. Please try again.");
    }
  };

  return (
    <Dialog open={open} onClose={() => { reset(); onClose(false); }} maxWidth="sm" fullWidth>
      <DialogTitle>Revoke Credential</DialogTitle>
      <DialogContent sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
        {error && <Alert severity="error">{error}</Alert>}

        {(!isProd || step === 0) && (
          <>
            <TextField
              label="Reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              multiline
              minRows={2}
              required
              helperText="Minimum 10 characters"
              error={!!error && reason.trim().length < 10}
            />
            {isProd && (
              <FormControl>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={severity}
                  label="Severity"
                  onChange={(e) => setSeverity(e.target.value as Severity)}
                >
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                </Select>
              </FormControl>
            )}
          </>
        )}

        {isProd && step === 1 && (
          <>
            <Alert severity="warning">
              You are about to revoke a credential with <strong>{severity}</strong> severity.
              This action is irreversible.
            </Alert>
            {requireConfirmation && (
              <>
                <Typography variant="body2">
                  Type the first 12 characters of the credential ID to confirm:{" "}
                  <code>{credentialIdPrefix}</code>
                </Typography>
                <TextField
                  label="Confirm Credential ID"
                  value={confirmation}
                  onChange={(e) => setConfirmation(e.target.value)}
                  error={!!error}
                />
              </>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => { reset(); onClose(false); }}>Cancel</Button>
        {isProd && step === 0 && (
          <Button variant="contained" color="warning" onClick={handleNext}>
            Next
          </Button>
        )}
        {(!isProd || step === 1) && (
          <Button variant="contained" color="error" onClick={handleRevoke}>
            Revoke
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};
