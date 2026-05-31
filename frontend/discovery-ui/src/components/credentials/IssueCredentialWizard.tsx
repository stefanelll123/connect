import React, { useState } from "react";
import Alert from "@mui/material/Alert";
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
import Step from "@mui/material/Step";
import StepLabel from "@mui/material/StepLabel";
import Stepper from "@mui/material/Stepper";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableRow from "@mui/material/TableRow";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import Chip from "@mui/material/Chip";
import { issueAccessGrant, issueSentinelIdentity, issueServiceBinding } from "../../api/credentials";

const STEPS = ["Select Consumer", "Select Producer", "Configure", "Confirm"];

const AVAILABLE_SCOPES = ["read", "write", "admin", "publish", "subscribe"];

interface Props {
  open: boolean;
  onClose: (issued: boolean) => void;
}

export const IssueCredentialWizard: React.FC<Props> = ({ open, onClose }) => {
  const [step, setStep] = useState(0);
  const [consumerSentinelId, setConsumerSentinelId] = useState("");
  const [producerServiceId, setProducerServiceId] = useState("");
  const [env, setEnv] = useState<"dev" | "test" | "prod">("dev");
  const [scopes, setScopes] = useState<string[]>([]);
  const [expiryDays, setExpiryDays] = useState(90);
  const [credentialType, setCredentialType] = useState<"identity" | "service_binding" | "access_grant">("access_grant");
  const [error, setError] = useState("");

  const handleNext = () => setStep((s) => s + 1);
  const handleBack = () => setStep((s) => s - 1);

  const handleSubmit = async () => {
    setError("");
    try {
      let res;
      if (credentialType === "identity") {
        res = await issueSentinelIdentity({ sentinel_id: consumerSentinelId });
      } else if (credentialType === "service_binding") {
        res = await issueServiceBinding({ sentinel_id: consumerSentinelId, service_id: producerServiceId });
      } else {
        res = await issueAccessGrant({
          consumer_sentinel_id: consumerSentinelId,
          producer_service_id: producerServiceId,
          env,
          scope: scopes,
          expires_in_days: expiryDays,
        });
      }
      onClose(true);
      console.info("Issued credential:", res.credential_id);
    } catch {
      setError("Failed to issue credential.");
    }
  };

  const toggleScope = (scope: string) =>
    setScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );

  const reset = () => {
    setStep(0);
    setConsumerSentinelId("");
    setProducerServiceId("");
    setEnv("dev");
    setScopes([]);
    setExpiryDays(90);
    setCredentialType("access_grant");
    setError("");
  };

  return (
    <Dialog open={open} onClose={() => { reset(); onClose(false); }} maxWidth="sm" fullWidth>
      <DialogTitle>Issue Credential</DialogTitle>
      <DialogContent>
        <Stepper activeStep={step} sx={{ mb: 3 }}>
          {STEPS.map((label) => (
            <Step key={label}><StepLabel>{label}</StepLabel></Step>
          ))}
        </Stepper>

        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

        {step === 0 && (
          <TextField
            label="Consumer Sentinel ID"
            value={consumerSentinelId}
            onChange={(e) => setConsumerSentinelId(e.target.value)}
            fullWidth
            required
            helperText="Enter the sentinel ID of the consumer"
          />
        )}

        {step === 1 && (
          <TextField
            label="Producer Service ID"
            value={producerServiceId}
            onChange={(e) => setProducerServiceId(e.target.value)}
            fullWidth
            required
            helperText="Enter the service ID of the producer"
          />
        )}

        {step === 2 && (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <Typography variant="body2" gutterBottom>Select Scopes:</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {AVAILABLE_SCOPES.map((scope) => (
                <Chip
                  key={scope}
                  label={scope}
                  clickable
                  color={scopes.includes(scope) ? "primary" : "default"}
                  onClick={() => toggleScope(scope)}
                />
              ))}
            </Box>
            <TextField
              label="Expiry Days"
              type="number"
              value={expiryDays}
              onChange={(e) => setExpiryDays(Math.min(365, Math.max(1, Number(e.target.value))))}
              inputProps={{ min: 1, max: 365 }}
            />
            <FormControl>
              <InputLabel>Credential Type</InputLabel>
              <Select
                value={credentialType}
                label="Credential Type"
                onChange={(e) => setCredentialType(e.target.value as typeof credentialType)}
              >
                <MenuItem value="access_grant">Access Grant</MenuItem>
                <MenuItem value="service_binding">Service Binding</MenuItem>
                <MenuItem value="identity">Identity</MenuItem>
              </Select>
            </FormControl>
            {credentialType === "access_grant" && (
              <FormControl>
                <InputLabel>Environment</InputLabel>
                <Select
                  value={env}
                  label="Environment"
                  onChange={(e) => setEnv(e.target.value as typeof env)}
                >
                  <MenuItem value="dev">dev</MenuItem>
                  <MenuItem value="test">test</MenuItem>
                  <MenuItem value="prod">prod</MenuItem>
                </Select>
              </FormControl>
            )}
          </Box>
        )}

        {step === 3 && (
          <Box>
            <Table size="small">
              <TableBody>
                <TableRow><TableCell>Consumer</TableCell><TableCell>{consumerSentinelId}</TableCell></TableRow>
                <TableRow><TableCell>Producer</TableCell><TableCell>{producerServiceId || "—"}</TableCell></TableRow>
                {credentialType === "access_grant" && <>
                  <TableRow><TableCell>Env</TableCell><TableCell>{env}</TableCell></TableRow>
                  <TableRow><TableCell>Scopes</TableCell><TableCell>{scopes.join(", ") || "—"}</TableCell></TableRow>
                  <TableRow><TableCell>Expiry</TableCell><TableCell>{expiryDays} days</TableCell></TableRow>
                </>}
                <TableRow><TableCell>Type</TableCell><TableCell>{credentialType}</TableCell></TableRow>
              </TableBody>
            </Table>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => { reset(); onClose(false); }}>Cancel</Button>
        {step > 0 && <Button onClick={handleBack}>Back</Button>}
        {step < STEPS.length - 1 && (
          <Button
            onClick={handleNext}
            variant="contained"
            disabled={
              (step === 0 && !consumerSentinelId) ||
              (step === 1 && !producerServiceId)
            }
          >
            Next
          </Button>
        )}
        {step === STEPS.length - 1 && (
          <Button onClick={handleSubmit} variant="contained" color="primary">
            Issue Credential
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};
