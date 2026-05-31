import React, { useState } from "react";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
import Paper from "@mui/material/Paper";
import Snackbar from "@mui/material/Snackbar";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Typography from "@mui/material/Typography";
import CheckIcon from "@mui/icons-material/Check";
import CloseIcon from "@mui/icons-material/Close";
import {
  listPendingEnrollments,
  approveEnrollment,
  cancelEnrollment,
  type EnrollmentToken,
} from "../../api/sentinels";
import { useQuery } from "../hooks/useQuery";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export const ApprovalList: React.FC = () => {
  const { data, isLoading: loading, refetch } = useQuery(["pending-enrollments"], listPendingEnrollments);
  const enrollments: EnrollmentToken[] = data ?? [];
  const [confirmAction, setConfirmAction] = useState<{
    enrollment: EnrollmentToken;
    action: "approve" | "cancel";
  } | null>(null);
  const [snack, setSnack] = useState("");
  const [actionError, setActionError] = useState("");

  const handleConfirm = async () => {
    if (!confirmAction) return;
    setActionError("");
    try {
      if (confirmAction.action === "approve") {
        await approveEnrollment(confirmAction.enrollment.token_id);
        setSnack("Enrollment approved.");
      } else {
        await cancelEnrollment(confirmAction.enrollment.token_id);
        setSnack("Enrollment cancelled.");
      }
      setConfirmAction(null);
      refetch();
    } catch {
      setActionError("Action failed. Please try again.");
    }
  };

  return (
    <>
      <Typography variant="subtitle1" gutterBottom>
        Pending Enrollments
      </Typography>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Requested By</TableCell>
              <TableCell>Service</TableCell>
              <TableCell>Env</TableCell>
              <TableCell>Role</TableCell>
              <TableCell>Expires</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {loading && (
              <TableRow>
                <TableCell colSpan={7} align="center">Loading…</TableCell>
              </TableRow>
            )}
            {!loading && enrollments.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} align="center">No pending enrollments.</TableCell>
              </TableRow>
            )}
            {enrollments.map((enr) => (
              <TableRow key={enr.token_id} hover>
                <TableCell><code>{enr.token_id.slice(0, 8)}</code></TableCell>
                <TableCell>{enr.created_by}</TableCell>
                <TableCell>{enr.service_id}</TableCell>
                <TableCell>{enr.env}</TableCell>
                <TableCell>{enr.role}</TableCell>
                <TableCell>{formatDate(enr.expires_at)}</TableCell>
                <TableCell align="right">
                  <Button
                    size="small"
                    color="success"
                    startIcon={<CheckIcon />}
                    onClick={() => setConfirmAction({ enrollment: enr, action: "approve" })}
                  >
                    Approve
                  </Button>
                  <Button
                    size="small"
                    color="error"
                    startIcon={<CloseIcon />}
                    sx={{ ml: 1 }}
                    onClick={() => setConfirmAction({ enrollment: enr, action: "cancel" })}
                  >
                    Cancel
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog
        open={!!confirmAction}
        onClose={() => { setConfirmAction(null); setActionError(""); }}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>
          {confirmAction?.action === "approve" ? "Approve Enrollment?" : "Cancel Enrollment?"}
        </DialogTitle>
        <DialogContent>
          {actionError && <Alert severity="error" sx={{ mb: 1 }}>{actionError}</Alert>}
          <Typography variant="body2">
            {confirmAction?.action === "approve"
              ? "This will allow the sentinel to join the network."
              : "This will cancel this enrollment request."}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setConfirmAction(null); setActionError(""); }}>Cancel</Button>
          <Button
            variant="contained"
            color={confirmAction?.action === "approve" ? "success" : "error"}
            onClick={handleConfirm}
          >
            Confirm
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={!!snack}
        autoHideDuration={4000}
        onClose={() => setSnack("")}
        message={snack}
      />
    </>
  );
};
