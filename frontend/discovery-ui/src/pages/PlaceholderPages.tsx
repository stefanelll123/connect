import React from "react";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import ConstructionIcon from "@mui/icons-material/Construction";

interface UnderConstructionProps {
  pageName: string;
}

const UnderConstruction: React.FC<UnderConstructionProps> = ({ pageName }) => (
  <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" minHeight="50vh" gap={2}>
    <ConstructionIcon sx={{ fontSize: 64, color: "text.secondary" }} />
    <Typography variant="h5" color="text.secondary">
      {pageName} — Coming Soon
    </Typography>
  </Box>
);

export const ChainPage: React.FC = () => <UnderConstruction pageName="Chain" />;
export const AuditPage: React.FC = () => <UnderConstruction pageName="Audit" />;
