import React from "react";
import Chip from "@mui/material/Chip";
import { STATUS_COLORS } from "../../theme/theme";

interface StatusChipProps {
  status: string;
}

export const StatusChip: React.FC<StatusChipProps> = ({ status }) => {
  const color =
    (STATUS_COLORS as Record<string, string>)[status] ?? "default";

  return (
    <Chip
      label={status.charAt(0).toUpperCase() + status.slice(1)}
      color={color as "success" | "warning" | "error" | "default"}
      size="small"
      sx={
        color === "success"
          ? {
              "@keyframes pulse": {
                "0%": { opacity: 1 },
                "50%": { opacity: 0.7 },
                "100%": { opacity: 1 },
              },
              animation: "pulse 2s infinite",
            }
          : undefined
      }
    />
  );
};
