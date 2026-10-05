import type { ReactNode } from "react";
import "./styles.css";

export const metadata = {
  title: "AegisAI // Security Command Center",
  description: "AI-assisted SOC, SIEM and cyber threat intelligence platform",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
