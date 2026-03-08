import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono, Manrope } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/providers";
import { DemoProtection } from "@/components/demo-protection";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

const manrope = Manrope({
  subsets: ["latin"],
  variable: "--font-sans",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

export const metadata: Metadata = {
  title: "AgentGate Dashboard",
  description: "Intelligent agent gateway management platform",
  icons: {
    icon: "/favicon.ico",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body className={`${inter.variable} ${manrope.variable} ${jetbrainsMono.variable} antialiased${process.env.NEXT_PUBLIC_DEMO_MODE === "true" ? " demo-protected" : ""}`}>
        {process.env.NEXT_PUBLIC_DEMO_MODE === "true" && <DemoProtection />}
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
