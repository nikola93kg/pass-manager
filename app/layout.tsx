import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import { headers } from 'next/headers';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'NMark Pass Vault',
  description: 'Private zero-knowledge encrypted password vault',
  robots: {
    index: false,
    follow: false,
    nocache: true,
    googleBot: {
      index: false,
      follow: false,
    },
  },
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Reading headers() opts layout into dynamic rendering so Next.js attaches
  // the per-request CSP nonce generated in middleware.ts to framework scripts.
  await headers();

  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.className} bg-vault-bg text-vault-soft min-h-screen antialiased selection:bg-vault-accent/30 selection:text-vault-soft`}
      >
        {children}
      </body>
    </html>
  );
}
