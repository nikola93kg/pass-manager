// ============================================================
// LoadingScreen — NMark Pass Vault
// ============================================================

import { ShieldCheck } from 'lucide-react';

interface Props {
  label?: string;
}

export default function LoadingScreen({ label = 'Initializing encrypted vault...' }: Props) {
  return (
    <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
      <div className="flex flex-col items-center gap-4">
        <div className="relative">
          <div className="w-14 h-14 rounded-2xl bg-vault-surface border border-vault-border flex items-center justify-center shadow-lg shadow-vault-accent/10">
            <ShieldCheck className="w-7 h-7 text-vault-accent" />
          </div>
          <div className="absolute -inset-1 rounded-2xl border-2 border-vault-accent/40 border-t-vault-accent animate-spin" />
        </div>
        <p className="text-vault-muted text-sm font-medium">{label}</p>
      </div>
    </div>
  );
}
