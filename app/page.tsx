// ============================================================
// ROOT PAGE — client-side router for vault states
// ============================================================

'use client';

import { useEffect, useState } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import { hasVault } from '@/lib/vaultService';
import SetupPage from '@/components/auth/SetupPage';
import UnlockPage from '@/components/auth/UnlockPage';
import VaultLayout from '@/components/vault/VaultLayout';
import LoadingScreen from '@/components/ui/LoadingScreen';

export default function Home() {
  const { isUnlocked, isFirstRun, setFirstRun } = useVaultStore();
  const [mounted, setMounted] = useState(false);
  const [vaultExists, setVaultExists] = useState(false);

  useEffect(() => {
    const exists = hasVault();
    setVaultExists(exists);
    setFirstRun(!exists);
    setMounted(true);
  }, [setFirstRun]);

  if (!mounted) return <LoadingScreen />;
  if (isUnlocked) return <VaultLayout />;
  if (isFirstRun || !vaultExists) {
    return (
      <SetupPage
        onComplete={() => {
          setVaultExists(true);
          setFirstRun(false);
        }}
      />
    );
  }
  return <UnlockPage />;
}
