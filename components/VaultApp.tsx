// ============================================================
// VaultApp — Unified Client Orchestrator
// Enforces strict security boundaries in order:
//   1. Cloud Auth (single-admin allowlist) — when Supabase configured
//   2. Mandatory MFA (TOTP aal2)           — when Supabase configured
//   3. First-time Local -> Cloud Migration — safe, backup-verified
//   4. Master Password Vault Unlock        — ALWAYS required locally
//   5. Client Hub Deep-Link Item Display   — ONLY after unlock
// ============================================================

'use client';

import { useEffect, useState, useCallback } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import {
  hasVault,
  loadBlob,
  persistBlob,
  exportVault,
  triggerDownload,
  createRecoverySnapshot,
} from '@/lib/vaultService';
import { fetchCloudVault, pushCloudVault } from '@/lib/cloudSync';
import { isValidVaultItemId } from '@/lib/urlSafety';
import { getBlobRevision } from '@/lib/crypto';
import type { AuthSessionState, EncryptedVaultBlob } from '@/lib/types';

import LoadingScreen from '@/components/ui/LoadingScreen';
import CloudSignInPage from '@/components/auth/CloudSignInPage';
import MfaGatePage from '@/components/auth/MfaGatePage';
import SetupPage from '@/components/auth/SetupPage';
import UnlockPage from '@/components/auth/UnlockPage';
import VaultLayout from '@/components/vault/VaultLayout';
import { ShieldAlert, Download, CloudUpload, LogOut } from 'lucide-react';

interface Props {
  initialItemId?: string | null;
}

export default function VaultApp({ initialItemId = null }: Props) {
  const {
    isUnlocked,
    isFirstRun,
    setFirstRun,
    setSyncMode,
    setPendingDeepLinkItemId,
    lock,
  } = useVaultStore();

  const [session, setSession] = useState<AuthSessionState | null>(null);
  const [vaultExists, setVaultExists] = useState(false);
  const [remoteBlob, setRemoteBlob] = useState<EncryptedVaultBlob | null>(null);
  const [needsCloudMigration, setNeedsCloudMigration] = useState(false);
  const [backupExported, setBackupExported] = useState(false);
  const [migrating, setMigrating] = useState(false);
  const [migrationError, setMigrationError] = useState('');
  const [initializingVault, setInitializingVault] = useState(true);

  const safeDeepLinkId = isValidVaultItemId(initialItemId) ? initialItemId : null;

  useEffect(() => {
    if (safeDeepLinkId) {
      setPendingDeepLinkItemId(safeDeepLinkId);
    }
  }, [safeDeepLinkId, setPendingDeepLinkItemId]);

  const loadVaultAvailability = useCallback(
    async (authState: AuthSessionState) => {
      setInitializingVault(true);
      setNeedsCloudMigration(false);
      setRemoteBlob(null);

      if (authState.mode === 'local') {
        setSyncMode('local');
        const exists = hasVault();
        setVaultExists(exists);
        setFirstRun(!exists);
        setInitializingVault(false);
        return;
      }

      if (authState.step !== 'authenticated') {
        setSyncMode('cloud');
        setInitializingVault(false);
        return;
      }

      setSyncMode('cloud');
      try {
        const cloud = await fetchCloudVault();
        const local = loadBlob();

        if (cloud.exists && cloud.blob) {
          // Cache remote encrypted blob locally if local is missing or older
          if (!local || getBlobRevision(cloud.blob) >= getBlobRevision(local)) {
            persistBlob(cloud.blob, { force: true });
          }
          setRemoteBlob(cloud.blob);
          setVaultExists(true);
          setFirstRun(false);
        } else if (local) {
          // First-time safe migration: local vault exists, cloud is empty!
          setNeedsCloudMigration(true);
          setVaultExists(true);
          setFirstRun(false);
        } else {
          setVaultExists(false);
          setFirstRun(true);
        }
      } catch {
        // Offline fallback: allow unlocking local encrypted vault if available
        const localExists = hasVault();
        setVaultExists(localExists);
        setFirstRun(!localExists);
      } finally {
        setInitializingVault(false);
      }
    },
    [setFirstRun, setSyncMode]
  );

  const refreshSession = useCallback(async () => {
    try {
      const res = await fetch('/api/auth/session', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (res.status === 403) {
        const forbidden: AuthSessionState = {
          mode: 'cloud',
          step: 'forbidden',
          userEmail: null,
          userId: null,
          aal: null,
          hasTotpFactor: false,
        };
        setSession(forbidden);
        setInitializingVault(false);
        return;
      }
      const data = (await res.json()) as AuthSessionState;
      setSession(data);
      await loadVaultAvailability(data);
    } catch {
      // Fallback to local-only mode if session endpoint cannot be reached in dev
      const fallback: AuthSessionState = {
        mode: 'local',
        step: 'local_only',
        userEmail: null,
        userId: null,
        aal: null,
        hasTotpFactor: false,
      };
      setSession(fallback);
      await loadVaultAvailability(fallback);
    }
  }, [loadVaultAvailability]);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const handleSignOut = async () => {
    lock();
    try {
      await fetch('/api/auth/signout', {
        method: 'POST',
        credentials: 'same-origin',
      });
    } finally {
      await refreshSession();
    }
  };

  const handleExportBeforeMigration = () => {
    const json = exportVault();
    if (!json) return;
    triggerDownload(
      json,
      `nmark-pre-cloud-migration-backup-${new Date().toISOString().split('T')[0]}.json`
    );
    setBackupExported(true);
  };

  const handleMigrateLocalToCloud = async () => {
    setMigrationError('');
    const local = loadBlob();
    if (!local) {
      setMigrationError('Local encrypted vault not found.');
      return;
    }

    if (local.version !== 2) {
      // Unlock locally first so v1 safely migrates to v2 with AAD before cloud upload
      setNeedsCloudMigration(false);
      return;
    }

    setMigrating(true);
    try {
      createRecoverySnapshot('cloud_migration', local);
      await pushCloudVault(local, 0);
      setRemoteBlob(local);
      setNeedsCloudMigration(false);
    } catch (err: unknown) {
      setMigrationError(
        err instanceof Error ? err.message : 'Failed to migrate encrypted vault to cloud.'
      );
    } finally {
      setMigrating(false);
    }
  };

  if (!session || initializingVault) {
    return <LoadingScreen />;
  }

  // Gate 1: Non-allowlisted user rejected server-side
  if (session.step === 'forbidden') {
    return (
      <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
        <div className="max-w-sm w-full bg-vault-surface border border-red-700/60 rounded-2xl p-6 text-center space-y-4">
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
          <h1 className="text-lg font-bold text-vault-soft">Access Restricted</h1>
          <p className="text-xs text-vault-muted leading-relaxed">
            This NMark Pass Vault instance is restricted to a single authorized
            administrator.
          </p>
          <button
            type="button"
            onClick={handleSignOut}
            className="w-full py-2.5 rounded-xl bg-vault-elevated hover:bg-vault-border text-vault-soft text-sm font-medium"
          >
            Return to Sign In
          </button>
        </div>
      </div>
    );
  }

  // Gate 2: Cloud Sign-In (single-admin allowlist)
  if (session.mode === 'cloud' && session.step === 'sign_in') {
    return (
      <CloudSignInPage
        deepLinkItemId={safeDeepLinkId}
        onSignedIn={(nextSession) => {
          setSession(nextSession);
          void loadVaultAvailability(nextSession);
        }}
      />
    );
  }

  // Gate 3: Mandatory TOTP MFA (aal2)
  if (
    session.mode === 'cloud' &&
    (session.step === 'mfa_enroll' || session.step === 'mfa_challenge')
  ) {
    return (
      <MfaGatePage
        mode={session.step === 'mfa_enroll' ? 'enroll' : 'challenge'}
        userEmail={session.userEmail}
        onVerified={() => void refreshSession()}
        onSignOut={handleSignOut}
      />
    );
  }

  // Gate 4: Safe First-Time Migration from localStorage -> Cloud
  if (session.mode === 'cloud' && needsCloudMigration && !isUnlocked) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
        <div className="max-w-md w-full bg-vault-surface border border-vault-border rounded-2xl p-6 space-y-5 shadow-2xl">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-vault-elevated border border-vault-accent/40 flex items-center justify-center">
              <CloudUpload className="w-6 h-6 text-vault-accent" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-vault-soft">
                Migrate Local Vault to Cloud
              </h1>
              <p className="text-xs text-vault-muted">
                Your cloud vault is empty, and an encrypted local vault was detected.
              </p>
            </div>
          </div>

          <p className="text-xs text-vault-muted leading-relaxed">
            Only your <strong className="text-vault-soft">already-encrypted ciphertext</strong>{' '}
            will be uploaded. Before migrating, export a verified offline backup copy so
            local data can never be lost.
          </p>

          <button
            type="button"
            onClick={handleExportBeforeMigration}
            className="w-full flex items-center justify-center gap-2 bg-vault-elevated hover:bg-vault-border border border-vault-border text-vault-soft text-sm font-medium py-2.5 rounded-xl transition-colors"
          >
            <Download className="w-4 h-4 text-vault-accent" />
            {backupExported
              ? '1. Offline Encrypted Backup Exported ✓'
              : '1. Export Encrypted Local Backup (Required)'}
          </button>

          {migrationError && (
            <div className="bg-red-950/60 border border-red-700/70 text-red-200 text-xs rounded-xl px-3.5 py-2.5">
              {migrationError}
            </div>
          )}

          <button
            type="button"
            disabled={!backupExported || migrating}
            onClick={handleMigrateLocalToCloud}
            className="w-full bg-vault-accent hover:bg-vault-accent-hover disabled:bg-vault-elevated disabled:text-vault-muted text-vault-bg text-sm font-semibold py-2.5 rounded-xl transition-colors"
          >
            {migrating ? 'Uploading Encrypted Blob...' : '2. Upload Encrypted Vault to Cloud'}
          </button>

          <button
            type="button"
            onClick={() => setNeedsCloudMigration(false)}
            className="w-full text-xs text-vault-muted hover:text-vault-soft py-1"
          >
            Skip for now &amp; unlock locally
          </button>

          <button
            type="button"
            onClick={handleSignOut}
            className="w-full flex items-center justify-center gap-1.5 text-xs text-vault-muted hover:text-vault-soft"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out
          </button>
        </div>
      </div>
    );
  }

  // Gate 5: Vault Unlocked View
  if (isUnlocked) {
    return (
      <VaultLayout
        userEmail={session.userEmail}
        onSignOut={session.mode === 'cloud' ? handleSignOut : undefined}
      />
    );
  }

  // Gate 6: First-Run Vault Creation / Backup Restore
  if (isFirstRun || !vaultExists) {
    return (
      <SetupPage
        cloudEnabled={session.mode === 'cloud'}
        onSignOut={session.mode === 'cloud' ? handleSignOut : undefined}
        onComplete={() => {
          setVaultExists(true);
          setFirstRun(false);
        }}
      />
    );
  }

  // Gate 7: Master Password Vault Unlock (always separate from account session)
  return (
    <UnlockPage
      cloudEnabled={session.mode === 'cloud'}
      userEmail={session.userEmail}
      remoteBlob={remoteBlob}
      deepLinkItemId={safeDeepLinkId}
      onSignOut={session.mode === 'cloud' ? handleSignOut : undefined}
    />
  );
}
