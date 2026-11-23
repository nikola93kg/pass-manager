// ============================================================
// VaultApp — Unified Client Orchestrator
// Enforces strict FAIL-CLOSED security boundaries in order:
//   0. Session Fetch — NEVER fails open to local_only on errors
//   1. Cloud Auth (single-admin allowlist) — when Supabase configured
//   2. Mandatory MFA (TOTP aal2)           — when Supabase configured
//   3. Safe Local/Cloud Reconciliation     — NEVER overwrites unsynced local edits
//   4. First-time Local -> Cloud Migration — backup-verified
//   5. Master Password Vault Unlock        — ALWAYS required locally
//   6. Client Hub Deep-Link Item Display   — ONLY after unlock
// ============================================================

'use client';

import { useEffect, useState, useCallback } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import {
  hasVault,
  loadBlob,
  loadSyncMetadata,
  persistBlob,
  markCloudSynced,
  exportVault,
  triggerDownload,
  createRecoverySnapshot,
} from '@/lib/vaultService';
import { reconcileLocalAndCloudBlobs } from '@/lib/syncReconcile';
import { fetchCloudVault, pushCloudVault, CloudAuthError } from '@/lib/cloudSync';
import { isValidVaultItemId } from '@/lib/urlSafety';
import type { AuthSessionState, EncryptedVaultBlob, VaultConflict } from '@/lib/types';

import LoadingScreen from '@/components/ui/LoadingScreen';
import CloudSignInPage from '@/components/auth/CloudSignInPage';
import MfaGatePage from '@/components/auth/MfaGatePage';
import SetupPage from '@/components/auth/SetupPage';
import UnlockPage from '@/components/auth/UnlockPage';
import VaultLayout from '@/components/vault/VaultLayout';
import { ShieldAlert, Download, CloudUpload, LogOut, RefreshCw } from 'lucide-react';

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
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [vaultExists, setVaultExists] = useState(false);
  const [remoteBlob, setRemoteBlob] = useState<EncryptedVaultBlob | null>(null);
  const [preUnlockConflict, setPreUnlockConflict] = useState<VaultConflict | null>(null);
  const [cloudOfflineWarning, setCloudOfflineWarning] = useState<string | null>(null);
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
    async (authState: AuthSessionState, onAuthExpired?: () => void) => {
      setInitializingVault(true);
      setNeedsCloudMigration(false);
      setRemoteBlob(null);
      setPreUnlockConflict(null);
      setCloudOfflineWarning(null);

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
        const syncMeta = loadSyncMetadata();

        const reconciled = await reconcileLocalAndCloudBlobs({
          localBlob: local,
          cloudBlob: cloud.exists ? cloud.blob : null,
          syncMeta,
        });

        switch (reconciled.action) {
          case 'first_run':
            setVaultExists(false);
            setFirstRun(true);
            break;

          case 'needs_cloud_migration':
            setNeedsCloudMigration(true);
            setVaultExists(true);
            setFirstRun(false);
            break;

          case 'use_cloud':
            persistBlob(reconciled.cloudBlob, { force: true });
            await markCloudSynced(reconciled.cloudBlob);
            setRemoteBlob(reconciled.cloudBlob);
            setVaultExists(true);
            setFirstRun(false);
            break;

          case 'in_sync':
            await markCloudSynced(reconciled.blob);
            setRemoteBlob(reconciled.blob);
            setVaultExists(true);
            setFirstRun(false);
            break;

          case 'fast_forward_cloud':
            // Preserve previous local encrypted blob as a safety snapshot before fast-forwarding
            if (local) {
              createRecoverySnapshot('manual', local);
            }
            persistBlob(reconciled.cloudBlob, { force: true });
            await markCloudSynced(reconciled.cloudBlob);
            setRemoteBlob(reconciled.cloudBlob);
            setVaultExists(true);
            setFirstRun(false);
            break;

          case 'conflict':
            // NEVER overwrite localStorage! Unlock local vault and open ConflictModal.
            setPreUnlockConflict(reconciled.conflict);
            setRemoteBlob(null);
            setVaultExists(true);
            setFirstRun(false);
            break;
        }
      } catch (err: unknown) {
        if (err instanceof CloudAuthError) {
          // Session or MFA expired: fail closed and re-check auth gate
          onAuthExpired?.();
          return;
        }
        // Already authenticated + MFA-verified, but cloud sync endpoint is transiently unreachable:
        // allow unlocking existing local encrypted cache without overwriting it.
        const localExists = hasVault();
        setVaultExists(localExists);
        setFirstRun(!localExists);
        setCloudOfflineWarning(
          localExists
            ? 'Cloud sync is temporarily unreachable. Unlocking your cached local encrypted vault; changes will stay local until sync resumes.'
            : 'Cloud sync is temporarily unreachable and no local encrypted vault cache was found.'
        );
      } finally {
        setInitializingVault(false);
      }
    },
    [setFirstRun, setSyncMode]
  );

  const refreshSession = useCallback(async () => {
    setSessionError(null);
    setInitializingVault(true);

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

      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        setSession(null);
        setSessionError(
          typeof errBody.error === 'string' && errBody.error.length > 0
            ? errBody.error
            : `Authentication service returned HTTP ${res.status}.`
        );
        setInitializingVault(false);
        return;
      }

      const data = (await res.json()) as Partial<AuthSessionState>;
      if (
        (data.mode !== 'cloud' && data.mode !== 'local') ||
        typeof data.step !== 'string'
      ) {
        setSession(null);
        setSessionError('Received an invalid authentication response from the server.');
        setInitializingVault(false);
        return;
      }

      const validSession = data as AuthSessionState;
      setSession(validSession);
      await loadVaultAvailability(validSession, () => {
        void refreshSession();
      });
    } catch {
      // FAIL CLOSED: Never fall back to local-only mode when /api/auth/session fails.
      // Explicit local-only mode is entered ONLY when the server returns 200 { mode: 'local', step: 'local_only' }.
      setSession(null);
      setSessionError(
        'Unable to verify authentication status with the server. Check your connection and retry.'
      );
      setInitializingVault(false);
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
      await markCloudSynced(local);
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

  // Gate 0: Fail-closed authentication error screen (NEVER falls open to local mode)
  if (sessionError) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-vault-bg p-4">
        <div
          role="alert"
          className="max-w-sm w-full bg-vault-surface border border-red-700/60 rounded-2xl p-6 text-center space-y-4 shadow-2xl"
        >
          <ShieldAlert className="w-10 h-10 text-red-400 mx-auto" />
          <h1 className="text-lg font-bold text-vault-soft">
            Authentication Check Failed
          </h1>
          <p className="text-xs text-vault-muted leading-relaxed">{sessionError}</p>
          <p className="text-[11px] text-vault-muted/80 leading-relaxed">
            For security, NMark Pass Vault fails closed and will not bypass authentication
            or MFA when session verification is unavailable.
          </p>
          <button
            type="button"
            onClick={() => void refreshSession()}
            className="w-full inline-flex items-center justify-center gap-2 py-2.5 rounded-xl bg-vault-accent hover:bg-vault-accent-hover text-vault-bg text-sm font-semibold transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Retry Authentication Check
          </button>
        </div>
      </div>
    );
  }

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
          void loadVaultAvailability(nextSession, () => {
            void refreshSession();
          });
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
      pendingConflict={preUnlockConflict}
      cloudOfflineWarning={cloudOfflineWarning}
      deepLinkItemId={safeDeepLinkId}
      onSignOut={session.mode === 'cloud' ? handleSignOut : undefined}
    />
  );
}
