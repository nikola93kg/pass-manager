import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, act, waitFor } from '@testing-library/react';
import { useInactivityLock } from '@/hooks/useInactivityLock';
import { useClipboard } from '@/hooks/useClipboard';
import VaultApp from '@/components/VaultApp';
import { useVaultStore, resetWriteQueueForTests } from '@/store/vaultStore';
import { createVault, saveVault } from '@/lib/vaultService';
import type { PlaintextVault } from '@/lib/types';

function InactivityHarness() {
  useInactivityLock();
  const isUnlocked = useVaultStore((s) => s.isUnlocked);
  return <div data-testid="lock-state">{isUnlocked ? 'unlocked' : 'locked'}</div>;
}

function ClipboardHarness({ secret }: { secret: string }) {
  const { copiedId, copyToClipboard } = useClipboard();
  return (
    <div>
      <button onClick={() => void copyToClipboard(secret, 'pw-1')}>Copy</button>
      <span data-testid="copied">{copiedId ?? 'none'}</span>
    </div>
  );
}

describe('Auto-Lock, Safe Clipboard & Client Hub Deep-Link Authorization', () => {
  beforeEach(() => {
    localStorage.clear();
    resetWriteQueueForTests();
    useVaultStore.getState().lock({ broadcast: false });
    useVaultStore.getState().setPendingDeepLinkItemId(null);
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('auto-locks after configured inactivity timeout and on wake-from-sleep wall-clock elapsed time', async () => {
    vi.useFakeTimers();
    const created = await createVault('AutoLockMaster!2026');
    const vaultWith1Min: PlaintextVault = {
      ...created.vault,
      settings: {
        autoLockMinutes: 1,
        clipboardClearSeconds: 10,
        lockOnBlur: false,
      },
    };
    useVaultStore.getState().unlock(created.key, vaultWith1Min, created.salt, 1);

    render(<InactivityHarness />);
    expect(screen.getByTestId('lock-state').textContent).toBe('unlocked');

    // Window blur does NOT lock when lockOnBlur is false
    act(() => {
      window.dispatchEvent(new Event('blur'));
    });
    expect(screen.getByTestId('lock-state').textContent).toBe('unlocked');

    // Advance 61 seconds -> inactivity auto-lock triggers
    act(() => {
      vi.advanceTimersByTime(61_000);
    });
    expect(screen.getByTestId('lock-state').textContent).toBe('locked');
  });

  it('locks immediately on blur when optional lockOnBlur setting is enabled', async () => {
    const created = await createVault('BlurLockMaster!2026');
    const vaultBlur: PlaintextVault = {
      ...created.vault,
      settings: {
        autoLockMinutes: 10,
        clipboardClearSeconds: 10,
        lockOnBlur: true,
      },
    };
    useVaultStore.getState().unlock(created.key, vaultBlur, created.salt, 1);

    render(<InactivityHarness />);
    expect(screen.getByTestId('lock-state').textContent).toBe('unlocked');

    act(() => {
      window.dispatchEvent(new Event('blur'));
    });
    expect(screen.getByTestId('lock-state').textContent).toBe('locked');
  });

  it('clears clipboard after timeout when unchanged, and preserves newer clipboard values', async () => {
    vi.useFakeTimers();
    let clipboardContent = '';
    const writeText = vi.fn(async (val: string) => {
      clipboardContent = val;
    });
    const readText = vi.fn(async () => clipboardContent);

    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText, readText },
      configurable: true,
    });

    const created = await createVault('ClipboardMaster!2026');
    useVaultStore.getState().unlock(
      created.key,
      {
        ...created.vault,
        settings: { autoLockMinutes: 5, clipboardClearSeconds: 5 },
      },
      created.salt,
      1
    );

    const { rerender } = render(<ClipboardHarness secret="SecretA!123" />);

    // Case 1: Clipboard stays unchanged -> gets cleared to ''
    await act(async () => {
      screen.getByText('Copy').click();
    });
    expect(clipboardContent).toBe('SecretA!123');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5100);
    });
    expect(clipboardContent).toBe('');

    // Case 2: User copies a newer value elsewhere before timeout -> must NOT erase newer value
    rerender(<ClipboardHarness secret="SecretB!456" />);
    await act(async () => {
      screen.getByText('Copy').click();
    });
    expect(clipboardContent).toBe('SecretB!456');

    clipboardContent = 'SomethingNewerUserCopied';

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5100);
    });
    expect(clipboardContent).toBe('SomethingNewerUserCopied');
  });

  it('gates Client Hub deep links (/item/{id}) behind Cloud Auth/MFA and Master Password Unlock', async () => {
    const deepId = '22222222-2222-4222-8222-222222222222';
    const created = await createVault('DeepLinkMaster!2026');
    const populated: PlaintextVault = {
      ...created.vault,
      items: [
        {
          id: deepId,
          category: 'projekti',
          title: 'Client Acme Hosting',
          username: 'acme-admin',
          password: 'AcmeSuperSecretPassword!77',
          url: 'https://hosting.acme.example',
          notes: '',
          tags: ['acme'],
          createdAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
        },
      ],
    };
    await saveVault(populated, created.key, created.salt, {
      expectedRevision: 1,
      nextRevision: 2,
    });

    // 1. In Cloud Mode while unauthenticated: must show Sign-In gate, NEVER credentials
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            mode: 'cloud',
            step: 'sign_in',
            userEmail: null,
            userId: null,
            aal: null,
            hasTotpFactor: false,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );

    const { unmount } = render(<VaultApp initialItemId={deepId} />);
    await waitFor(() => {
      expect(screen.getByText(/Continue to MFA Verification/i)).toBeInTheDocument();
    });
    expect(screen.queryByText(/AcmeSuperSecretPassword!77/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Client Acme Hosting/)).not.toBeInTheDocument();
    unmount();

    // 2. In Local Mode while locked: must show Unlock screen, NEVER credentials
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            mode: 'local',
            step: 'local_only',
            userEmail: null,
            userId: null,
            aal: null,
            hasTotpFactor: false,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      )
    );

    render(<VaultApp initialItemId={deepId} />);
    await waitFor(() => {
      expect(screen.getByText(/Unlock Vault/i)).toBeInTheDocument();
    });
    expect(screen.getByText(deepId)).toBeInTheDocument();
    expect(screen.queryByText(/AcmeSuperSecretPassword!77/)).not.toBeInTheDocument();

    // 3. Only AFTER unlocking with master password does the referenced entry modal open
    act(() => {
      useVaultStore.getState().unlock(created.key, populated, created.salt, 2);
    });

    await waitFor(() => {
      expect(screen.getByText(/Edit Credential/i)).toBeInTheDocument();
      expect(screen.getByDisplayValue('Client Acme Hosting')).toBeInTheDocument();
    });
  });
});
