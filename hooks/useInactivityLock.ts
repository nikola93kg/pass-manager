// ============================================================
// INACTIVITY TIMER, WAKE-FROM-SLEEP LOCK & MULTI-TAB SYNC
// - Wall-clock elapsed-time checks protect against OS sleep /
//   mobile tab suspension where setTimeout pauses.
// - Throttled activity tracking avoids timer churn on mousemove.
// - Optional immediate lock on tab hidden / window blur.
// - Listens for cross-tab lock broadcasts and external localStorage
//   modifications to prevent silent multi-tab overwrites.
// ============================================================

'use client';

import { useEffect, useRef, useCallback } from 'react';
import { useVaultStore } from '@/store/vaultStore';
import { loadBlob, VAULT_STORAGE_KEY } from '@/lib/vaultService';
import { getBlobRevision } from '@/lib/crypto';
import { subscribeTabSync } from '@/lib/tabSync';

const DEFAULT_LOCK_MS = 5 * 60 * 1000; // 5 minutes
const ACTIVITY_THROTTLE_MS = 1000;
const HEARTBEAT_MS = 5000;

export function useInactivityLock() {
  const { isUnlocked, lock, vault, revision, reportExternalConflict } = useVaultStore();
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const heartbeatRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastActivityRef = useRef<number>(Date.now());
  const lastThrottleRef = useRef<number>(0);

  const autoLockMs =
    vault?.settings?.autoLockMinutes != null
      ? vault.settings.autoLockMinutes * 60 * 1000
      : DEFAULT_LOCK_MS;

  const lockOnBlur = vault?.settings?.lockOnBlur ?? false;

  const clearTimers = useCallback(() => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    if (heartbeatRef.current !== null) {
      clearInterval(heartbeatRef.current);
      heartbeatRef.current = null;
    }
  }, []);

  const checkExpiredAndLock = useCallback(() => {
    if (!useVaultStore.getState().isUnlocked) return false;
    const elapsed = Date.now() - lastActivityRef.current;
    if (elapsed >= autoLockMs) {
      clearTimers();
      lock();
      return true;
    }
    return false;
  }, [autoLockMs, clearTimers, lock]);

  const scheduleTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    if (!isUnlocked) return;
    const remaining = Math.max(0, autoLockMs - (Date.now() - lastActivityRef.current));
    timerRef.current = setTimeout(() => {
      checkExpiredAndLock();
    }, remaining);
  }, [isUnlocked, autoLockMs, checkExpiredAndLock]);

  const recordActivity = useCallback(() => {
    const now = Date.now();
    if (now - lastThrottleRef.current < ACTIVITY_THROTTLE_MS) {
      return;
    }
    lastThrottleRef.current = now;
    lastActivityRef.current = now;
    scheduleTimer();
  }, [scheduleTimer]);

  useEffect(() => {
    if (!isUnlocked) {
      clearTimers();
      return;
    }

    lastActivityRef.current = Date.now();
    lastThrottleRef.current = 0;

    const ACTIVITY_EVENTS = [
      'mousemove',
      'mousedown',
      'keydown',
      'touchstart',
      'scroll',
      'click',
    ] as const;

    ACTIVITY_EVENTS.forEach((event) => {
      window.addEventListener(event, recordActivity, { passive: true });
    });

    const handleVisibilityChange = () => {
      if (document.hidden) {
        if (lockOnBlur) {
          clearTimers();
          lock();
        }
      } else {
        // Returning from background or OS sleep: check wall-clock elapsed time immediately
        if (!checkExpiredAndLock()) {
          scheduleTimer();
        }
      }
    };

    const handleBlur = () => {
      if (lockOnBlur) {
        clearTimers();
        lock();
      }
    };

    const handleFocus = () => {
      if (!checkExpiredAndLock()) {
        scheduleTimer();
      }
    };

    const handleBeforeUnload = () => {
      clearTimers();
      lock({ broadcast: false });
    };

    // Multi-tab localStorage write detection
    const handleStorage = (e: StorageEvent) => {
      if (e.key !== VAULT_STORAGE_KEY) return;
      const latest = loadBlob();
      if (!latest) return;
      const storedRev = getBlobRevision(latest);
      const currentRev = useVaultStore.getState().revision;
      if (storedRev > currentRev) {
        reportExternalConflict({
          source: 'tab',
          localRevision: currentRev,
          remoteRevision: storedRev,
          remoteBlob: latest,
          detectedAt: new Date().toISOString(),
        });
      }
    };

    // BroadcastChannel cross-tab sync
    const unsubscribeTab = subscribeTabSync((msg) => {
      if (msg.type === 'LOCK_VAULT') {
        clearTimers();
        lock({ broadcast: false });
      } else if (msg.type === 'VAULT_REVISION_UPDATED') {
        const currentRev = useVaultStore.getState().revision;
        if (msg.revision > currentRev) {
          const latest = loadBlob();
          if (latest) {
            reportExternalConflict({
              source: 'tab',
              localRevision: currentRev,
              remoteRevision: msg.revision,
              remoteBlob: latest,
              detectedAt: new Date().toISOString(),
            });
          }
        }
      }
    });

    document.addEventListener('visibilitychange', handleVisibilityChange);
    window.addEventListener('blur', handleBlur);
    window.addEventListener('focus', handleFocus);
    window.addEventListener('beforeunload', handleBeforeUnload);
    window.addEventListener('storage', handleStorage);

    // Heartbeat protects against timer drift/throttling
    heartbeatRef.current = setInterval(() => {
      checkExpiredAndLock();
    }, HEARTBEAT_MS);

    scheduleTimer();

    return () => {
      clearTimers();
      unsubscribeTab();
      ACTIVITY_EVENTS.forEach((event) => {
        window.removeEventListener(event, recordActivity);
      });
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.removeEventListener('blur', handleBlur);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('beforeunload', handleBeforeUnload);
      window.removeEventListener('storage', handleStorage);
    };
  }, [
    isUnlocked,
    lock,
    lockOnBlur,
    revision,
    recordActivity,
    scheduleTimer,
    checkExpiredAndLock,
    clearTimers,
    reportExternalConflict,
  ]);
}
