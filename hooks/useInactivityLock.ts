// ============================================================
// INACTIVITY TIMER + AUTO-LOCK
// Locks vault after configurable inactivity period.
// Also locks on: tab hidden, window blur, page unload.
// ============================================================

'use client';

import { useEffect, useRef, useCallback } from 'react';
import { useVaultStore } from '@/store/vaultStore';

const DEFAULT_LOCK_MS = 5 * 60 * 1000; // 5 minutes

export function useInactivityLock() {
  const { isUnlocked, lock, vault } = useVaultStore();
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const autoLockMs =
    vault?.settings?.autoLockMinutes != null
      ? vault.settings.autoLockMinutes * 60 * 1000
      : DEFAULT_LOCK_MS;

  const lockOnBlur = vault?.settings?.lockOnBlur ?? false;

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const resetTimer = useCallback(() => {
    clearTimer();
    if (!isUnlocked) return;
    timerRef.current = setTimeout(() => {
      lock();
    }, autoLockMs);
  }, [isUnlocked, lock, autoLockMs, clearTimer]);

  useEffect(() => {
    if (!isUnlocked) {
      clearTimer();
      return;
    }

    // Activity events that reset the timer
    const ACTIVITY_EVENTS = [
      'mousemove',
      'mousedown',
      'keydown',
      'touchstart',
      'scroll',
      'click',
    ] as const;

    const handleActivity = () => resetTimer();

    ACTIVITY_EVENTS.forEach((event) => {
      window.addEventListener(event, handleActivity, { passive: true });
    });

    // Lock on tab hidden (only if enabled in settings)
    const handleVisibilityChange = () => {
      if (document.hidden) {
        clearTimer();
        lock();
      }
    };

    // Lock on window blur (only if enabled in settings)
    const handleBlur = () => {
      clearTimer();
      lock();
    };

    // Always lock on page unload / refresh
    const handleBeforeUnload = () => {
      clearTimer();
      lock();
    };

    if (lockOnBlur) {
      document.addEventListener('visibilitychange', handleVisibilityChange);
      window.addEventListener('blur', handleBlur);
    }
    window.addEventListener('beforeunload', handleBeforeUnload);

    // Start the initial timer
    resetTimer();

    return () => {
      clearTimer();
      ACTIVITY_EVENTS.forEach((event) => {
        window.removeEventListener(event, handleActivity);
      });
      if (lockOnBlur) {
        document.removeEventListener('visibilitychange', handleVisibilityChange);
        window.removeEventListener('blur', handleBlur);
      }
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [isUnlocked, lock, lockOnBlur, resetTimer, clearTimer]);
}
