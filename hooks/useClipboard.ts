// ============================================================
// useClipboard — secure clipboard with auto-clear
// ============================================================

'use client';

import { useState, useRef, useCallback, useEffect } from 'react';
import { useVaultStore } from '@/store/vaultStore';

const DEFAULT_CLEAR_SECONDS = 20;

export function useClipboard() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const isMountedRef = useRef(true);

  const vault = useVaultStore((s) => s.vault);
  const clearSeconds =
    vault?.settings?.clipboardClearSeconds ?? DEFAULT_CLEAR_SECONDS;

  const clearTimers = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      // Stop countdown interval on unmount, but let any pending clipboard-clear
      // timeout still execute so sensitive text does not remain in the clipboard.
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
  }, []);

  const copyToClipboard = useCallback(
    async (text: string, id: string) => {
      clearTimers();

      try {
        await navigator.clipboard.writeText(text);
      } catch {
        // Fallback for older browsers (still no Math.random)
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }

      if (isMountedRef.current) {
        setCopiedId(id);
        setSecondsLeft(clearSeconds);
      }

      // Countdown
      intervalRef.current = setInterval(() => {
        if (!isMountedRef.current) {
          if (intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
          }
          return;
        }
        setSecondsLeft((s) => {
          if (s <= 1) {
            if (intervalRef.current) {
              clearInterval(intervalRef.current);
              intervalRef.current = null;
            }
            return 0;
          }
          return s - 1;
        });
      }, 1000);

      // Clear clipboard after timeout
      timerRef.current = setTimeout(async () => {
        try {
          await navigator.clipboard.writeText('');
        } catch {
          // Best-effort clear
        }
        timerRef.current = null;
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
          intervalRef.current = null;
        }
        if (isMountedRef.current) {
          setCopiedId(null);
          setSecondsLeft(0);
        }
      }, clearSeconds * 1000);
    },
    [clearSeconds, clearTimers]
  );

  return { copiedId, secondsLeft, copyToClipboard };
}
