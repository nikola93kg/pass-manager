// ============================================================
// MULTI-TAB SYNCHRONIZATION & LOCK PROPAGATION
// Uses BroadcastChannel (when available) + storage events to:
// 1. Propagate manual/inactivity locks across all open tabs.
// 2. Detect external localStorage writes from sibling tabs.
// Never broadcasts plaintext credentials or keys.
// ============================================================

export type TabSyncPayload =
  | { type: 'LOCK_VAULT' }
  | { type: 'VAULT_REVISION_UPDATED'; revision: number };

export type TabSyncMessage = TabSyncPayload & { senderId: string };

const CHANNEL_NAME = 'nmark_pass_vault_tab_sync_v2';

let tabSenderId: string | null = null;

export function getTabSenderId(): string {
  if (!tabSenderId) {
    tabSenderId =
      typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `tab-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
  }
  return tabSenderId;
}

export function broadcastTabMessage(msg: TabSyncPayload): void {
  if (typeof window === 'undefined' || typeof BroadcastChannel === 'undefined') {
    return;
  }
  try {
    const channel = new BroadcastChannel(CHANNEL_NAME);
    channel.postMessage({ ...msg, senderId: getTabSenderId() });
    channel.close();
  } catch {
    // Best-effort only
  }
}

export function subscribeTabSync(
  onMessage: (msg: TabSyncMessage) => void
): () => void {
  if (typeof window === 'undefined' || typeof BroadcastChannel === 'undefined') {
    return () => {};
  }

  let channel: BroadcastChannel | null = null;
  try {
    channel = new BroadcastChannel(CHANNEL_NAME);
    channel.onmessage = (event: MessageEvent<TabSyncMessage>) => {
      const data = event.data;
      if (!data || typeof data !== 'object' || data.senderId === getTabSenderId()) {
        return;
      }
      onMessage(data);
    };
  } catch {
    return () => {};
  }

  return () => {
    try {
      channel?.close();
    } catch {
      // ignore
    }
  };
}
