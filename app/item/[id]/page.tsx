// ============================================================
// Client Hub Deep-Link Route: /item/{vaultItemId}
//
// Security Boundary:
// - Validates the item ID format before passing it to VaultApp.
// - NEVER returns credentials from the server or URL.
// - Requires full Auth + MFA (in cloud mode) AND local Master
//   Password unlock before opening the referenced entry.
// ============================================================

import VaultApp from '@/components/VaultApp';
import { isValidVaultItemId } from '@/lib/urlSafety';

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function DeepLinkItemPage({ params }: PageProps) {
  const { id } = await params;
  const validatedId = isValidVaultItemId(id) ? id : null;
  return <VaultApp initialItemId={validatedId} />;
}
