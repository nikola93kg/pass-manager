import { NextResponse } from 'next/server';
import {
  isCloudSyncConfigured,
  isLocalOnlyModeAllowed,
  getUpstashRedisConfig,
  getTrustedProxyConfig,
} from '@/lib/env';

export const dynamic = 'force-dynamic';

export async function GET() {
  const cloudSyncConfigured = isCloudSyncConfigured();
  const localOnlyAllowed = isLocalOnlyModeAllowed();
  const distributedRateLimitConfigured = getUpstashRedisConfig() !== null;
  const { provider: trustedProxyProvider } = getTrustedProxyConfig();

  return NextResponse.json(
    {
      ok: cloudSyncConfigured || localOnlyAllowed,
      service: 'nmark-pass-vault',
      cloudSyncConfigured,
      localOnlyAllowed,
      distributedRateLimitConfigured,
      trustedProxyProvider,
    },
    {
      status: 200,
      headers: { 'Cache-Control': 'no-store' },
    }
  );
}
