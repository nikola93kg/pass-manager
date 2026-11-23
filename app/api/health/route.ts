import { NextResponse } from 'next/server';
import { isCloudSyncConfigured } from '@/lib/env';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json(
    {
      ok: true,
      service: 'nmark-pass-vault',
      cloudSyncConfigured: isCloudSyncConfigured(),
    },
    {
      status: 200,
      headers: { 'Cache-Control': 'no-store' },
    }
  );
}
