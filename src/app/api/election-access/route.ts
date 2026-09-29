import { NextResponse } from 'next/server';
import { ELECTION_QUERY_HEADERS, readElectionJson } from '../../../lib/elections/query';
import { isElectionId } from '../../../lib/elections/entitlement';
import { queryElectionAccess } from '../election-access-transport';

export const runtime = 'nodejs';
const noStore = { 'Cache-Control': 'no-store, max-age=0', Pragma: 'no-cache' };
export async function POST(request: Request): Promise<NextResponse> {
  const fail = (status: number) => NextResponse.json({ error: 'ELECTION_AUTHORITY_UNAVAILABLE' }, { status, headers: noStore });
  if (request.headers.get('content-type')?.split(';')[0].trim() !== 'application/json') return fail(400);
  const signed = ELECTION_QUERY_HEADERS.map(name => request.headers.get(name) ?? '');
  if (signed.some(value => value.length === 0 || value.length > 4096)) return fail(400);
  try {
    const body = await readElectionJson(request.body, 256);
    if (body === null || typeof body !== 'object' || Array.isArray(body)) return fail(400);
    const data = body as Record<string, unknown>;
    if (Object.keys(data).length !== 1 || !isElectionId(data.electionId)) return fail(400);
    const scope = await queryElectionAccess(data.electionId,
      { signatory: signed[0], signedAt: signed[1], signature: signed[2] }, process.env.HUSHSERVER_NODE_ENDPOINT);
    return NextResponse.json({ scope }, { headers: noStore });
  } catch { return fail(503); }
}
