import type { AuthRenderProjection } from '../react/adapter';
import { electionEntitlementReason, type ElectionEntitlementReason } from '../../elections/entitlement';
import type { EntitlementStagePresentation } from './entitlement-presentation';

/** Closed E03 copy. Raw messages, keys, roster entries and server diagnostics never render. */
const COPY: Readonly<Record<ElectionEntitlementReason, { label: string; body: string }>> = {
  ENTITLEMENT_NOT_ACTIVE: { label: 'Active licence required', body: 'This new-election action needs an active licence. An election already opened keeps its captured voting and completion rights.' },
  ENTITLEMENT_LIMIT_EXCEEDED: { label: 'Voter limit exceeded', body: 'The resulting roster exceeds the election owner’s licence limit. Review the roster size before trying again.' },
  ENTITLEMENT_PROFILE_NOT_ALLOWED: { label: 'Profile unavailable', body: 'This election profile is not available under the owner’s licence. The saved Draft and governance lock are unchanged.' },
  ENTITLEMENT_AUTHORITY_UNAVAILABLE: { label: 'Election access unavailable', body: 'We couldn’t verify election access. Retry when the service is available.' },
  ENTITLEMENT_CAPTURE_UNAVAILABLE: { label: 'Election authorization unavailable', body: 'We couldn’t verify the authorization saved when this election opened. Retry or contact support. Renewing a licence will not repair this authorization.' },
  ENTITLEMENT_SEMANTICS_UNSUPPORTED: { label: 'Compatible service required', body: 'This election requires a compatible application and service. Retry after they have been updated, or contact support.' },
  ROSTER_REPLACEMENT_AFTER_LINK: { label: 'Roster replacement unavailable', body: 'A voter has already linked to this election. The current roster cannot be replaced and remains unchanged.' },
};

export function electionEntitlementFeedback(projection: AuthRenderProjection): EntitlementStagePresentation | null {
  const scope = projection.electionAccess;
  if (projection.authState !== 'authenticated' || projection.connectivity !== 'online' || !scope
    || scope.epoch !== projection.sessionEpoch || scope.actorSigningAddress !== projection.authenticatedIdentity?.publicSigningKey) return null;
  const reason = electionEntitlementReason(scope.reason);
  if (reason === null) return null;
  const copy = COPY[reason];
  return { key: `election:${reason}`, statusLabel: copy.label, bodyCopy: copy.body,
    busy: false, ariaBusy: false, controls: { retry: true, lock: true }, focusHeading: false, liveAnnounce: true };
}
