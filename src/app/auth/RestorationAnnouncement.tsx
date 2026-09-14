import { useEffect, useRef } from 'react';
import type { AuthRenderProjection } from '../../lib/auth/react/adapter';

type RestorationFacts = Pick<AuthRenderProjection, 'protectedAccess' | 'sessionEpoch' | 'completedRestorationEpoch' | 'completedRestorationKind'>;

/** Stable root live region: a completed child cannot announce success before the root verifies it. */
export function RestorationAnnouncement({ projection }: { readonly projection: RestorationFacts | null }) {
  const region = useRef<HTMLSpanElement>(null);
  const announcedEpoch = useRef<number | null>(null);
  const epoch = projection?.sessionEpoch;
  const receipt = projection?.completedRestorationEpoch;
  const allowed = projection?.protectedAccess === true;
  useEffect(() => {
    if (region.current === null) return;
    if (epoch === undefined || receipt !== epoch) {
      region.current.textContent = '';
      return;
    }
    if (allowed && announcedEpoch.current !== epoch) {
      announcedEpoch.current = epoch;
      // A single DOM text insertion notifies assistive technology without
      // remounting the region or adding another application-state render.
      region.current.textContent = 'Identity restored';
    }
  }, [epoch, receipt, allowed]);
  return <>
    <span ref={region} className="sr-only" role="status" aria-live="polite" aria-atomic="true" data-testid="restoration-announcement" />
    {allowed && epoch !== undefined && receipt === epoch && projection?.completedRestorationKind === 'restoreCredentialFile' && (
      <p className="mx-auto max-w-3xl px-6 pt-4 text-sm text-voting-muted" data-testid="backup-preservation-notice">
        Your original backup is unchanged and may still contain encrypted recovery words. HushVoting did not retain any recovery words.
      </p>
    )}
  </>;
}
