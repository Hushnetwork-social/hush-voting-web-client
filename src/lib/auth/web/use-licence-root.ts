/**
 * FEAT-017 Task 6.1 — page-side licence root hook (Web composition).
 *
 * React adapter over the EntitlementBridge licence mirror + machine
 * projection. Returns the closed `LicenceUpgradePresentationInput` (or null
 * when no safe licence facts exist) plus the account summary facts for the
 * Account menu. AuthRoot uses this hook to keep the root shell, Account menu,
 * and workspace surfaces driven by the SAME authority facts.
 *
 * The hook never signs, journals, stores, or polls; it only mirrors safe
 * progress and re-renders when a new safe broadcast arrives.
 *
 * Normative source: FEAT-017 FeatureDescription; Task 6.1 behavior spec.
 */

import { useEffect, useMemo, useState } from 'react';
import type { AuthRenderProjection } from '../react/adapter';
import type { EntitlementBridge } from './entitlement-bridge';
import { presentationInputFromMirror } from './licence-workspace';
import type { LicenceUpgradePresentationInput } from '../../licensing/upgrade-presentation';
import { projectAccountLicenceSummary } from '../../licensing/upgrade-presentation';
import type { LicenceAccountSummaryFacts } from '../../licensing/upgrade-presentation';

export interface LicenceRootFacts {
  readonly input: LicenceUpgradePresentationInput | null;
  readonly account: LicenceAccountSummaryFacts | null;
}

export function useLicenceRootFacts(
  bridge: EntitlementBridge | null,
  projection: AuthRenderProjection | null,
): LicenceRootFacts {
  const [version, setVersion] = useState(0);

  useEffect(() => {
    if (bridge === null) {
      return;
    }
    const unsub = bridge.subscribeLicenceWorkspace(() => setVersion((v) => v + 1));
    return unsub;
  }, [bridge]);

  return useMemo(() => {
    if (bridge === null || projection === null) {
      return { input: null, account: null };
    }
    // Re-evaluate when a new safe broadcast arrives.
    void version;
    const mirror = bridge.licenceFacts();
    const input = presentationInputFromMirror({ mirror, projection });
    if (input === null) {
      return { input: null, account: null };
    }
    return {
      input,
      account: projectAccountLicenceSummary(input, defaultTimeZone()),
    };
    // version is an intentional dependency: new mirror broadcasts must
    // recompute the projections.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [bridge, projection, version]);
}

function defaultTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}
