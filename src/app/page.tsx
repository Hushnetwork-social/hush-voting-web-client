import AuthRoot from './auth/AuthRoot';

/**
 * Root application page.
 *
 * FEAT-002 replaces the foundation screen with the auth-gated root: the
 * branded Sovereign Shield renders immediately; protected content mounts only
 * after local unlock + exact online identity verification. The visible URL
 * remains `/`; no election/workflow identifier is exposed here.
 */
export default function HomePage() {
  return <AuthRoot />;
}
