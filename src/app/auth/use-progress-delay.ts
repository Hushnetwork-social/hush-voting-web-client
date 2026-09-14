import { useEffect, useState } from 'react';

// FEAT-008 Safe progress / FEAT-009 Phase 5 Task 5.1.
const RESTORE_PROGRESS_DELAY_MS = 150;

/** Mount with an active operation; unmount on completion/cancellation. */
export function useProgressDelay(): boolean {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setReady(true), RESTORE_PROGRESS_DELAY_MS);
    return () => clearTimeout(timer);
  }, []);
  return ready;
}
