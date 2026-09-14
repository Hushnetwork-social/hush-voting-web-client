import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { RestorationAnnouncement } from './RestorationAnnouncement';

describe('HushVotingApp TwinTests — restoration announcement', () => {
  // EPIC-001 -> FEAT-008 AC-008-071 -> Phase 4 Task 4.2 / Phase 5 Task 5.6.
  it('inserts one recovery announcement per verified epoch despite repeated access projections', async () => {
    const pending = { protectedAccess: false, sessionEpoch: 1, completedRestorationEpoch: 1,
      completedRestorationKind: 'restoreRecoveryWords' as const };
    const { rerender } = render(<RestorationAnnouncement projection={pending} />);
    const region = screen.getByRole('status');
    let announcements = 0;
    const observer = new MutationObserver(records => {
      announcements += records.filter(record => [...record.addedNodes].some(node => node.textContent === 'Identity restored')).length;
    });
    observer.observe(region, { childList: true });
    try {
      expect(region).toBeEmptyDOMElement();
      rerender(<RestorationAnnouncement projection={{ ...pending, protectedAccess: true }} />);
      await waitFor(() => expect(announcements).toBe(1));
      rerender(<RestorationAnnouncement projection={{ ...pending, protectedAccess: true }} />);
      rerender(<RestorationAnnouncement projection={pending} />);
      rerender(<RestorationAnnouncement projection={{ ...pending, protectedAccess: true }} />);
      rerender(<RestorationAnnouncement projection={{ ...pending, protectedAccess: true, sessionEpoch: 2 }} />);
      expect(region).toBeEmptyDOMElement();
      await Promise.resolve();
      expect(announcements).toBe(1);
      rerender(<RestorationAnnouncement projection={{ ...pending, protectedAccess: true, sessionEpoch: 2, completedRestorationEpoch: 2 }} />);
      await waitFor(() => expect(announcements).toBe(2));
      expect(screen.getByRole('status')).toBe(region);
      expect(region).toHaveAttribute('aria-atomic', 'true');
    } finally { observer.disconnect(); }
  });
  it('shows a truthful source-preservation notice only after verified file restoration in the current epoch', () => {
    const restored = { protectedAccess: false, sessionEpoch: 1, completedRestorationEpoch: 1, completedRestorationKind: 'restoreCredentialFile' as const };
    const { rerender } = render(<RestorationAnnouncement projection={restored} />);
    expect(screen.queryByTestId('backup-preservation-notice')).not.toBeInTheDocument();
    rerender(<RestorationAnnouncement projection={{ ...restored, protectedAccess: true }} />);
    expect(screen.getByTestId('backup-preservation-notice')).toHaveTextContent('Your original backup is unchanged');
    expect(screen.getByTestId('backup-preservation-notice')).toHaveTextContent('may still contain encrypted recovery words');
    expect(screen.getByTestId('backup-preservation-notice')).toHaveTextContent('HushVoting did not retain any recovery words');
    rerender(<RestorationAnnouncement projection={{ ...restored, protectedAccess: true, sessionEpoch: 2 }} />);
    expect(screen.queryByTestId('backup-preservation-notice')).not.toBeInTheDocument();
    rerender(<RestorationAnnouncement projection={{ ...restored, protectedAccess: true, completedRestorationKind: 'restoreRecoveryWords' }} />);
    expect(screen.queryByTestId('backup-preservation-notice')).not.toBeInTheDocument();
  });
  it('waits for protected access and retains one stable live region across the transition', () => {
    const before = { protectedAccess: false, sessionEpoch: 1, completedRestorationEpoch: null };
    const { rerender } = render(<RestorationAnnouncement projection={before} />);
    const region = screen.getByRole('status');
    expect(region).toBeEmptyDOMElement();
    rerender(<RestorationAnnouncement projection={{ ...before, completedRestorationEpoch: 1 }} />);
    expect(region).toBeEmptyDOMElement();
    rerender(<RestorationAnnouncement projection={{ ...before, completedRestorationEpoch: 1, protectedAccess: true }} />);
    expect(region).toHaveTextContent('Identity restored');
    expect(screen.getByRole('status')).toBe(region);
    expect(region).toHaveAttribute('aria-live', 'polite');
  });

  it('cannot announce a child completion from a revoked epoch or an ordinary later unlock', () => {
    const { rerender } = render(<RestorationAnnouncement projection={{ protectedAccess: true, sessionEpoch: 1, completedRestorationEpoch: 1 }} />);
    expect(screen.getByRole('status')).toHaveTextContent('Identity restored');
    rerender(<RestorationAnnouncement projection={{ protectedAccess: false, sessionEpoch: 2, completedRestorationEpoch: null }} />);
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    rerender(<RestorationAnnouncement projection={{ protectedAccess: true, sessionEpoch: 2, completedRestorationEpoch: 1 }} />);
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    rerender(<RestorationAnnouncement projection={{ protectedAccess: true, sessionEpoch: 2, completedRestorationEpoch: null }} />);
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
  });
});
