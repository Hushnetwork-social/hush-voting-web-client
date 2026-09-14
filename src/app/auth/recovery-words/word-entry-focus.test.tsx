/** EPIC-001 -> FEAT-008 AC-008-079, validation feedback -> Phase 5 Tasks 5.1/5.2.
 * App Twins: numbered error focus/links and phrase-wide checksum feedback.
 * Public input only; never snapshot or serialize recovery values.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { WordGridProjection } from '../../../lib/recovery-words/contracts/projection';
import { WordEntryScreen } from './word-entry';

function projection(overrides: Partial<WordGridProjection> = {}): WordGridProjection {
  return {
    selectedWordCount: '12', invalidPositions: [], countValid: true,
    vocabularyValid: true, checksumState: 'notRun', allConcealed: true,
    busy: false, canVerify: true, errorSummary: [], pasteReplacementPending: false,
    ...overrides,
  };
}
function callbacks() {
  return { onSelectCount: vi.fn(), onPastePhrase: vi.fn(), onConfirmPasteReplacement: vi.fn(),
    onClearAll: vi.fn(), onVerify: vi.fn(), onBack: vi.fn() };
}

describe('Recovery validation focus (FEAT-008 Task 5.2)', () => {
  it('focuses the first numbered invalid input and links every affected input without echoing words', async () => {
    // Arrange: a completed authority validation returns unordered numbered positions.
    const user = userEvent.setup();
    const props = callbacks();
    const view = render(<WordEntryScreen {...props} grid={projection({ busy: true })} />);

    // Act.
    view.rerender(<WordEntryScreen {...props} grid={projection({ invalidPositions: [8, 3],
      errorSummary: [{ code: 'UNKNOWN_WORD', positions: [8, 3] }] })} />);

    // Assert: link activation targets the actual field and has no secret label.
    expect(screen.getByLabelText('Recovery word 3 of 12')).toHaveFocus();
    const summary = screen.getByRole('region', { name: 'Recovery word errors' });
    expect(summary).toBeVisible();
    expect(screen.getByRole('link', { name: 'Review word 3' })).toBeVisible();
    await user.click(screen.getByRole('link', { name: 'Review word 8' }));
    expect(screen.getByLabelText('Recovery word 8 of 12')).toHaveFocus();
  });

  it('focuses a phrase-wide checksum summary while retaining concealed inputs and no invented invalid position', () => {
    // Arrange.
    const props = callbacks();
    const view = render(<WordEntryScreen {...props} grid={projection()} />);
    const first = screen.getByLabelText('Recovery word 1 of 12');
    fireEvent.change(first, { target: { value: 'abandon' } });
    first.focus();

    // Act.
    view.rerender(<WordEntryScreen {...props} grid={projection({ checksumState: 'failed' })} />);

    // Assert.
    expect(screen.getByRole('region', { name: 'Recovery word errors' })).toHaveFocus();
    expect(first).toHaveValue('abandon');
    expect(first).toHaveAttribute('type', 'password');
    expect(screen.queryByRole('link', { name: /Review word/ })).toBeNull();
    expect(document.body.textContent).not.toContain('abandon');
  });

  it('does not steal correction focus on an equivalent projection, but focuses a repeated failed validation', () => {
    // Arrange.
    const props = callbacks();
    const view = render(<WordEntryScreen {...props} grid={projection({ checksumState: 'failed' })} />);
    const last = screen.getByLabelText('Recovery word 12 of 12');
    last.focus();

    // Act: harmless new projection object must not restart focus management.
    view.rerender(<WordEntryScreen {...props} grid={projection({ checksumState: 'failed' })} />);

    // Assert, followed by a distinct validation attempt.
    expect(last).toHaveFocus();
    view.rerender(<WordEntryScreen {...props} grid={projection({ busy: true, checksumState: 'pending' })} />);
    view.rerender(<WordEntryScreen {...props} grid={projection({ checksumState: 'failed' })} />);
    expect(screen.getByRole('region', { name: 'Recovery word errors' })).toHaveFocus();
  });

  it('focuses and links an unknown pasted position without lifting its value into the error summary', () => {
    // Arrange.
    render(<WordEntryScreen {...callbacks()} grid={projection()} />);
    const words = Array<string>(12).fill('abandon');
    words[4] = 'notabipword';

    // Act.
    fireEvent.paste(screen.getByLabelText('Recovery word 1 of 12'),
      { clipboardData: { getData: () => words.join(' ') } });

    // Assert.
    expect(screen.getByLabelText('Recovery word 5 of 12')).toHaveFocus();
    expect(screen.getByRole('link', { name: 'Review word 5' })).toBeVisible();
    expect(screen.getByRole('region', { name: 'Recovery word errors' }).textContent).not.toContain('notabipword');
  });
});
