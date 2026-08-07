import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { abbreviatePublicKey, AuthenticatedUserMenu } from './AuthenticatedUserMenu';

const identity = {
  alias: 'Alice',
  publicSigningKey: '02abcdef0123456789',
  publicEncryptionKey: '03abcdef0123456789',
};

describe('authenticated user popup', () => {
  it('shows only verified public identity information', async () => {
    const user = userEvent.setup();
    render(<AuthenticatedUserMenu identity={identity} onLock={() => undefined} />);

    await user.click(screen.getByRole('button', { name: 'Alice' }));
    expect(screen.getByRole('dialog', { name: 'User information' })).toBeVisible();
    expect(screen.getAllByText(identity.alias)).toHaveLength(2);
    expect(screen.getByText(abbreviatePublicKey(identity.publicSigningKey))).toBeInTheDocument();
    expect(screen.getByText(abbreviatePublicKey(identity.publicEncryptionKey))).toBeInTheDocument();
    expect(screen.queryByText(identity.publicSigningKey)).toBeNull();
    expect(screen.queryByText(identity.publicEncryptionKey)).toBeNull();
  });

  it('copies the selected full key while displaying only its abbreviation', async () => {
    const user = userEvent.setup();
    render(<AuthenticatedUserMenu identity={identity} onLock={() => undefined} />);
    await user.click(screen.getByRole('button', { name: 'Alice' }));
    const writeText = vi.spyOn(navigator.clipboard, 'writeText');

    await user.click(screen.getByRole('button', { name: 'Copy public signing key' }));
    expect(writeText).toHaveBeenCalledWith(identity.publicSigningKey);
    expect(screen.getByText('Copied')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Copy public encryption key' }));
    expect(writeText).toHaveBeenCalledWith(identity.publicEncryptionKey);
  });

  it('closes on Escape and restores focus to the trigger', async () => {
    const user = userEvent.setup();
    render(<AuthenticatedUserMenu identity={identity} onLock={() => undefined} />);
    const trigger = screen.getByRole('button', { name: 'Alice' });
    await user.click(trigger);
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'User information' })).toBeNull();
    expect(trigger).toHaveFocus();
  });

  it('closes when clicking outside', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <AuthenticatedUserMenu identity={identity} onLock={() => undefined} />
        <button type="button">Outside</button>
      </div>,
    );
    await user.click(screen.getByRole('button', { name: 'Alice' }));
    await user.click(screen.getByRole('button', { name: 'Outside' }));
    expect(screen.queryByRole('dialog', { name: 'User information' })).toBeNull();
  });

  it('invokes Lock from the bottom action', async () => {
    const user = userEvent.setup();
    const onLock = vi.fn();
    render(<AuthenticatedUserMenu identity={identity} onLock={onLock} />);
    await user.click(screen.getByRole('button', { name: 'Alice' }));
    await user.click(screen.getByRole('button', { name: 'Lock' }));
    expect(onLock).toHaveBeenCalledOnce();
    expect(screen.queryByRole('dialog', { name: 'User information' })).toBeNull();
  });
});
