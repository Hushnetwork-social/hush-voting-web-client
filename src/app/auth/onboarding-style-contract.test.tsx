// EPIC-001 -> FEAT-007 AC-007-068 / FEAT-008 AC-008-079 / FEAT-009 AC-009-084.
// Isolated style contracts; actual target geometry is checked by the .NET browser journey.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import postcss from 'postcss';
import { ActionButton } from './create/surfaces';

const stylesheet = postcss.parse(readFileSync(resolve(process.cwd(), 'src/app/globals.css'), 'utf8'));

function declaration(selector: string, property: string): string {
  let value: string | undefined;
  stylesheet.walkRules(selector, rule => {
    rule.walkDecls(property, entry => { value = entry.value; });
  });
  if (value === undefined) throw new Error(`Missing style contract: ${selector}/${property}`);
  return value;
}

function luminance(hex: string): number {
  if (!/^#[a-f\d]{6}$/i.test(hex)) throw new Error('Expected an opaque six-digit theme colour.');
  return [0.2126, 0.7152, 0.0722].reduce((sum, weight, index) => {
    const channel = parseInt(hex.slice(1 + index * 2, 3 + index * 2), 16) / 255;
    return sum + weight * (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  }, 0);
}

describe('onboarding target and text contrast contracts', () => {
  it('reserves at least 44 CSS pixels on both axes for the shared Back control', () => {
    for (const axis of ['height', 'width']) {
      const value = declaration('.auth-back-link', `min-${axis}`);
      const match = /^(\d+(?:\.\d+)?)(px|rem)$/.exec(value);
      expect(match).not.toBeNull();
      const pixels = Number(match![1]) * (match![2] === 'rem' ? 16 : 1);
      expect(pixels).toBeGreaterThanOrEqual(44);
    }
  });

  it.each(['normal', 'hover'])('keeps creation danger text at least 4.5:1 in %s state', state => {
    render(<ActionButton variant="danger" onClick={vi.fn()}>Regenerate</ActionButton>);
    const button = screen.getByRole('button', { name: 'Regenerate' });
    expect(button).toHaveClass('text-white');
    const prefix = state === 'hover' ? 'hover:' : '';
    const background = [...button.classList].find(value => value.startsWith(`${prefix}bg-[var(`));
    expect(background).toBeDefined();
    const token = background!.match(/var\((--[a-z-]+)\)/)?.[1];
    expect(token).toBeDefined();
    const ratio = (1 + 0.05) / (luminance(declaration(':root', token!)) + 0.05);
    expect(ratio).toBeGreaterThanOrEqual(4.5);
  });
});
