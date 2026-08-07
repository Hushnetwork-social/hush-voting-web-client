'use client';

import { createContext, useContext, type ReactNode } from 'react';

const InlineOnboardingBackContext = createContext(true);

/** Root composition supplies the single Back control above the setup heading. */
export function OnboardingBackProvider({ children }: { readonly children: ReactNode }) {
  return <InlineOnboardingBackContext.Provider value={false}>{children}</InlineOnboardingBackContext.Provider>;
}

/** Standalone component tests/previews keep their local Back control by default. */
export function useInlineOnboardingBack(): boolean {
  return useContext(InlineOnboardingBackContext);
}
