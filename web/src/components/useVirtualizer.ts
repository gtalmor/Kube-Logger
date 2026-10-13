// Thin Preact binding for @tanstack/virtual-core (same shape as react-virtual).
import { useLayoutEffect, useMemo, useReducer } from 'preact/hooks';
import { Virtualizer, elementScroll, observeElementOffset, observeElementRect, type PartialKeys, type VirtualizerOptions } from '@tanstack/virtual-core';

export type ElementVirtualizer = Virtualizer<HTMLDivElement, HTMLElement>;

export function useVirtualizer(
  options: PartialKeys<VirtualizerOptions<HTMLDivElement, HTMLElement>, 'observeElementRect' | 'observeElementOffset' | 'scrollToFn'>,
): ElementVirtualizer {
  const [, rerender] = useReducer((x: number) => x + 1, 0);
  const resolved: VirtualizerOptions<HTMLDivElement, HTMLElement> = {
    observeElementRect,
    observeElementOffset,
    scrollToFn: elementScroll,
    ...options,
    onChange: (instance, sync) => {
      if (sync) rerender(0); else rerender(0);
      options.onChange?.(instance, sync);
    },
  };
  const instance = useMemo(() => new Virtualizer<HTMLDivElement, HTMLElement>(resolved), []);
  instance.setOptions(resolved);
  useLayoutEffect(() => instance._didMount(), [instance]);
  useLayoutEffect(() => instance._willUpdate());
  return instance;
}
