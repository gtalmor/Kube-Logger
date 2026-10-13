import { render } from 'preact';
import './styles/tokens.css';
import './styles/base.css';
import './styles/app.css';
import { App } from './components/App';
import { store, loadText } from './state/app';
import { connect, maybeRedirectToLastSession, send, dispatch } from './state/connection';
import { sampleCapture } from './lib/testutil';

declare global {
  interface Window { __kl: { store: typeof store; loadFile: (text: string) => void; send: typeof send; dispatch: typeof dispatch; simulate: (linesPerSec: number, seconds?: number) => () => void } }
}

// Debug / smoke hooks: window.__kl.loadFile(text), window.__kl.simulate(1000).
window.__kl = {
  store,
  loadFile: (text: string) => loadText(text, 'text'),
  send,
  dispatch,
  simulate(linesPerSec: number, seconds = 60) {
    const raws = sampleCapture(5000);
    let k = 0, i = 0;
    const per = Math.max(1, Math.round(linesPerSec / 20));
    const t = setInterval(() => {
      const items = [];
      for (let j = 0; j < per; j++) { items.push({ i: i++, ns: 'demo', line: raws[k++ % raws.length] }); }
      dispatch({ type: 'log-batch', items });
    }, 50);
    const stop = () => clearInterval(t);
    setTimeout(stop, seconds * 1000);
    return stop;
  },
};

if (!maybeRedirectToLastSession()) {
  render(<App />, document.getElementById('app') as HTMLElement);
  const demo = new URLSearchParams(location.search).get('demo');
  if (demo) {
    const n = +demo > 1 ? +demo : 2000;
    dispatch({ type: 'capture-start', captureId: 'demo', ns: ['demo'], start: Date.now() });
    dispatch({ type: 'log-batch', items: sampleCapture(n).map((line, i) => ({ i, ns: 'demo', line })) });
    dispatch({ type: 'capture-end', n });
  } else {
    connect();
  }
}
