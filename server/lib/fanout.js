'use strict';
// Consumer send helpers with backpressure. A viewer that stops reading (tab
// in the background on a sleeping laptop, broken network) would otherwise
// make the relay buffer frames for it without limit.

const CLOSE_SLOW_CONSUMER = 4002;
const MB = 1024 * 1024;

function kick(ws, reason) {
  if (ws._kicked) return;
  ws._kicked = true;
  try { ws.close(CLOSE_SLOW_CONSUMER, reason || 'slow consumer'); } catch {}
  // ws waits for the peer's close frame; a stuck peer never sends one, so
  // make sure the socket really goes away.
  const t = setTimeout(() => { try { ws.terminate(); } catch {} }, 5000);
  if (t.unref) t.unref();
}

// Send one frame, or kick the consumer if its outbound buffer is too deep.
// Returns true if the frame was handed to the socket.
function sendOrKick(ws, raw, { maxBuffered = 16 * MB } = {}) {
  if (ws.readyState !== 1 || ws._kicked) return false;
  if (ws.bufferedAmount > maxBuffered) { kick(ws, 'slow consumer'); return false; }
  try { ws.send(raw); return true; } catch { return false; }
}

// Fan a frame out to every consumer. Consumers mid-replay get it queued so it
// lands after the history they're receiving.
function fanout(consumers, raw, opts = {}) {
  const maxPending = opts.maxPending || 8 * MB;
  for (const ws of consumers) {
    if (ws._replaying) {
      ws._pending.push(raw);
      ws._pendingBytes += raw.length;
      if (ws._pendingBytes > maxPending) kick(ws, 'slow consumer');
      continue;
    }
    sendOrKick(ws, raw, opts);
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const yieldLoop = () => new Promise(r => setImmediate(r));

// Replay stored history to a freshly connected consumer in chunks, yielding
// to the event loop between chunks and pausing while the socket's buffer is
// above `highWater`. Live frames that arrive meanwhile are queued on the
// socket (see fanout) and flushed after the history, before `history-end`.
async function replayHistory(ws, history, opts = {}) {
  const { chunk = 50, highWater = 4 * MB, deadlineMs = 60000, pollMs = 5 } = opts;
  const frames = history.frames();
  const begin = JSON.stringify({
    type: 'history-begin',
    captureId: history.captureId,
    lines: history.lines,
    batches: frames.length,
    firstIndex: history.firstIndex,
    lastIndex: history.lastIndex,
  });
  ws._replaying = true;
  ws._pending = [];
  ws._pendingBytes = 0;
  const finish = () => { ws._replaying = false; ws._pending = []; ws._pendingBytes = 0; };

  if (!sendOrKick(ws, begin, opts)) { finish(); return false; }
  const deadline = Date.now() + deadlineMs;
  for (let k = 0; k < frames.length; k += chunk) {
    const end = Math.min(k + chunk, frames.length);
    for (let j = k; j < end; j++) {
      if (!sendOrKick(ws, frames[j], opts)) { finish(); return false; }
    }
    while (ws.bufferedAmount > highWater) {
      if (Date.now() > deadline || ws.readyState !== 1) { kick(ws, 'slow consumer'); finish(); return false; }
      await sleep(pollMs);
    }
    await yieldLoop();
    if (ws.readyState !== 1 || ws._kicked) { finish(); return false; }
  }
  const pending = ws._pending;
  finish();
  for (const raw of pending) if (!sendOrKick(ws, raw, opts)) return false;
  return sendOrKick(ws, JSON.stringify({ type: 'history-end', captureId: history.captureId, lastIndex: history.lastIndex }), opts);
}

module.exports = { CLOSE_SLOW_CONSUMER, sendOrKick, fanout, replayHistory, kick };
