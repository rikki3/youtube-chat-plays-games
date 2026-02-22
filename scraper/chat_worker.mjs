import { chromium } from 'playwright';

function emit(event) {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseArgs(argv) {
  const out = {
    videoId: '',
    profileDir: '',
    headless: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--video-id' && i + 1 < argv.length) {
      out.videoId = argv[++i];
      continue;
    }
    if (a === '--profile-dir' && i + 1 < argv.length) {
      out.profileDir = argv[++i];
      continue;
    }
    if (a === '--headless' && i + 1 < argv.length) {
      out.headless = String(argv[++i]).toLowerCase() === 'true';
      continue;
    }
  }

  return out;
}

async function installExtractor(page) {
  return page.evaluate(() => {
    const MESSAGE_SELECTOR = [
      'yt-live-chat-text-message-renderer',
      'yt-live-chat-paid-message-renderer',
      'yt-live-chat-paid-sticker-renderer',
    ].join(',');

    const MAX_SEEN = 500;
    const SEEN_TTL_MS = 120000;

    if (window.__ytplaysCleanupExtractor) {
      window.__ytplaysCleanupExtractor();
    }

    const queue = [];
    const seen = new Map();
    let observer = null;
    let xpathTimer = null;

    const nowMs = () => Date.now();

    function hashString(s) {
      let h = 5381;
      for (let i = 0; i < s.length; i += 1) {
        h = ((h << 5) + h) + s.charCodeAt(i);
        h |= 0;
      }
      return Math.abs(h).toString(16);
    }

    function cleanupSeen() {
      const now = nowMs();
      for (const [key, ts] of seen.entries()) {
        if ((now - ts) > SEEN_TTL_MS) seen.delete(key);
      }
      if (seen.size <= MAX_SEEN) return;
      const sorted = Array.from(seen.entries()).sort((a, b) => a[1] - b[1]);
      const overflow = sorted.length - MAX_SEEN;
      for (let i = 0; i < overflow; i += 1) {
        seen.delete(sorted[i][0]);
      }
    }

    function buildMessageId(node, author, message) {
      const rawId = (node && (node.id || node.getAttribute('id'))) || '';
      if (rawId) return rawId;
      const ts = node && node.querySelector ? (node.querySelector('#timestamp')?.textContent || '').trim() : '';
      return `h-${hashString(`${author}|${message}|${ts}`)}`;
    }

    function enqueueChat(author, message, id) {
      if (!message) return;
      cleanupSeen();
      if (seen.has(id)) return;
      seen.set(id, nowMs());
      queue.push({
        type: 'chat',
        id,
        author: author || 'YouTubeChat',
        userKey: author || 'YouTubeChat',
        message,
        timestamp: new Date().toISOString(),
      });
      if (queue.length > 1000) {
        queue.splice(0, queue.length - 1000);
      }
    }

    function extractMessageNode(node) {
      if (!node || !node.querySelector) return;
      const author = (node.querySelector('#author-name')?.textContent || '').trim();
      let message = (node.querySelector('#message')?.textContent || '').trim();
      if (!message) {
        message = (node.textContent || '').trim();
      }
      if (!message) return;
      enqueueChat(author, message, buildMessageId(node, author, message));
    }

    function scanNode(root) {
      if (!root || root.nodeType !== Node.ELEMENT_NODE) return;
      if (root.matches && root.matches(MESSAGE_SELECTOR)) {
        extractMessageNode(root);
      }
      if (root.querySelectorAll) {
        root.querySelectorAll(MESSAGE_SELECTOR).forEach((n) => extractMessageNode(n));
      }
    }

    function detectState() {
      const url = String(location.href || '');
      const txt = (document.body?.innerText || '').toLowerCase();
      if (url.includes('accounts.google.com')) {
        return { state: 'login_required', detail: 'redirected_to_google_signin' };
      }
      if (txt.includes('chat is disabled')) {
        return { state: 'chat_disabled', detail: 'live chat is disabled' };
      }
      if (txt.includes('chat ended') || txt.includes('you cannot send messages')) {
        return { state: 'chat_ended', detail: 'live chat ended' };
      }
      if (txt.includes('sign in to chat') || txt.includes('to join the chat')) {
        return { state: 'login_required', detail: 'sign in to chat' };
      }
      if (!document.querySelector('yt-live-chat-item-list-renderer')) {
        return { state: 'selector_miss', detail: 'chat list renderer missing' };
      }
      return { state: 'ok', detail: '' };
    }

    const list = document.querySelector('yt-live-chat-item-list-renderer #items') ||
                 document.querySelector('yt-live-chat-item-list-renderer');

    if (list) {
      scanNode(list);
      observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
          for (const n of m.addedNodes) {
            scanNode(n);
          }
        }
      });
      observer.observe(list, { childList: true, subtree: true });
    }

    // XPath fallback for markup drift: sample newest renderer periodically.
    xpathTimer = setInterval(() => {
      try {
        const xpath = '(//yt-live-chat-text-message-renderer | //yt-live-chat-paid-message-renderer | //yt-live-chat-paid-sticker-renderer)[last()]';
        const result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
        const latest = result.singleNodeValue;
        if (latest) extractMessageNode(latest);
      } catch (_) {
        // Ignore XPath issues; main observer path is primary.
      }
    }, 1500);

    window.__ytplaysDequeue = () => {
      const out = queue.splice(0, queue.length);
      return out;
    };

    window.__ytplaysState = () => detectState();

    window.__ytplaysCleanupExtractor = () => {
      if (observer) observer.disconnect();
      if (xpathTimer) clearInterval(xpathTimer);
      observer = null;
      xpathTimer = null;
    };

    const state = detectState();
    return { ok: true, hasList: Boolean(list), state };
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.videoId) {
    emit({ type: 'error', reason: 'bad_args', message: 'missing --video-id' });
    process.exit(2);
  }
  if (!args.profileDir) {
    emit({ type: 'error', reason: 'bad_args', message: 'missing --profile-dir' });
    process.exit(2);
  }

  const chatUrl = `https://www.youtube.com/live_chat?is_popout=1&v=${encodeURIComponent(args.videoId)}`;

  const context = await chromium.launchPersistentContext(args.profileDir, {
    headless: args.headless,
    viewport: { width: 1280, height: 900 },
  });

  const closeContext = async () => {
    try {
      await context.close();
    } catch (_) {
      // Ignore close errors.
    }
  };

  process.on('SIGINT', async () => {
    await closeContext();
    process.exit(0);
  });
  process.on('SIGTERM', async () => {
    await closeContext();
    process.exit(0);
  });

  let page = context.pages()[0];
  if (!page) page = await context.newPage();

  page.on('framenavigated', async (frame) => {
    if (frame === page.mainFrame()) {
      try {
        const installResult = await installExtractor(page);
        if (installResult?.state?.state && installResult.state.state !== 'ok') {
          emit({ type: 'status', state: installResult.state.state, detail: installResult.state.detail || '' });
        }
      } catch (err) {
        emit({ type: 'error', reason: 'inject_failed', message: String(err) });
      }
    }
  });

  await page.goto(chatUrl, { waitUntil: 'domcontentloaded', timeout: 60000 });
  const installResult = await installExtractor(page);
  emit({ type: 'ready' });
  if (!installResult?.hasList) {
    emit({ type: 'status', state: 'selector_miss', detail: 'chat list not found on initial load' });
  }

  let lastState = '';
  let lastStateDetail = '';
  let lastHeartbeat = Date.now();

  while (true) {
    const events = await page.evaluate(() => (window.__ytplaysDequeue ? window.__ytplaysDequeue() : []));
    for (const event of events) {
      emit(event);
    }

    const state = await page.evaluate(() => (window.__ytplaysState ? window.__ytplaysState() : ({ state: 'selector_miss', detail: 'extractor missing' })));
    if (state.state !== lastState || state.detail !== lastStateDetail) {
      emit({ type: 'status', state: state.state, detail: state.detail || '' });
      lastState = state.state;
      lastStateDetail = state.detail || '';
    }

    const now = Date.now();
    if ((now - lastHeartbeat) >= 10000) {
      emit({ type: 'status', state: 'heartbeat' });
      lastHeartbeat = now;
    }

    await sleep(400);
  }
}

main().catch((err) => {
  emit({ type: 'error', reason: 'worker_crash', message: String(err && err.stack ? err.stack : err) });
  process.exit(1);
});