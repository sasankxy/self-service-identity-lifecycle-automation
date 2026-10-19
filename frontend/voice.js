/**
 * IdentityOS — voice input for the Directory Assistant.
 *
 * Thin layer over the browser's Web Speech API. It only ever writes text into #chat-input and
 * (optionally) clicks #send-btn, so the transcript goes through exactly the same path as typed text:
 * /assistant/query -> NLU -> policy engine -> "confirm" button. No backend changes.
 */
(() => {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  const LANG = 'en-IN';          // Indian-English model; change to 'en-US' / 'en-GB' if recognition feels off
  const MAX_CHARS = 500;         // backend: AssistantQuery.query max_length=500
  const AUTO_SEND_KEY = 'identityos-voice-autosend';

  const $ = (id) => document.getElementById(id);

  /* Spoken text -> what the NLU expects. Kept deliberately tiny: usernames are the main casualty. */
  function normalize(t) {
    return t
      .replace(/(\w)\s+dot\s+(\w)/gi, '$1.$2')        // "kai dot chen" -> "kai.chen"
      .replace(/\s+/g, ' ')
      .trim();
  }

  const ERRORS = {
    'not-allowed': 'Microphone access is blocked. Allow it in the browser’s site settings and try again.',
    'service-not-allowed': 'Speech recognition is disabled in this browser.',
    'audio-capture': 'No microphone found.',
    'network': 'Speech recognition needs a network connection (the browser sends audio to its speech service).',
    'language-not-supported': 'This browser doesn’t support that recognition language.',
  };

  function init() {
    const input = $('chat-input'), send = $('send-btn'), wrapper = document.querySelector('.chat-input-wrapper');
    if (!input || !send || !wrapper) return;

    const mic = document.createElement('button');
    mic.type = 'button';
    mic.id = 'mic-btn';
    mic.className = 'mic-btn';
    mic.setAttribute('aria-label', 'Start voice input');
    mic.setAttribute('aria-pressed', 'false');
    mic.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="12" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><line x1="12" y1="18" x2="12" y2="22"/></svg>';
    wrapper.insertBefore(mic, send);

    const status = document.createElement('div');
    status.className = 'voice-status';
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    status.hidden = true;
    wrapper.parentNode.insertBefore(status, wrapper.nextSibling);

    const say = (msg, isError) => {
      status.textContent = msg || '';
      status.hidden = !msg;
      status.classList.toggle('voice-status--error', !!isError);
    };

    // Unsupported browser (Firefox) or insecure origin: hide the button rather than show a dead control.
    if (!SR || !window.isSecureContext) { mic.hidden = true; return; }

    const autoSend = () => localStorage.getItem(AUTO_SEND_KEY) === '1';

    let rec = null, listening = false, base = '', finalText = '', cancelled = false;

    const setListening = (on) => {
      listening = on;
      mic.classList.toggle('mic-btn--on', on);
      mic.setAttribute('aria-pressed', String(on));
      mic.setAttribute('aria-label', on ? 'Stop voice input' : 'Start voice input');
    };

    const render = (interim) => {
      const spoken = normalize(finalText + interim);
      input.value = (base ? base + ' ' : '') + spoken;
      input.dataset.mode = 'voice';                      // read by send() in pages.js -> input_mode: 'voice'
      input.dispatchEvent(new Event('input'));          // reuse the textarea auto-resize handler
    };

    function start() {
      if (listening) return;
      rec = new SR();
      rec.lang = LANG;
      rec.continuous = false;            // one utterance per press; stops itself after a pause
      rec.interimResults = true;         // live preview while speaking
      rec.maxAlternatives = 1;
      base = input.value.trim(); finalText = ''; cancelled = false;

      rec.onstart = () => { setListening(true); say('Listening… speak now (Esc to cancel)'); };
      rec.onresult = (e) => {
        let interim = '';
        for (let i = e.resultIndex; i < e.results.length; i++) {
          const r = e.results[i];
          if (r.isFinal) finalText += r[0].transcript + ' '; else interim += r[0].transcript;
        }
        render(interim);
      };
      rec.onerror = (e) => {
        if (e.error === 'aborted') return;
        cancelled = true;
        say(e.error === 'no-speech' ? 'Didn’t catch anything — try again.' : (ERRORS[e.error] || `Voice input failed (${e.error}).`), e.error !== 'no-speech');
      };
      rec.onend = () => {
        setListening(false);
        const spoken = normalize(finalText);
        if (cancelled) { if (!status.classList.contains('voice-status--error') && status.textContent.indexOf('Didn') !== 0) say(''); return; }
        if (!spoken) { say('Didn’t catch anything — try again.'); return; }
        if (input.value.length > MAX_CHARS) { input.value = input.value.slice(0, MAX_CHARS); say(`Trimmed to ${MAX_CHARS} characters (assistant limit).`, true); }
        else say(autoSend() ? '' : 'Check the text, then press Enter or Send.');
        input.focus();
        if (autoSend() && input.value.trim()) send.click();   // same handler as a typed message
      };

      try { rec.start(); } catch (_) { setListening(false); say('Could not start voice input.', true); }
    }

    function stop(cancel) {
      if (!rec || !listening) return;
      cancelled = !!cancel;
      if (cancel) { input.value = base; delete input.dataset.mode; input.dispatchEvent(new Event('input')); rec.abort(); setListening(false); say(''); }
      else rec.stop();
    }

    // Any real keystroke/paste means the person edited the text: it is no longer a pure transcript, so treat it as typed.
    input.addEventListener('input', (e) => { if (e.isTrusted) delete input.dataset.mode; });
    mic.addEventListener('click', () => (listening ? stop(false) : start()));
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && listening) stop(true); });
    // Don't keep the mic open when the user leaves the assistant page or tab.
    document.addEventListener('visibilitychange', () => { if (document.hidden) stop(true); });
    document.querySelectorAll('.nav-item[data-page]').forEach((n) => n.addEventListener('click', () => stop(true)));
    $('new-chat-btn')?.addEventListener('click', () => stop(true));
    send.addEventListener('click', () => stop(true));

    // Optional auto-send toggle, shown under the input. Off by default: names are easy to mis-hear.
    const label = document.createElement('label');
    label.className = 'voice-autosend';
    label.innerHTML = '<input type="checkbox" id="voice-autosend"> Send automatically after speaking';
    const cb = label.querySelector('input');
    cb.checked = autoSend();
    cb.addEventListener('change', () => localStorage.setItem(AUTO_SEND_KEY, cb.checked ? '1' : '0'));
    status.parentNode.insertBefore(label, status.nextSibling);
  }

  document.addEventListener('DOMContentLoaded', init);
})();