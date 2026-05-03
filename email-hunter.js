#!/usr/bin/env node

import chalk from 'chalk';
import axios from 'axios';
import dns from 'dns/promises';
import net from 'net';

// ─── Args ────────────────────────────────────────────────────────────────────
const email   = process.argv[2];
const hibpIdx = process.argv.indexOf('--hibp-key');
const hibpKey = hibpIdx !== -1 ? process.argv[hibpIdx + 1] : null;

// ─── Disposable domain list ───────────────────────────────────────────────────
const DISPOSABLE = new Set([
  'mailinator.com','guerrillamail.com','tempmail.com','throwaway.email',
  'yopmail.com','sharklasers.com','grr.la','guerrillamail.info',
  'guerrillamail.biz','guerrillamail.de','guerrillamail.net','guerrillamail.org',
  'spam4.me','10minutemail.com','trashmail.com','trashmail.me','trashmail.net',
  'dispostable.com','fakeinbox.com','maildrop.cc','spamgourmet.com',
  'tempinbox.com','throwam.com','mailnull.com','spamfree24.org','byom.de',
  'spamspot.com','discard.email','mailscrap.com','spammotel.com',
  'getnada.com','throwam.com','tempr.email','dispostable.com',
  'tempail.com','spamgourmet.org','getairmail.com','filzmail.com',
  'spamherelots.com','jetable.fr.nf','noref.in','spamthisplease.com',
]);

// ─── Helpers ──────────────────────────────────────────────────────────────────
function validateFormat(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function extractDomain(email) {
  return email.split('@')[1].toLowerCase();
}

async function lookupMX(domain) {
  try {
    const records = await dns.resolveMx(domain);
    return records.sort((a, b) => a.priority - b.priority);
  } catch {
    return null;
  }
}

async function lookupA(domain) {
  try {
    return await dns.resolve4(domain);
  } catch {
    return null;
  }
}

function isDisposable(domain) {
  return DISPOSABLE.has(domain.toLowerCase());
}

// ─── SMTP Verification ────────────────────────────────────────────────────────
function checkSMTP(mxHost, email) {
  return new Promise((resolve) => {
    const socket  = net.createConnection(25, mxHost);
    let   buffer  = '';
    let   stage   = 0;

    const cleanup = (result) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(result);
    };

    const timer = setTimeout(
      () => cleanup({ status: 'blocked', label: 'Blocked / Timed out (normal for major providers)' }),
      6000
    );

    socket.on('data', (data) => {
      buffer += data.toString();

      if (stage === 0 && buffer.includes('220')) {
        socket.write('EHLO email-hunter\r\n');
        stage = 1; buffer = '';
      } else if (stage === 1 && buffer.match(/250/)) {
        socket.write('MAIL FROM:<probe@email-hunter.io>\r\n');
        stage = 2; buffer = '';
      } else if (stage === 2 && buffer.includes('250')) {
        socket.write(`RCPT TO:<${email}>\r\n`);
        stage = 3; buffer = '';
      } else if (stage === 3) {
        socket.write('QUIT\r\n');
        if      (buffer.match(/^2\d\d/m))  cleanup({ status: 'valid',     label: 'Address ACCEPTED by mail server' });
        else if (buffer.match(/^55[013]/m)) cleanup({ status: 'invalid',   label: 'Address REJECTED by mail server' });
        else                                cleanup({ status: 'uncertain', label: 'Server gave an ambiguous response' });
      }
    });

    socket.on('error', () => cleanup({ status: 'blocked', label: 'Connection refused (port 25 likely filtered)' }));
  });
}

// ─── HaveIBeenPwned ───────────────────────────────────────────────────────────
async function checkHIBP(email, apiKey) {
  try {
    const res = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
      { headers: { 'hibp-api-key': apiKey, 'User-Agent': 'email-hunter-cli' } }
    );
    return { ok: true, data: res.data };
  } catch (err) {
    if (err.response?.status === 404) return { ok: true,  data: [] };
    if (err.response?.status === 401) return { ok: false, error: 'invalid_key' };
    return { ok: false, error: 'unreachable' };
  }
}

// ─── Banner ───────────────────────────────────────────────────────────────────
function printBanner() {
  console.log(chalk.red(`
  ███████╗███╗   ███╗ █████╗ ██╗██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔════╝████╗ ████║██╔══██╗██║██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ██╔████╔██║███████║██║██║      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗ ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  `));
  console.log(chalk.gray('  Email Reconnaissance Tool  |  For Educational Purposes Only\n'));
}

// ─── Separator ────────────────────────────────────────────────────────────────
const sep = () => console.log(chalk.gray('  ' + '─'.repeat(60)));

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  printBanner();

  if (!email) {
    console.log(chalk.red('  [!] Usage: node email-hunter.js <email> [--hibp-key <key>]\n'));
    process.exit(1);
  }

  console.log(chalk.cyan(`  [*] Target » ${chalk.white.bold(email)}`));
  sep();

  // ── 1. Format Validation ───────────────────────────────────────────────────
  console.log(chalk.gray('\n  [~] Validating email format...'));
  if (!validateFormat(email)) {
    console.log(chalk.red('  [✗] Invalid email format. Aborting.\n'));
    process.exit(1);
  }
  console.log(chalk.green('  [✓] Format is valid'));

  const domain = extractDomain(email);
  console.log(chalk.gray(`  [i] Domain: ${chalk.white(domain)}`));

  // ── 2. Disposable Check ────────────────────────────────────────────────────
  console.log(chalk.gray('\n  [~] Checking disposable email providers...'));
  if (isDisposable(domain)) {
    console.log(chalk.yellow('  [⚠] DISPOSABLE email address detected'));
  } else {
    console.log(chalk.green('  [✓] Not a known disposable provider'));
  }

  // ── 3. DNS Lookup ──────────────────────────────────────────────────────────
  sep();
  console.log(chalk.gray('\n  [~] Performing DNS lookups...'));

  const mxRecords = await lookupMX(domain);
  if (!mxRecords || mxRecords.length === 0) {
    console.log(chalk.red('  [✗] No MX records found — domain cannot receive email'));
    console.log(chalk.red('\n  [!] Scan aborted: no mail server detected.\n'));
    process.exit(0);
  }

  console.log(chalk.green(`  [✓] MX Records (${mxRecords.length} found):`));
  for (const r of mxRecords) {
    console.log(chalk.white(`      ${String(r.priority).padEnd(4)} → ${r.exchange}`));
  }

  const aRecords = await lookupA(domain);
  if (aRecords) {
    console.log(chalk.green(`  [✓] A Records: ${aRecords.join(', ')}`));
  }

  // ── 4. SMTP Verification ───────────────────────────────────────────────────
  sep();
  console.log(chalk.gray('\n  [~] Attempting SMTP verification via primary MX...'));
  console.log(chalk.gray(`  [i] Connecting to ${mxRecords[0].exchange}:25`));

  const smtp = await checkSMTP(mxRecords[0].exchange, email);

  if      (smtp.status === 'valid')     console.log(chalk.green(`  [✓] SMTP: ${smtp.label}`));
  else if (smtp.status === 'invalid')   console.log(chalk.red(`  [✗] SMTP: ${smtp.label}`));
  else if (smtp.status === 'uncertain') console.log(chalk.yellow(`  [?] SMTP: ${smtp.label}`));
  else                                  console.log(chalk.yellow(`  [⚠] SMTP: ${smtp.label}`));

  // ── 5. HaveIBeenPwned ──────────────────────────────────────────────────────
  sep();
  if (hibpKey) {
    console.log(chalk.gray('\n  [~] Checking HaveIBeenPwned database...'));
    const hibp = await checkHIBP(email, hibpKey);

    if (!hibp.ok && hibp.error === 'invalid_key') {
      console.log(chalk.red('  [✗] Invalid HIBP API key'));
    } else if (!hibp.ok) {
      console.log(chalk.yellow('  [⚠] Could not reach HIBP API'));
    } else if (hibp.data.length === 0) {
      console.log(chalk.green('  [✓] Not found in any known data breaches'));
    } else {
      console.log(chalk.red(`  [!] Found in ${chalk.white.bold(hibp.data.length)} breach(es):\n`));
      for (const b of hibp.data) {
        console.log(chalk.red(
          `      ✗ ${chalk.white.bold(b.Name)} — ${b.BreachDate} — ${chalk.gray(b.PwnCount.toLocaleString() + ' accounts')}`
        ));
      }
    }
  } else {
    console.log(chalk.gray('\n  [i] Tip: Pass --hibp-key <key> to check breach databases.'));
    console.log(chalk.gray('      Get a free key at: https://haveibeenpwned.com/API/Key'));
  }

  sep();
  console.log(chalk.cyan('\n  [*] Scan complete.\n'));
}

main().catch((err) => {
  console.error(chalk.red(`\n  [!] Unexpected error: ${err.message}\n`));
  process.exit(1);
});
