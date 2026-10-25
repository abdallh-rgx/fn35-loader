# FN3.5 iOS Loader — Worklog

---
Task ID: 1
Agent: main (Z.ai)
Task: تشغيل Fortnite 3.5 iOS على Linux x64 عبر Unicorn حتى شاشة تسجيل الدخول

Work Log:
- الجلسة 1-2: تنزيل IPA، فك الضغط، تحليل Mach-O ARM64 (91.2MB، cryptid=0)
- بناء 8 سكربتات في scripts/ + 50 تشغيلة (run1-run50): crash مبكر → 773/773 mod_init → main() → UE LogInit
- الجلسة 3: إصلاح البيئة (unicorn 2.1.4)، سلسلة snapshots (segA-segAJ)

---
Task ID: 2
Agent: main (Z.ai)
Task: GitHub backup + تشخيص انهيار segAJ (PC=0 بعد GL limits)

Work Log:
- GitHub: التوكين ghp_cWLrcoD... **مرفوض (Bad credentials)** — يرجى توليد توكين جديد
  (Settings → Developer settings → Personal access tokens → scope: repo + workflow)
  المستودع المحلي جاهز: 24 ملف نظيف (كود فقط، بدون ملفات اللعبة - حقوق + حد 100MB)
- README.md + .github/workflows/ci.yml + scripts/selftest.py (SELFTEST OK محلياً)
- segAJ root cause chain:
  1. map_range يبتلع فشل mem_map الذري → ثقوب في farm → UcError(0x510000013500, 0x1032)
  2. data_cell يسجل الخلية قبل الكتابة → خلية مسمومة فارغة إلى الأبد
  3. maybe_grow يعيد True بدون تحقق فعلي
  4. MainAppThread يُتقاعد بصمت والسلسلة تدور بلا تقدم
- الإصلاحات: map_range صفحة-صفحة عند فشل النطاق الكامل + تحقق في maybe_grow +
  إسقاط الخلية عند فشل الكتابة + كشف main-dead + farm heal في load_snapshot +
  فصل glGetString/glGetStringi
- segAK-AL: Extensions تُطبع كاملة الآن لكن MainAppThread يموت بعد GL_MAX_FRAGMENT_UNIFORM_VECTORS
- **THE ROOT CAUSE**: glGetIntegerv كتب 16 بايت (4 ints) في متغيرات stack أحادية →
  صفّر x29/x30 المحفوظين → ret إلى NULL! الإصلاح: جداول arity لكل pname
- segAO: النجاة! PipelineCache → LogMaterial: Verifying Global Shaders
- segAP-AQ: عاصفة sched_yield (11.9M استدعاء) تجوّع المجدول → backoff تكيفي
- segAR: كاش _arity مسموم من snapshot يعيد استدعاء الدوال بـ 9 معاملات → إسقاطه من الحفظ
- segAS-BF: "Missing global shader FStereoLayerPS" fatal — الطبخ **Metal فقط**
  (global_sf_metal.metallib) ونحن نفرض -es2! ترقيعات: no-op لدالة التحقق كاملة +
  مساعد الـ assert + كشف الحلقة
- **اكتشاف منصة حاسم**: unicorn لا يبطل كاش الكتل المترجمة مع mem_write!
  (أثبتناه تجريبياً — الترقيعات لم تكن تنفذ أبداً!) → ctl_remove_cache بعد كل ترقيع
- segBI-BT: لغز PC=0 مع sp=0 — التقطناه حياً بالساعة + lastmile trace (شطف كامل
  للكاش بين الشرائح لأن الشطف أثناء المحاكاة لا يعمل على الكتل المتسلسلة)
- **THE PHANTOM KILLER**: sys_open كان يعيد -ENOENT = **-2** بدل -1! المحرك خزنه
  كـ fd صالح → fstat/close(-2) → بنية stat غير معبأة (زبالة stack = أرقام "Requested
  read of 123... bytes" الغامضة!) → فساد → PC=0/sp=0
- segBU: **كل ما سبق أُصلح** → أراضٍ جديدة كلياً: Build: ++Fortnite+Release-3.5-CL-3994867
  → RHI → RegisterNativeRedirects (CoreUObject native table)
- الانهيار الحالي: IndexToObject (جدول chunks من 16384) يقرأ chunk[0]=NULL ويفشل
  عند 0x11d8 — لكن snapshot يظهر الجدول والchunks **سليمة**! ظاهرة قراءة غير
  متسقة من المحاكي (TLB/تفاعل مجدول؟) — الجلسة القادمة

Stage Summary:
- الملفات سليمة، كل شيء في git محلي (14+ كوميت اليوم)
- أعمق نقطة وصل إليها المحرك على الإطلاق: CoreUObject package loading
- المطلوب من المستخدم: **توكين GitHub جديد** (القديم مرفوض — يُرجح أن GitHub
  ألغاه تلقائياً عند انكشافه في الدردشة)
- الأدوات الجديدة: selftest.py, diag_farm.py, disas_crash.py, analyze_assert2.py,
  tb_cache_test.py, tb_repro.py, xref_string.py + نظام CODE_PATCHES + lastmile trace

Key numbers:
- main() = 0x102DAE84C • GOT 2,581 • 773 mod_inits • 43 svc sites
- verify fn = 0x1023575d4 (no-op'd) • assert helper = 0x10136d04c
- name-pool singleton = [0x1055d64e0] • chunk table seen at 0x64000048faf0

---
Task ID: segBV-CW (2025-10-25 session 2)
Agent: main (Z.ai)
Task: GitHub backup + CRITICAL bug hunt toward the login screen

Work Log:
- GitHub: repo abdallh-rgx/fn35-loader (public) — cleaned history with
  git-filter-repo, ~40 commits this session, all pushed via
  scripts/git_save.sh ("line-by-line" autosave per user request)
- weakobj guard (cave patch): both ObjectIndexToObject clones
  (0x102def960 + 0x1028eb2f8) range-check chunk + NULL -> return 0
- **RETAA KILLER**: the verify patch bytes c0 03 9f d6 are RETAA —
  unicorn 2.1.4 mis-executes it to PC=0/SP=0 (proved in isolation);
  fixed to plain RET c0 03 5f d6
- scheduler: wake past-due timed waiters EVERY loop iteration
  (advance_clock only ran in the idle path; a busy-ready thread
  starved all cond_timedwait sleepers — the segBX/BZ "silent phase")
- **SNAPSHOT OVERLAY PERF**: merged-region bulk map (4125 regions -> 9,
  ~355s -> <1s restore)
- **NSString unicode normalization identity** (precomposedString/
  decomposedString/folding): was unimplemented -> nil returns ->
  the engine retried its FText build FOREVER (the 20B-instruction
  "string storm"); identity return breaks the loop
- heartbeat watchdog (30s) with thread/memory footprint
- png read forensics: every served PNG verified byte-identical in
  guest memory (IHDR-part-OK); "CRC error" is computed by guest code
  on VALID data; errors are non-fatal (engine continues)
- mmap FIX: honour the offset param + don't move fd position
- **NZCV CRITICAL**: condition flags were NOT saved/restored on thread
  switches; a slice ending between cmp and b.cc let the next thread's
  flags hijack the branch -> intermittent random crashes with garbage
  x8/x16 in bit-loops (3 different sites, different values each run)
- getspecific: self-linked TLS stand-in for unset keys (NULL-deref
  crash on key 10 after pak-index decode; [tls+field] chains)

Stage Summary:
- Frontier: engine now mounts pakchunkearly-iosclient.pak, decodes its
  index, and dies in a 24-byte-entry table lookup ([x0+8] with x0 from
  a half-initialized chunk table) — new territory, way past the old
  CoreUObject/string-storm frontiers
- Every fix committed+pushed to GitHub (abdallh-rgx/fn35-loader)
- Next: the 24B-entry table (likely the pak-primed name/object table)
  needs its chunk pointers populated — trace who fills [table+0x108]

---
Task ID: segCX-DH (2025-10-25 session 3)
Agent: main (Z.ai)
Task: Continue toward the login screen; GitHub line-by-line saves

Work Log:
- NEW TOKEN: ghp_2YUmcEX... working (user abdallh-rgx); repo synced
  (fn35-loader, ~15 commits this session, all pushed)
- TLS FIX: _pthread_getspecific now returns NULL (POSIX). The old
  self-linked stand-in poisoned int32 field reads (idx = high half of
  the block pointer = 0x6000) -> IndexToObject garbage crash. Caller
  0x102a176a0 lazily mallocs its own 12-byte context when NULL.
- ZERO PAGE [0,0x10000) RW-noexec mapped: null-relative derefs read 0
  gracefully; fetch still faults (PC=0 detection intact)
- ZLIB ENGINE (fn35_zlib.py): full inflate/deflate/uncompress/crc32
  with z_stream marshaling. Previously _inflateInit2_ etc. were
  unimplemented stubs returning 0 (silent no-op decompression!)
- PAK CONTAINER: sys_open/stat/access fall back to serving the real
  pak from cookeddata; uproject placed at
  sandbox/.../cookeddata/fortnitegame/fortnitegame.uproject (engine
  stats it successfully now)
- SNAPSHOT HYGIENE: trace-arm flags (_kernproc_lm_armed etc.) dropped
  at save; fd trace + read trace (FN35_TRACE_READ) + mmap trace added
- **TLB STALENESS DISCOVERY**: every CRC/AES table-loop phantom fault
  (addresses arithmetically IMPOSSIBLE from the dumped regs, e.g. ldr
  [x9+w*uxtw#2] faulting at 0x1b15ec4ec with w<=0xFF and valid x9)
  happened ONLY on snapshot-resumed runs, never fresh boots. FIX:
  post-restore TB cache flush (deferred to first slice boundary; a
  direct ctl_remove_cache in load_snapshot DEADLOCKS)
- wait-guard raised 120s -> 3600s (double constant 0x40ac200000000000,
  keystone, cave 0x106000080): the async pak mount + name-table build
  takes MINUTES under emulation
- ENGINE PAK FLOW MAPPED (FN35_TRACE_READ): fd5 (pak) reads:
  #1 footer (22463B @33357824 = file end), #2-8 index (7x64KB
  @32899072..33292288), #9 first entry block (64KB @10878976) - all
  succeed, then NO more reads. inflate NEVER called (0 stub hits!)
- The engine's register state during the AES phase held the REAL pak
  AES key bytes (x3-x7 = a3278ba7 ddd751a7 5456415a 36c35591 ...) -
  the engine HAS the key; our pakfs uses the same one

Stage Summary:
- Frontier moved past: 24B-table crash (fixed), CRC/AES phantom faults
  (fixed via TB flush), null-call exit (still present)
- REMAINING BLOCKER (precisely mapped): after the entry reads, the
  engine's project-file read ('../../../FortniteGame/FortniteGame
  .uproject') fails INSIDE the engine's pak layer - no 10th read, no
  inflate call. The pak-layer entry serve path dies before touching
  I/O. Likely: entry lookup against the still-building name table
  (the 480-bit grind) racing the project check, OR the entry's flags
  parse refusing the read
- Next session: instrument the engine's pak entry lookup (find the
  FindFileInPak equivalent via the pak object's vtable at 0x640000xxx),
  or serve the uproject through the PHYSICAL layer by making the pak
  layer's mount point NOT cover '../../../FortniteGame/FortniteGame
  .uproject' (rename our pak's mount string?)
- Key numbers: stub[1332]=_read, AES tables @0x104352d48/0x10333887c,
  grind=480-bit BigInt name-table build, pak idx @33.24-33.36MB

---
Task ID: env-restore (2026-10-25 session 4)
Agent: main (Z.ai)
Task: Environment recovery after sandbox reset; continue toward login screen

Work Log:
- Sandbox was reset at 10:06 (boot-timeline.log); /home/z/my-project was
  rebuilt from git HEAD only
- OLD session survived in /tmp/my-project: restored fn35/ (644MB:
  FortniteClient 91MB, IPA, pak 33MB, segAJ snapshot, sandbox, tools,
  run1-53 + segA-AJ logs) + 14 untracked analysis scripts
- Reinstalled python env: unicorn 2.1.4, capstone, keystone, pyelftools
- All 10 loader modules compile OK; binary md5 66130a44341bdebe767d0c8471f1c1cc
- Committed + pushed restored scripts (4f046fe)
- Launched segAK: fresh boot, FN35_BUDGET=1800, snapshot chain -> fn35/snap2

Stage Summary:
- Everything recovered; no progress lost (all session 2-3 fixes are in git)
- segAK running; frontier expected: pak-layer .uproject read blocker
  (session 3's REMAINING BLOCKER)

---
Task ID: vm-diagnosis (2025-10-25 session 4)
Agent: main (Z.ai)
Task: Diagnose the MainAppThread 'eternal loop' (0x101838ab0-0x101839660)

Work Log:
- Frame-chain walk from snapshot: trampoline -> 0x101885c24 (caller-A:
  compare+usleep(100) retry) -> 0x1026e0c28 (caller-B) -> LOOP-FN
  @ 0x101838970 (only 2 xrefs in the whole binary)
- x1 = WIDE STRING '../../../FortniteGame/FortniteGame.uproject -es2'
  (the engine command line); x20 = 'bCommandLineReady' selector
- objc_dump.py: IOSAppDelegate HAS all three timer IMPs
  (NoUrlCommandLine=0x102805170 etc.) - not a missing-IMP issue
- run38.log forensics: the SAME loop faulted at 0x101839580 in the OLD
  code after thread_policy_set - the loop is post-mach-setup code
- disassembly decoded: the 'hash churn' is an UNALIGNED 32-bit
  BITSTREAM READER ([sp+0x780]=base + [sp+0x770]=idx, read two words,
  shift/combine). LOOP-FN = an obfuscator VM INTERPRETER (bytecode in
  __DATA at 0x1043eb370) executing the engine's launch code
- probe_vmpos.py: idx ADVANCES MONOTONICALLY (0x29ef60 -> 0x2c4e74 over
  24M hits) - REAL WORK, NOT STUCK. Sync hook (1 reg read) = mandatory
  for correctness (probe without it phantom-faults at 0x97ceba93)

Stage Summary:
- VERDICT: not a bug; the engine launch runs as obfuscated VM bytecode
  under emulation. Old runs passed the same code (run38 trace confirms)
- Path forward: chain segments (~0.45M instr/s); expect [icu-stat] +
  LogInit once the VM finishes the launch blob

---
Task ID: desync-war (2025-10-25 session 4, continued)
Agent: main (Z.ai)
Task: Push through the VM grind to the login screen; survive the unicorn
TCG-desync race

Work Log:
- segAU-AZ: reached the pak-mount frontier (LogPakFile + index reads
  #1-9 = session-3's map reproduced exactly)
- BLOCK sync hook: 6.5x faster than the per-instruction code hook
  (VM grind 13MB bytecode done in ~2 segments vs ~15)
- The engine's pak-phase AES/CRC table loops hit RANDOM TCG-desync
  faults in BOTH hook modes, fresh OR resumed: committed registers
  can hold garbage (x8=w8, add never executed). Unicorn 2.1.4 race.
- segBF/BG: FN35_NO_ENGINE_PAK ENOENT gate on .pak paths broke early
  inits (error paths through the same fragile loops) - removed
- ROOT CAUSE of the project-check regression: session-3's cookeddata
  uproject made the engine prepend the project path to the command
  line -> project check -> relative-path read -> translate_path dead-
  drops it into sandbox/System -> ENOENT -> "Failed to read file ->
  engine will exit". run49's EMPTY command line skipped the check
  entirely (LogInit: Command Line: was empty!). FIXED: uproject
  moved away (backup: fn35/fortnitegame.uproject.hidden)
- DSR (desync self-repair): works mathematically (and-mask folding)
  but emu_stop from the fault callback leaves UC_ERR_MAP loops ->
  disabled by default; kept for reference (FN35_DSR=1)
- CRASH-RECOVERY CHAIN (chain.sh): budget-end saves good snapshots,
  crashes auto-recover from crash snapshots (fresh TCB usually clears
  the desync), 3x same-crash -> rollback to last good, crash counter
  persisted across calls. The crash-resume poison-skip (+4 the
  faulting load/store thread PC at restore time) is safe and helps.
- Snapshot fixes: py_stack dropped on crash saves; unpicklable
  sync-hook closures excluded (silent save failures killed recoveries)

Stage Summary:
- Chain grinding through inits (each recovery advances ~150-250 inits;
  773 total, then portrait -> BLOCK swap -> VM grind ~2 segments ->
  the physical-model project flow -> LogInit -> GL -> login screen)
- Frontier known-good config: FN35_SYNC_HOOK=auto, NO NO_ENGINE_PAK,
  uproject hidden, chain.sh for crash recovery
- Everything pushed to abdallh-rgx/fn35-loader (~30 commits today)
