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
