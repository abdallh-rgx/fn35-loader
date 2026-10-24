# FN3.5 iOS Loader — Worklog

---
Task ID: 1
Agent: main (Z.ai)
Task: تشغيل Fortnite 3.5 iOS على Linux x64 عبر Unicorn حتى شاشة تسجيل الدخول

Work Log:
- الجلسة 1-2: تنزيل IPA (Google Drive gdown)، فك الضغط، تحليل Mach-O ARM64 (91.2MB، cryptid=0)
- بناء 8 سكربتات في scripts/: fn35_macho, fn35_clib, fn35_gles, fn35_ioslib, fn35_objc, fn35_pakfs, fn35_native, fn35_loader (المتكامل، 100KB)
- 50 تشغيلة (run1-run50): تقدم من crash مبكر → 773/773 mod_init → main() → UE LogInit → Device Profile [IPhone8] CVars
- run50 (budget=600s): توقف بمهلة زمنية فقط، fatal=None — المحرك يعمل
- الجلسة 3 (الحالية): البيئة أُعيدت تهيئتها جزئياً (unicorn/capstone/keystone حُذفت) → أعدت تثبيتها (unicorn 2.1.4, capstone 5.0.9, keystone 0.9.2)
- أطلقت run52 (budget=3600s) بـ setsid nohup PID 1246 لتكون محصّنة

Stage Summary:
- الملفات كلها سليمة (المستخدم سأل إذا فُقدت — الجواب: لا)
- run52 جارية الآن: FN35_BUDGET=3600 nohup python scripts/fn35_loader.py > fn35/run52.log
- نقاط مفتاحية: main()=0x102dae84c, pakfs 3260 entries, 595 ObjC classes, 84 GL imports → Mesa/llvmpipe
- بعد Device Profiles يأتي: FConfigCacheIni → GEngine init → RHI(-es2 GLES) → Slate → login screen
- مشاكل معروفة من run50: 15k threads (timerForSplashScreen 10k / RecordPeakMemory 5k) — churn لكنه غير قاتل

Key numbers:
- main() = 0x102DAE84C • GOT 2,581 • 773 mod_inits • 43 svc sites
- run50: MainAppThread 1.74e12 instr في 600s (~6.5 G instr/s إجمالي)
- top calls: mach_absolute_time 754k, pthread_mutex_lock 690k, objc_msgSend 350k
