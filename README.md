This tool is an advanced APK analysis toolkit designed to provide in‑depth, professional static analysis of Android APK files. It integrates multiple analysis techniques and external decompilation tools into a unified dashboard with a modern user interface. Here’s an overview of its key features:

Comprehensive APK Analysis:
• Uses Androguard to parse APK files, extract metadata, permissions, activities, certificates, and more.
• Provides detailed app overview, including basic information and permission summaries.

Advanced Decompilation:
• Leverages external decompilers like JADX as the primary tool and falls back to dex2jar with jd-cli if needed.
• Recursively searches decompiled outputs to reliably locate source code files (even for tricky classes like BuildConfig).

Multi-Tab Dashboard:
• Overview: Summarizes app details, permissions, and a purpose analysis.
• Manifest: Displays the Android manifest in a navigable tree view.
• API Calls: Lists API calls used in the app with the ability to filter and view detailed method information.
• DEX & Native: Shows all DEX files and native libraries bundled in the APK.
• Security: Provides security-related details such as debuggable status, network security configuration, and obfuscation indicators.
• Certificates: Lists certificate details from the APK for authenticity and integrity checks.
• Source Code: Allows you to browse decompiled source code, with reliable file lookup for each class/method.
• Recon: Extracts and displays additional information like emails, URLs, and potential secrets from the APK.
• Components: Lists app components (activities, services, providers, libraries, and files) with detailed info on each.
• Advanced Analysis: Generates an organized, detailed HTML report that combines outputs from external tools (like apkid and apktool) and static analysis of both the manifest and decompiled sources.

Enhanced Static Analysis:
• Scans for suspicious patterns (e.g., reflective calls, dynamic method invocations, runtime executions) to flag potentially malicious behavior.
• Compares requested permissions against a comprehensive list of known sensitive or dangerous permissions.

Professional Reporting:
• Consolidates data from multiple sources into a clear, advanced HTML report.
• Ensures that the analysis results are accurate, structured, and free of dummy or junk outputs.
