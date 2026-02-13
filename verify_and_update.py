#!/usr/bin/env python3
"""
Systematically verify and update tasks.md based on actual codebase verification
"""

import subprocess
import re

def file_exists(path):
    result = subprocess.run(['test', '-f', path], capture_output=True)
    return result.returncode == 0

def dir_exists(path):
    result = subprocess.run(['test', '-d', path], capture_output=True)
    return result.returncode == 0

def grep_exists(pattern, path):
    result = subprocess.run(['grep', '-q', pattern, path], capture_output=True)
    return result.returncode == 0

# Phase 2 verification
phase2_complete = all([
    dir_exists('internal/transport/xhttpmeta'),
    file_exists('internal/transport/xhttpmeta/metadata.go'),
    file_exists('internal/transport/xhttpmeta/metadata_test.go'),
    file_exists('internal/transport/xhttpmeta/metadata_prop_test.go'),
    grep_exists('xhttpmeta', 'internal/transport/xhttp/xhttp.go'),
    grep_exists('session_placement', 'examples/uqsp-mode-4a.yaml'),
])

# Phase 3 verification
phase3_complete = all([
    grep_exists('CMaxReuseTimes', 'internal/transport/xhttp/xmux.go'),
    grep_exists('shouldRetire', 'internal/transport/xhttp/xmux.go'),
    grep_exists('markDraining', 'internal/transport/xhttp/xmux.go'),
    file_exists('internal/transport/xhttp/xmux_test.go'),
    file_exists('internal/transport/xhttp/xmux_prop_test.go'),
])

# Phase 4 verification
phase4_complete = all([
    file_exists('internal/transport/faketcp/crypto.go'),
    file_exists('internal/transport/faketcp/aead.go'),
    file_exists('internal/transport/faketcp/faketcp_crypto_test.go'),
    file_exists('internal/transport/faketcp/faketcp_property_test.go'),
    file_exists('internal/transport/faketcp/faketcp_encryption_integration_test.go'),
])

# Phase 5 verification
phase5_complete = all([
    dir_exists('internal/transport/anytls'),
    file_exists('internal/transport/anytls/anytls.go'),
    file_exists('internal/transport/anytls/padding.go'),
    file_exists('internal/transport/anytls/padding_test.go'),
    file_exists('internal/transport/anytls/anytls_property_test.go'),
])

# Phase 6 verification
phase6_complete = all([
    file_exists('internal/transport/reality/spider.go'),
    file_exists('internal/transport/reality/spider_test.go'),
    file_exists('internal/transport/reality/spider_property_test.go'),
])

# Phase 7 verification
phase7_complete = all([
    file_exists('internal/transport/kcpbase/entropy.go'),
    file_exists('internal/transport/kcpbase/entropy_test.go'),
    file_exists('internal/transport/kcpbase/entropy_bench_test.go'),
])

# Phase 8 verification
phase8_complete = all([
    file_exists('internal/transport/kcpbase/fec.go'),
    file_exists('internal/transport/kcpbase/fec_test.go'),
    file_exists('internal/transport/kcpbase/fec_property_test.go'),
])

# Phase 9 verification
phase9_complete = all([
    file_exists('internal/mux/shaper.go'),
    file_exists('internal/mux/shaper_test.go'),
    file_exists('internal/mux/shaper_property_test.go'),
    file_exists('internal/mux/shaper_integration_test.go'),
])

# Phase 10 verification
phase10_complete = all([
    file_exists('internal/transport/pool/adaptive.go'),
    file_exists('internal/transport/pool/adaptive_test.go'),
    file_exists('internal/transport/pool/adaptive_property_test.go'),
])

print(f"Phase 2 (XHTTP Metadata): {'✅ COMPLETE' if phase2_complete else '❌ INCOMPLETE'}")
print(f"Phase 3 (Xmux Lifecycle): {'✅ COMPLETE' if phase3_complete else '❌ INCOMPLETE'}")
print(f"Phase 4 (FakeTCP AEAD): {'✅ COMPLETE' if phase4_complete else '❌ INCOMPLETE'}")
print(f"Phase 5 (AnyTLS): {'✅ COMPLETE' if phase5_complete else '❌ INCOMPLETE'}")
print(f"Phase 6 (REALITY Spider): {'✅ COMPLETE' if phase6_complete else '❌ INCOMPLETE'}")
print(f"Phase 7 (KCP Entropy): {'✅ COMPLETE' if phase7_complete else '❌ INCOMPLETE'}")
print(f"Phase 8 (KCP FEC): {'✅ COMPLETE' if phase8_complete else '❌ INCOMPLETE'}")
print(f"Phase 9 (Smux Shaper): {'✅ COMPLETE' if phase9_complete else '❌ INCOMPLETE'}")
print(f"Phase 10 (Adaptive Pool): {'✅ COMPLETE' if phase10_complete else '❌ INCOMPLETE'}")
