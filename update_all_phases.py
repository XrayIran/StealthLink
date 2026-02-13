#!/usr/bin/env python3
import re

# Read the tasks file
with open('/home/iman/.kiro/specs/upstream-integration-completion/tasks.md', 'r') as f:
    content = f.read()

# Phase 5-10 are all complete based on verification
# Update phase headers
content = re.sub(
    r'## Phase 5: AnyTLS Protocol \(High Priority\) - Mode 4c/4e TLS Fingerprint Resistance$',
    r'## Phase 5: AnyTLS Protocol (High Priority) - Mode 4c/4e TLS Fingerprint Resistance ✅ COMPLETE',
    content, flags=re.MULTILINE
)
content = re.sub(
    r'## Phase 6: REALITY Spider Enhancement \(Medium Priority\) - Mode 4c Connection Speed$',
    r'## Phase 6: REALITY Spider Enhancement (Medium Priority) - Mode 4c Connection Speed ✅ COMPLETE',
    content, flags=re.MULTILINE
)
content = re.sub(
    r'## Phase 7: KCP Hardware Entropy \(Medium Priority\) - Mode 4d Performance$',
    r'## Phase 7: KCP Hardware Entropy (Medium Priority) - Mode 4d Performance ✅ COMPLETE',
    content, flags=re.MULTILINE
)
content = re.sub(
    r'## Phase 8: KCP FEC Enhancements \(Medium Priority\) - Mode 4d Reliability$',
    r'## Phase 8: KCP FEC Enhancements (Medium Priority) - Mode 4d Reliability ✅ COMPLETE',
    content, flags=re.MULTILINE
)
content = re.sub(
    r'## Phase 9: Smux Priority Shaper \(Medium Priority\) - All Modes Mux Performance$',
    r'## Phase 9: Smux Priority Shaper (Medium Priority) - All Modes Mux Performance ✅ COMPLETE',
    content, flags=re.MULTILINE
)
content = re.sub(
    r'## Phase 10: Adaptive Connection Pool \(Medium Priority\) - All Modes Pool Management$',
    r'## Phase 10: Adaptive Connection Pool (Medium Priority) - All Modes Pool Management ✅ COMPLETE',
    content, flags=re.MULTILINE
)

# Update all checkboxes for phases 5-10
# Phase 5
for task_num in ['5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8']:
    content = re.sub(rf'- \[ \] {re.escape(task_num)} ', f'- [x] {task_num} ', content)
    content = re.sub(rf'- \[ \]\* {re.escape(task_num)} ', f'- [x]* {task_num} ', content)
    # Sub-tasks
    for letter in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']:
        content = re.sub(rf'- \[ \] {re.escape(task_num)}{letter} ', f'- [x] {task_num}{letter} ', content)

# Phase 6
for task_num in ['6.1', '6.2', '6.3', '6.4', '6.5']:
    content = re.sub(rf'- \[ \] {re.escape(task_num)} ', f'- [x] {task_num} ', content)
    content = re.sub(rf'- \[ \]\* {re.escape(task_num)} ', f'- [x]* {task_num} ', content)
    for letter in ['a', 'b', 'c', 'd', 'e', 'f', 'g']:
        content = re.sub(rf'- \[ \] {re.escape(task_num)}{letter} ', f'- [x] {task_num}{letter} ', content)

# Phase 7
for task_num in ['7.1', '7.2', '7.3', '7.4', '7.5']:
    content = re.sub(rf'- \[ \] {re.escape(task_num)} ', f'- [x] {task_num} ', content)
    content = re.sub(rf'- \[ \]\* {re.escape(task_num)} ', f'- [x]* {task_num} ', content)
    for letter in ['a', 'b', 'c', 'd', 'e', 'f', 'g']:
        content = re.sub(rf'- \[ \] {re.escape(task_num)}{letter} ', f'- [x] {task_num}{letter} ', content)

# Phase 8
for task_num in ['8.1', '8.2', '8.3', '8.4', '8.5', '8.6', '8.7']:
    content = re.sub(rf'- \[ \] {re.escape(task_num)} ', f'- [x] {task_num} ', content)
    content = re.sub(rf'- \[ \]\* {re.escape(task_num)} ', f'- [x]* {task_num} ', content)
    for letter in ['a', 'b', 'c', 'd', 'e', 'f', 'g']:
        content = re.sub(rf'- \[ \] {re.escape(task_num)}{letter} ', f'- [x] {task_num}{letter} ', content)

# Phase 9
for task_num in ['9.1', '9.2', '9.3', '9.4', '9.5', '9.6']:
    content = re.sub(rf'- \[ \] {re.escape(task_num)} ', f'- [x] {task_num} ', content)
    content = re.sub(rf'- \[ \]\* {re.escape(task_num)} ', f'- [x]* {task_num} ', content)
    for letter in ['a', 'b', 'c', 'd', 'e', 'f']:
        content = re.sub(rf'- \[ \] {re.escape(task_num)}{letter} ', f'- [x] {task_num}{letter} ', content)

# Phase 10
for task_num in ['10.1', '10.2', '10.3', '10.4', '10.5', '10.6']:
    content = re.sub(rf'- \[ \] {re.escape(task_num)} ', f'- [x] {task_num} ', content)
    content = re.sub(rf'- \[ \]\* {re.escape(task_num)} ', f'- [x]* {task_num} ', content)
    for letter in ['a', 'b', 'c', 'd', 'e', 'f']:
        content = re.sub(rf'- \[ \] {re.escape(task_num)}{letter} ', f'- [x] {task_num}{letter} ', content)

# Write back
with open('/home/iman/.kiro/specs/upstream-integration-completion/tasks.md', 'w') as f:
    f.write(content)

print("All phases 5-10 marked as complete")
