#!/usr/bin/env python3
"""
Debug script to check what files were generated
"""

import os
import json

print("🔍 Checking output directories...\n")

# Check output directory
output_dir = 'output'
if not os.path.exists(output_dir):
    print(f"❌ Output directory '{output_dir}' not found!")
    exit(1)

# List all subdirectories
subdirs = [d for d in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, d))]

if not subdirs:
    print("❌ No job directories found in output/")
    exit(1)

print(f"✅ Found {len(subdirs)} job directories\n")

# Check each one
for subdir in sorted(subdirs, reverse=True)[:3]:  # Last 3 jobs
    job_path = os.path.join(output_dir, subdir)
    print(f"📁 Job: {subdir}")
    print(f"   Path: {job_path}")

    # List all files
    for root, dirs, files in os.walk(job_path):
        level = root.replace(job_path, '').count(os.sep)
        indent = ' ' * 4 * (level + 1)
        print(f'{indent}📂 {os.path.basename(root)}/')
        subindent = ' ' * 4 * (level + 2)
        for file in files:
            file_path = os.path.join(root, file)
            size = os.path.getsize(file_path)
            print(f'{subindent}📄 {file} ({size} bytes)')

    print()

print("\n💡 To fix the issue:")
print("1. Check if report.html exists in the job directory")
print("2. Verify the job_id in the URL matches the directory name")
print("3. Make sure symbolic_hunter_complete.py saved all files correctly")
