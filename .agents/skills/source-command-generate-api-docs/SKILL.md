---
name: "source-command-generate-api-docs"
description: "Create comprehensive API documentation from source code"
---

# source-command-generate-api-docs

Use this skill when the user asks to run the migrated source command `generate-api-docs`.

## Command Template

# API Documentation Generator

Generate API documentation by:

1. Scanning all files in `/src/api/`
2. Extracting function signatures and JSDoc comments
3. Organizing by endpoint/module
4. Creating markdown with examples
5. Including request/response schemas
6. Adding error documentation

Output format:
- Markdown file in `/docs/api.md`
- Include curl examples for all endpoints
- Add TypeScript types

---
**Last Updated**: April 9, 2026
