#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dashboardRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(dashboardRoot, "..");
const binderDir = path.join(repoRoot, "docs", "_binder");
const outFile = path.join(dashboardRoot, "src", "generated", "docs-bundle.json");

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function readYaml(filePath) {
  const raw = await fs.readFile(filePath, "utf-8");
  const data = yaml.load(raw);
  if (!data || typeof data !== "object") {
    throw new Error(`Invalid YAML mapping: ${filePath}`);
  }
  return data;
}

async function main() {
  const navPath = path.join(binderDir, "nav.yaml");
  const classificationPath = path.join(binderDir, "classification.yaml");
  const migrationPath = path.join(binderDir, "migration-map.yaml");

  const binderAvailable =
    (await exists(navPath)) &&
    (await exists(classificationPath)) &&
    (await exists(migrationPath));

  if (!binderAvailable) {
    if (await exists(outFile)) {
      console.log(
        "Docs binder metadata is unavailable in this build context; using existing generated bundle.",
      );
      return;
    }
    throw new Error(
      "Cannot build docs bundle: docs/_binder files are missing and no generated bundle exists.",
    );
  }

  const nav = await readYaml(navPath);
  const classification = await readYaml(classificationPath);
  const migration = await readYaml(migrationPath);

  const contents = {};
  const sections = Array.isArray(nav.sections) ? nav.sections : [];

  for (const section of sections) {
    const pages = Array.isArray(section?.pages) ? section.pages : [];
    for (const page of pages) {
      const pagePath = page?.path;
      if (!pagePath || typeof pagePath !== "string") {
        continue;
      }
      const absPath = path.join(repoRoot, pagePath);
      if (!(await exists(absPath))) {
        throw new Error(`Referenced docs file missing: ${pagePath}`);
      }
      contents[pagePath] = await fs.readFile(absPath, "utf-8");
    }
  }

  const bundle = {
    version: 1,
    nav,
    classification,
    migration,
    contents,
  };

  await fs.mkdir(path.dirname(outFile), { recursive: true });
  await fs.writeFile(outFile, JSON.stringify(bundle, null, 2) + "\n", "utf-8");
  console.log(`Wrote docs bundle: ${path.relative(repoRoot, outFile)} (${Object.keys(contents).length} pages)`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

