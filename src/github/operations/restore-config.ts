import { execFileSync } from "child_process";
import { cpSync, existsSync, rmSync } from "fs";

// Paths that are both PR-controllable and read from cwd at CLI startup.
//
// Deliberately excluded from the CLI's broader auto-edit blocklist:
//   .git/        — not tracked by git; PR commits cannot place files there.
//                  Restoring it would also undo the PR checkout entirely.
//   .gitconfig   — git reads ~/.gitconfig and .git/config, never cwd/.gitconfig.
//   .bashrc etc. — shells source these from $HOME; checkout cannot reach $HOME.
//   .vscode/.idea— IDE config; nothing in the CLI's startup path reads them.
const SENSITIVE_PATHS = [
  ".claude",
  ".mcp.json",
  ".claude.json",
  ".gitmodules",
  ".ripgreprc",
  "CLAUDE.md",
  "CLAUDE.local.md",
  ".husky",
];

/**
 * Restores security-sensitive config paths from the PR base branch.
 *
 * The CLI's non-interactive mode trusts cwd: it reads `.mcp.json`,
 * `.claude/settings.json`, and `.claude/settings.local.json` from the working
 * directory and acts on them before any tool-permission gating — executing
 * hooks (including SessionStart), setting env vars (NODE_OPTIONS, LD_PRELOAD,
 * PATH), running apiKeyHelper/awsAuthRefresh shell commands, and auto-approving
 * MCP servers. When this action checks out a PR head, all of these are
 * attacker-controlled.
 *
 * Rather than enumerate every dangerous key, this replaces the entire `.claude/`
 * tree and `.mcp.json` with the versions from the PR base branch, which a
 * maintainer has reviewed and merged. Paths absent on base are deleted.
 *
 * Known limitation: if a PR legitimately modifies `.claude/` and the CLI later
 * commits with `git add -A`, the revert will be included in that commit. This
 * is a narrow UX tradeoff for closing the RCE surface.
 *
 * @param baseBranch - PR base branch name. Must be pre-validated (branch.ts
 *   calls validateBranchName on it before returning).
 */
export function restoreConfigFromBase(baseBranch: string): void {
  console.log(
    `Restoring ${SENSITIVE_PATHS.join(", ")} from origin/${baseBranch} (PR head is untrusted)`,
  );

  // Snapshot every PR-authored sensitive path into .claude-pr/ before deletion
  // so review agents can inspect what the PR changes without those files ever
  // being executed. Captured before the security delete so it reflects the
  // PR-authored version.
  rmSync(".claude-pr", { recursive: true, force: true });
  for (const p of SENSITIVE_PATHS) {
    if (existsSync(p)) {
      cpSync(p, `.claude-pr/${p}`, { recursive: true });
    }
  }
  if (existsSync(".claude-pr")) {
    console.log(
      "Preserved PR's sensitive paths → .claude-pr/ for review agents (not executed)",
    );
  }

  // Delete PR-controlled versions BEFORE fetching so the attacker-controlled
  // .gitmodules is absent during the network operation. If git reads .gitmodules
  // during fetch (fetch.recurseSubmodules=on-demand, the git default), it will
  // attempt to fetch submodule objects and block on credential prompts in CI —
  // causing an indefinite hang. Deleting first closes that window.
  //
  // If the restore below fails for a given path, that path stays deleted —
  // the safe fallback (no attacker-controlled config). A bare `git checkout`
  // alone wouldn't remove files the PR added, so nuke first.
  console.log(`[restore-config] Deleting PR-controlled sensitive paths...`);
  for (const p of SENSITIVE_PATHS) {
    rmSync(p, { recursive: true, force: true });
  }
  console.log(`[restore-config] Sensitive paths deleted.`);

  // Dump git auth state for debugging fetch hangs on self-hosted runners.
  try {
    const remoteUrl = execFileSync("git", ["remote", "get-url", "origin"], {
      stdio: "pipe",
      timeout: 5_000,
    })
      .toString()
      .trim();
    console.log(`[restore-config] remote origin URL: ${remoteUrl}`);
  } catch {
    console.log(`[restore-config] remote origin URL: (failed to read)`);
  }
  try {
    const gitConfig = execFileSync(
      "git",
      ["config", "--list", "--show-origin"],
      { stdio: "pipe", timeout: 5_000 },
    )
      .toString()
      .split("\n")
      .filter(
        (line) =>
          /credential|helper|extraheader|askpass|url\./i.test(line),
      )
      .join("\n");
    console.log(
      `[restore-config] auth-related git config:\n${gitConfig || "(none)"}`,
    );
  } catch {
    console.log(`[restore-config] auth-related git config: (failed to read)`);
  }
  console.log(
    `[restore-config] GIT_ASKPASS=${process.env.GIT_ASKPASS || "(unset)"}`,
  );
  console.log(
    `[restore-config] GH_TOKEN=${process.env.GH_TOKEN ? "(set, length=" + process.env.GH_TOKEN.length + ")" : "(unset)"}`,
  );
  console.log(
    `[restore-config] GITHUB_TOKEN=${process.env.GITHUB_TOKEN ? "(set, length=" + process.env.GITHUB_TOKEN.length + ")" : "(unset)"}`,
  );

  // --no-recurse-submodules: explicitly suppress submodule fetching regardless of
  // fetch.recurseSubmodules config. Defense-in-depth alongside the delete above.
  const fetchArgs = [
    "fetch",
    "origin",
    baseBranch,
    "--depth=1",
    "--no-recurse-submodules",
  ];
  console.log(
    `[restore-config] Running: git ${fetchArgs.join(" ")} (timeout: 60s)`,
  );
  const fetchStart = Date.now();
  try {
    execFileSync("git", fetchArgs, {
      stdio: "inherit",
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: "0",
        GIT_LFS_SKIP_SMUDGE: "1",
      },
      timeout: 60_000,
    });
    console.log(
      `[restore-config] git fetch completed in ${Date.now() - fetchStart}ms`,
    );
  } catch (error) {
    const elapsed = Date.now() - fetchStart;
    console.error(
      `[restore-config] git fetch FAILED after ${elapsed}ms: ${error instanceof Error ? error.message : String(error)}`,
    );
    throw error;
  }

  console.log(
    `[restore-config] Checking out sensitive paths from origin/${baseBranch}...`,
  );
  for (const p of SENSITIVE_PATHS) {
    try {
      execFileSync("git", ["checkout", `origin/${baseBranch}`, "--", p], {
        stdio: "pipe",
        timeout: 10_000,
      });
      console.log(`[restore-config]   ✓ ${p}`);
    } catch {
      // Path doesn't exist on base — it stays deleted.
      console.log(`[restore-config]   - ${p} (not on base, stays deleted)`);
    }
  }

  // `git checkout <ref> -- <path>` stages the restored files. Unstage so the
  // revert doesn't silently leak into commits the CLI makes later.
  console.log(`[restore-config] Unstaging restored files...`);
  try {
    execFileSync("git", ["reset", "--", ...SENSITIVE_PATHS], {
      stdio: "pipe",
      timeout: 10_000,
    });
  } catch {
    // Nothing was staged, or paths don't exist on HEAD — either is fine.
  }
  console.log(`[restore-config] Restore complete.`);
}
