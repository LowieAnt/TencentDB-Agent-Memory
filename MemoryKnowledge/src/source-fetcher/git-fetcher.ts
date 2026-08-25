/**
 * GitSourceFetcher — 基于 simple-git 的源码拉取实现。
 *
 * simple-git 内部用 child_process.spawn + args 数组，不走 shell，从原理上消除 shell 注入。
 *
 * 安全防护（002 §4-5）：
 *   - R1 git hooks：clone/fetch 本就不拉取远端 .git/hooks（hooks 为本地态），故不额外
 *     配置 core.hooksPath（加固版 git 会拒绝该配置，需 allowUnsafeHooksPath）。
 *   - R2 SSRF：只允许 public HTTPS + 内网/环回地址黑名单（对齐项目 security_rules）。
 *   - Bug 修复（方案 A）：增量 sync 的 git clean 排除 .codegraph/，避免删掉 codegraph 索引库。
 */

import simpleGit, { CleanOptions, ResetMode } from "simple-git";
import type { ISourceFetcher, FetchResult, SourceType } from "./types.js";

/**
 * 内网 / 环回 / link-local 地址黑名单（标准网段）：
 *   - 10. / 172.16-31. / 192.168.  → RFC1918 私有网段
 *   - 169.254.                     → link-local（含云元数据 169.254.169.254）
 *   - 127. / 0. / localhost / ::1  → 环回
 *   - fe80:                        → IPv6 link-local
 *
 * 该黑名单可通过环境变量 KNOWLEDGE_SSRF_CHECK=off 关闭（见 GitSourceFetcher 构造）。
 */
const PRIVATE_ADDR_RE =
  /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|127\.|0\.|localhost$|::1$|fe80:)/i;

/**
 * 读取 SSRF 私网黑名单开关。默认开启；
 * 当 KNOWLEDGE_SSRF_CHECK 为 off/false/0/no（大小写不敏感）时关闭。
 */
function ssrfCheckEnabledFromEnv(): boolean {
  const raw = process.env.KNOWLEDGE_SSRF_CHECK;
  if (raw == null || raw.trim() === "") return true;
  const v = raw.trim().toLowerCase();
  return !(v === "off" || v === "false" || v === "0" || v === "no");
}

export interface GitSourceFetcherOptions {
  /**
   * 是否启用 SSRF 私网 / 环回地址黑名单校验。
   * 默认读环境变量 KNOWLEDGE_SSRF_CHECK（默认开启）；显式传入时优先于环境变量。
   */
  ssrfCheck?: boolean;
}

export class GitSourceFetcher implements ISourceFetcher {
  readonly supportedType: SourceType = "git";

  /** SSRF 私网黑名单校验开关（https-only 协议校验始终生效，不受此开关影响）。 */
  private readonly ssrfCheck: boolean;

  constructor(opts?: GitSourceFetcherOptions) {
    this.ssrfCheck = opts?.ssrfCheck ?? ssrfCheckEnabledFromEnv();
  }

  validate(sourceUrl: string): void {
    // 仅支持 HTTPS 仓库（公开或私有，私有仓库鉴权见 fetch/sync 的 credential 参数）；SSH 暂不支持。
    if (!sourceUrl.startsWith("https://")) {
      throw new Error("only HTTPS repos are supported; SSH is not supported");
    }
    const host = this.extractHost(sourceUrl);
    if (!host) {
      throw new Error(`invalid repo_url: cannot parse host from ${sourceUrl}`);
    }
    // R2: SSRF 防护 —— 禁止指向内网 / 环回地址（可经 KNOWLEDGE_SSRF_CHECK=off 关闭）。
    if (this.ssrfCheck && this.isPrivateAddress(host)) {
      throw new Error(`repo_url must not point to private/loopback address: ${host}`);
    }
  }

  async fetch(sourceUrl: string, branch: string, localPath: string, credential?: string): Promise<FetchResult> {
    this.validate(sourceUrl);
    const authedUrl = this.withCredential(sourceUrl, credential);
    try {
      // 浅克隆单分支。注：git clone/fetch 不会拉取远端的 .git/hooks（hooks 是本地态），
      // 所以正常仓库 clone 出来不带可执行钩子；此处不再配置 core.hooksPath
      // （加固版 git 会拒绝该配置：需 allowUnsafeHooksPath）。
      await simpleGit().clone(authedUrl, localPath, {
        "--depth": 1,
        "--branch": branch,
      });
    } catch (err) {
      throw this.redact(err, credential);
    } finally {
      // clone 会把 authedUrl（含凭据）原样写入 <localPath>/.git/config —— 无论成败，
      // 只要目录已生成就立刻把 origin 改回明文 URL，避免凭据落盘常驻。
      if (credential) await this.stripCredentialFromRemote(localPath, sourceUrl);
    }
    const version = await this.headCommit(localPath);
    return { localPath, version, sourceType: "git" };
  }

  async sync(sourceUrl: string, branch: string, localPath: string, credential?: string): Promise<FetchResult> {
    this.validate(sourceUrl);
    const authedUrl = this.withCredential(sourceUrl, credential);
    try {
      const git = simpleGit(localPath);
      // 私有仓库：先把 origin 指向带凭据的 URL 再 fetch，避免依赖已落盘的旧 remote。
      await git.remote(["set-url", "origin", authedUrl]);
      await git.fetch("origin", branch, { "--depth": 1 });
      await git.reset(ResetMode.HARD, [`origin/${branch}`]);
      // Bug 修复（方案 A）：clean 排除 .codegraph/，否则会删掉 codegraph 的索引库，
      // 导致增量 sync 永远失败、每次回退到全量 clone。
      await git.clean(CleanOptions.FORCE + CleanOptions.RECURSIVE, ["-e", ".codegraph"]);
      const version = await this.headCommit(localPath);
      return { localPath, version, sourceType: "git" };
    } catch (err) {
      throw this.redact(err, credential);
    } finally {
      // 同上：fetch 结束后立刻把 origin 改回明文 URL，避免凭据在 .git/config 落盘常驻。
      if (credential) await this.stripCredentialFromRemote(localPath, sourceUrl);
    }
  }

  /** 把 <localPath>/.git 里的 origin 改回不含凭据的明文 URL（幂等，失败静默忽略）。 */
  private async stripCredentialFromRemote(localPath: string, plainSourceUrl: string): Promise<void> {
    try {
      await simpleGit(localPath).remote(["set-url", "origin", plainSourceUrl]);
    } catch {
      // 目录可能还不存在（clone 在写入前就失败）——无残留凭据可清，忽略。
    }
  }

  // ── 内部 helper ──

  /** 在 URL 中注入凭据作为 username（PAT-over-HTTPS，Azure DevOps/GitHub/GitLab 通用）。 */
  private withCredential(sourceUrl: string, credential?: string): string {
    if (!credential) return sourceUrl;
    const url = new URL(sourceUrl);
    url.username = encodeURIComponent(credential);
    return url.toString();
  }

  /**
   * 凭据落库前的最后防线：git/simple-git 报错信息常回显完整远端 URL，
   * 若其中含凭据明文，会经 sync_error 一路透传回前端 —— 抛出前替换为 ***。
   */
  private redact(err: unknown, credential?: string): Error {
    const msg = err instanceof Error ? err.message : String(err);
    const safe = credential ? msg.split(credential).join("***").split(encodeURIComponent(credential)).join("***") : msg;
    return new Error(safe);
  }

  private async headCommit(localPath: string): Promise<string | null> {
    try {
      return (await simpleGit(localPath).revparse(["HEAD"])).trim().slice(0, 12);
    } catch {
      return null;
    }
  }

  private extractHost(url: string): string {
    try {
      return new URL(url).hostname;
    } catch {
      return "";
    }
  }

  private isPrivateAddress(host: string): boolean {
    return PRIVATE_ADDR_RE.test(host);
  }
}
