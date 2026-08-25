/**
 * SourceFetcher 接口层 — 协议无关的源码拉取与安全校验抽象。
 *
 * 职责：把"从某个 source（git/local/ftp）拉取代码到本地目录"抽象成统一接口，
 * 安全校验（协议白名单 + SSRF 防护）集中在各实现的 validate() 里。
 * 具体实现（如 GitSourceFetcher）依赖 simple-git，但该依赖不泄漏到本接口层。
 */

export type SourceType = "git" | "local" | "ftp";

export interface FetchResult {
  /** 源码落盘的本地目录（绝对路径）。 */
  localPath: string;
  /** 当前版本标识（git 为 commit hash 前 12 位；取不到为 null）。 */
  version: string | null;
  /** 源协议类型。 */
  sourceType: SourceType;
}

/**
 * 源码拉取器接口。实现者负责：
 *   1. 校验 sourceUrl 安全性（协议白名单、SSRF 等）
 *   2. 拉取/同步源码到 localPath
 *   3. 返回版本标识
 *
 * 实现：
 *   - GitSourceFetcher：simple-git，支持 HTTPS 公开与私有仓库（credential 参数传 PAT）；SSH 暂不支持
 *   - LocalSourceFetcher / FtpSourceFetcher：未来扩展
 */
export interface ISourceFetcher {
  /**
   * 首次拉取：把源码下载到 localPath。
   * @param credential 私有仓库凭据（明文 PAT，已由调用方解密）；公开仓库不传。
   */
  fetch(sourceUrl: string, branch: string, localPath: string, credential?: string): Promise<FetchResult>;

  /**
   * 增量同步：更新已存在的 localPath 到最新版本。
   * @param credential 私有仓库凭据（明文 PAT，已由调用方解密）；公开仓库不传。
   */
  sync(sourceUrl: string, branch: string, localPath: string, credential?: string): Promise<FetchResult>;

  /** 校验 sourceUrl 是否合法（协议白名单 + SSRF 防护）。非法则 throw。 */
  validate(sourceUrl: string): void;

  /** 支持的协议类型。 */
  readonly supportedType: SourceType;
}
