// 用户原始需求（2026-08-13）：Admin 以管理员登录表达 bootstrap owner key，而非要求用户配置 API。
// 正交意图：会话内保存管理员密钥；创建 Kernel 客户端；支持登录和退出；绝不写入静态资产或 localStorage。
import { apiOriginFromAdminOrigin, KernelApiClient } from "$lib/iweb/api";

const ADMIN_SESSION_STORAGE_KEY = "iweb-admin-owner-key";

export class ApiSession {
	ownerKey = $state("");
	origin = $state("");

	get authenticated(): boolean {
		return this.ownerKey.trim().length > 0;
	}

	initialize(): void {
		this.origin = apiOriginFromAdminOrigin(new URL(window.location.href));
		this.ownerKey = window.sessionStorage.getItem(ADMIN_SESSION_STORAGE_KEY) ?? "";
	}

	login(ownerKey: string): void {
		this.ownerKey = ownerKey.trim();
		if (this.ownerKey) window.sessionStorage.setItem(ADMIN_SESSION_STORAGE_KEY, this.ownerKey);
	}

	logout(): void {
		this.ownerKey = "";
		window.sessionStorage.removeItem(ADMIN_SESSION_STORAGE_KEY);
	}

	client(): KernelApiClient {
		return new KernelApiClient(this.origin, () => this.ownerKey);
	}
}
