// 用户原始需求（2026-08-14）：rootless supervisor 用户必须拥有与其他宿主用户不冲突的 subordinate IDs。
// 正交意图：解析系统范围；识别既有分配；寻找空闲区间；拒绝耗尽。
export interface SubordinateIdRange {
	readonly owner: string;
	readonly start: number;
	readonly count: number;
}

export function parseSubordinateIdRanges(source: string): readonly SubordinateIdRange[] {
	return source.split(/\r?\n/).flatMap((line) => {
		const [owner, rawStart, rawCount, extra] = line.split(":");
		const start = Number(rawStart);
		const count = Number(rawCount);
		if (!owner || extra !== undefined || !Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(count) || count < 1) return [];
		return [{ owner, start, count }];
	});
}

export function findAvailableSubordinateIdStart(ranges: readonly SubordinateIdRange[], count: number, minimum = 100_000, maximum = 2_000_000_000): number {
	if (!Number.isSafeInteger(count) || count < 1) throw new Error("subordinate ID range size must be a positive integer");
	let candidate = minimum;
	for (;;) {
		const conflict = ranges.find((range) => candidate < range.start + range.count && candidate + count > range.start);
		if (!conflict) return candidate;
		candidate = conflict.start + conflict.count;
		if (!Number.isSafeInteger(candidate + count - 1) || candidate + count - 1 > maximum) throw new Error("no subordinate ID range is available");
	}
}
