// 用户原始需求（2026-08-13）：工作区专注于文件树与文件详情。
// 正交意图：把扁平对象列表投影为稳定树节点；区分目录与文件；不保留展开状态或编辑行为。
import type { WorkspaceFile } from "$lib/iweb/contracts";

export type FileTreeNode = {
	name: string;
	path: string;
	children: FileTreeNode[];
	file: WorkspaceFile | null;
};

type MutableTreeNode = Omit<FileTreeNode, "children"> & { children: Map<string, MutableTreeNode> };

function node(name: string, path: string): MutableTreeNode {
	return { name, path, children: new Map(), file: null };
}

export function workspaceTree(files: WorkspaceFile[]): FileTreeNode[] {
	const root = node("/", "");
	for (const file of files) {
		const segments = file.path.split("/");
		let current = root;
		for (const [index, segment] of segments.entries()) {
			const path = [...segments.slice(0, index), segment].join("/");
			const child = current.children.get(segment) ?? node(segment, path);
			current.children.set(segment, child);
			current = child;
		}
		current.file = file;
	}

	function toNodes(parent: MutableTreeNode): FileTreeNode[] {
		return [...parent.children.values()]
			.sort((left, right) => {
			const leftDirectory = left.children.size > 0;
			const rightDirectory = right.children.size > 0;
			if (leftDirectory !== rightDirectory) return leftDirectory ? -1 : 1;
			return left.name.localeCompare(right.name);
			})
			.map((child) => ({ name: child.name, path: child.path, children: toNodes(child), file: child.file }));
	}
	return toNodes(root);
}
