// 用户原始需求（2026-08-13）：文件树使用 shadcn-svelte-extras Tree View。
// 正交意图：导出 extras 的 Tree View 组合；保持项目路径别名；不添加项目业务逻辑。
import TreeView from "./tree-view.svelte";
import TreeViewFile from "./tree-view-file.svelte";
import TreeViewFolder from "./tree-view-folder.svelte";

export {
	TreeView,
	TreeViewFile,
	TreeViewFolder,
	TreeView as Root,
	TreeViewFile as File,
	TreeViewFolder as Folder
};
