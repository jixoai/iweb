<!--
原始需求（2026-08-24）：为 iweb 的 01-organic-core 白底少色图标寻找开源的“选中 -> 路径 -> 填色”工作流。
正交意图：给出当前图标的工具选择；给出可复现的 GUI/CLI 路径；记录自动矢量化边界与第一方依据。
-->

# iweb 图标开源矢量化

目标图为 [01-organic-core](../../.agents/images/2026-08-24-iweb-icon-candidates-organic/01-organic-core.png)：`1024 x 1024`、纯白背景、少色扁平图形。它适合颜色追踪，不需要先做通用主体分割。

## 结论

首选 **Inkscape**。它的 `Path > Trace Bitmap` 会把位图转成可编辑路径；`Multiple scans > Colors` 会逐色创建对象。对这张图先以 `4--6` 色追踪，删除白底对象，解组后用节点工具修正轮廓与层级，最后用 `Fill and Stroke` 重新定色。这一步直接得到可维护 SVG，最快接近 Photoshop 的“选中 -> 路径 -> 填色”。

自动结果只是初稿：Inkscape 官方明确说明追踪并不保证 100% 忠实，保留颜色时每种颜色会成为单独对象；其旧版官方教程也建议在追踪后用 `Path > Simplify` 降低节点数。因此，保留原图作底图比盲目加大色数更可靠。

```text
01-organic-core.png
        |
Inkscape: Trace Bitmap / Multiple scans / Colors (4--6)
        |
删除白底 -> Ungroup -> Node tool 修轮廓 -> Fill and Stroke 定色
        |
iweb-logo.svg
```

### 最快 GUI 流程

1. 在 Inkscape 导入原图，选中它，执行 `Path > Trace Bitmap`（快捷键 `Shift+Alt+B`）。
2. 选择 `Multiple scans > Colors`，从 `4` 色开始；预览后逐步增加到轮廓不丢失但未出现大量小碎片的最低色数，点击 `Apply`。
3. 将追踪结果移开与原图对照，删除面积最大的纯白对象，`Object > Ungroup`。
4. 只对明显锯齿或冗余的形状使用 `Path > Simplify`；再以节点工具手工修正关键曲线、前后遮挡和小缺口。
5. 逐对象在 `Fill and Stroke` 设定最终品牌色，保存为 plain SVG。

## 工具取舍

| 工具 | 对此图的适配 | 用途与限制 |
| --- | --- | --- |
| **Inkscape Trace Bitmap** | **最高** | 有颜色追踪和后续 SVG 编辑，正好覆盖路径与填色。自动追踪会生成多个逐色对象，需人工清理。 |
| **VTracer** | 高，适合批量/CLI | 原生输出 SVG，支持固定调色板、色数上限、曲线简化和 `cutout` 无缝区域。它是自动追踪器，不能让人逐区域交互选择。 |
| **GIMP** | 中，最像所述手工动作 | Fuzzy Select 可选连续相近颜色；`Select > To Path` 能把选区转路径。适合手动补一个难追踪区域，但它是位图编辑器，最终 SVG 整理仍建议交给 Inkscape。 |
| **Krita** | 低，限手动选区 | 连续选区工具可按相近颜色选取并调 fuzziness；适合绘制/修补，不是本图的高效 SVG 输出链。 |
| **Potrace** | 低，仅单色组件 | 输入是黑白位图，输出可为 SVG；可以作为某个单色剪影的底层追踪器，不能一次保留本图的多色分区。 |

## CLI 备选：VTracer

适合一次性得到可在 Inkscape 清理的初稿。其维护者的 README 说明 `vtracer-cli` 可由 Cargo 安装，`--max-colors` 用于量化颜色，`--hierarchical cutout` 生成无缝拼接区域，`--simplify` 控制曲线节点量。

```sh
cargo install vtracer-cli
vtracer \
  .agents/images/2026-08-24-iweb-icon-candidates-organic/01-organic-core.png \
  /tmp/iweb-logo-draft.svg \
  --preset poster \
  --max-colors 5 \
  --hierarchical cutout \
  --simplify 1.2 \
  --optimize 2
```

随后在 Inkscape 打开 `/tmp/iweb-logo-draft.svg`，移除白底区域、校正色板和关键曲线。色板已确定时，用 `--palette '#RRGGBB,#RRGGBB,...'` 锁定输出色，避免 JPEG 压缩产生近似色。

> 本机当前安装的 `vtracer 0.6.5` CLI 只接受 `--input`、`--output` 和
> `--preset`，不接受上述细调参数；生成初稿时使用
> `vtracer --input source.jpg --output draft.svg --preset poster`。升级到支持
> README 所列参数的版本后，才可使用色板与色数控制。

## 能力边界

没有一个成熟开源桌面工具能完整等价 Photoshop 的 AI「智能选中」：后者依赖语义主体理解；上述开源工具提供的是颜色/连通域选择或像素边界追踪。对这张白底、少色、轮廓清晰的图，这不是实质缺口；若后续图标包含渐变、纹理、投影或需要判断“哪个视觉对象属于主体”，应回到人工路径编辑，或使用专门的 AI 分割模型后再追踪。

## 第一方资料

- [Inkscape: Tracing an Image](https://inkscape-manuals.readthedocs.io/en/latest/tracing-an-image.html) — Trace Bitmap、单/多扫描、颜色对象及不保证完全忠实的限制。
- [Inkscape: Tracing Bitmaps](https://inkscape.org/doc/tutorials/tracing/tutorial-tracing.html) — Trace Bitmap 入口、颜色量化、Simplify 的节点取舍。
- [VTracer README](https://github.com/visioncortex/vtracer#readme) — CLI 安装、固定色板、色数限制、无缝 cutout 与曲线简化。
- [GIMP 3: Fuzzy Selection](https://docs.gimp.org/3.0/en/gimp-tool-fuzzy-select.html) 与 [Paths Dialog](https://docs.gimp.org/3.0/en/gimp-path-dialog.html#selection-to-path) — 连续相近色选择与选区转路径。
- [Krita: Contiguous Selection Tool](https://docs.krita.org/en/reference_manual/tools/contiguous_select.html) — 相近色连续选区与 fuzziness。
- [Potrace 手册](https://potrace.sourceforge.net/potrace.html) — 黑白位图输入和 SVG 输出的边界。
