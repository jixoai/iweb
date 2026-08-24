// hello 静态站：独立脚本文件（验证 celld 多文件直出）。
const clock = document.getElementById("clock");
const render = () => { clock.textContent = `本文件由浏览器单独加载：${new Date().toLocaleString("zh-CN")}`; };
render();
setInterval(render, 1000);
