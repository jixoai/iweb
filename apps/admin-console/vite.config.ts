import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
import tailwindcss from '@tailwindcss/vite';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';

export default defineConfig({
	plugins: [
		tailwindcss(),
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) => filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({
				pages: "build",
				assets: "build",
				strict: true
			})
		})
	],
	test: {
		expect: { requireAssertions: true },
		projects: [
			{
				extends: './vite.config.ts',
				test: {
					name: 'server',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			},
			{
				// Real DOM component tests (10.4): mount Svelte components into
				// happy-dom and assert the rendered table, not source strings.
				// The kit plugin compiles .svelte for the client, so the exact
				// "svelte" specifier is pinned to the client entry for mount().
				extends: './vite.config.ts',
				resolve: {
					alias: [{ find: /^svelte$/, replacement: resolve('./node_modules/svelte/src/index-client.js') }]
				},
				test: {
					name: 'components',
					environment: 'happy-dom',
					include: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			}
		]
	}
});
