import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
const r = await build({ entryPoints: ['src/app.js'], bundle: true, minify: true, format: 'iife', write: false, target: 'es2022' });
const js = r.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
mkdirSync('dist', { recursive: true });
writeFileSync('dist/index.html', readFileSync('index.template.html', 'utf8').replace('/*BUNDLE*/', () => js));
console.log('dist/index.html', (js.length / 1024).toFixed(0) + ' KB script');
