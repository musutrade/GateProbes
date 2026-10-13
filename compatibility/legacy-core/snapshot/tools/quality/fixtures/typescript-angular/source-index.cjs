// Parser-only identity inventory. Run with the locked fixture dependencies.
const ts = require('./app/node_modules/typescript');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = process.argv[2];
if (!root || ts.version !== '6.0.2') throw new Error('Expected source root and TypeScript 6.0.2');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const files = {};
for (const relative of fs.readdirSync(path.join(root, 'src'), { recursive: true }).sort()) {
  if (!relative.endsWith('.ts') || relative.endsWith('.spec.ts')) continue;
  const name = 'src/' + relative;
  const bytes = fs.readFileSync(path.join(root, name));
  const source = ts.createSourceFile(name, bytes.toString('utf8'), ts.ScriptTarget.Latest, true);
  if (source.parseDiagnostics.length) throw new Error('Invalid TypeScript: ' + name);
  const point = pos => { const p = source.getLineAndCharacterOfPosition(pos); return {line:p.line+1, column:p.character}; };
  const functions = [];
  let template = false;
  function visit(node, owners = []) {
    if (ts.isPropertyAssignment(node) && ['template', 'templateUrl'].includes(node.name.getText(source))) template = true;
    const owner = (ts.isClassDeclaration(node) || ts.isModuleDeclaration(node)) && node.name ? [...owners, node.name.getText(source)] : owners;
    if ((ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && node.body) {
      const start = point(node.getStart(source)), end = point(node.end);
      const label = node.name ? node.name.getText(source) : ts.SyntaxKind[node.kind];
      functions.push({kind:ts.isMethodDeclaration(node)?'method/v1':'function/v1',
        name:[...owners,label].join('.'), start, end,
        declaration:point(node.name ? node.name.getStart(source) : node.getStart(source)),
        body:point(node.body.getStart(source))});
    }
    ts.forEachChild(node, child => visit(child, owner));
  }
  visit(source);
  files[name] = {sha256:sha(bytes), template, generated:name.includes('/generated/'), functions};
}
process.stdout.write(JSON.stringify({schema:'typescript-source-index/v1', compiler:ts.version, files}, null, 2)+'\n');
