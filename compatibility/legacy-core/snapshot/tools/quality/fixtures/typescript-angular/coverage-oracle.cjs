// Independent native Istanbul counter oracle for file and AST-local scopes.
const fs = require('node:fs');
const coverage = require('./app/node_modules/istanbul-lib-coverage');
const index = JSON.parse(fs.readFileSync(process.argv[2]));
const raw = JSON.parse(fs.readFileSync(process.argv[3]));
const prefix = process.argv[4].replace(/\/$/, '') + '/';
const output = {};
const compare = (a,b) => a.line - b.line || a.column - b.column;
for (const [absolute, data] of Object.entries(raw)) {
  if (!absolute.startsWith(prefix)) throw new Error('Unbound absolute source path');
  const name = absolute.slice(prefix.length), info = index.files[name];
  if (info.template || info.generated || !info.functions.length) continue;
  const scopes = [{name:'file', coverage:data}];
  for (const fn of info.functions) {
    const copy = structuredClone(data);
    for (const [key, loc] of Object.entries(data.statementMap)) {
      const owners = info.functions.filter(f => compare(f.body,loc.start)<=0 && compare(loc.start,f.end)<0);
      owners.sort((a,b)=>compare(b.start,a.start));
      if (owners[0] !== fn) { delete copy.statementMap[key]; delete copy.s[key]; }
    }
    for (const [key, native] of Object.entries(data.fnMap)) {
      if (compare(native.decl.start,fn.declaration)!==0) {delete copy.fnMap[key]; delete copy.f[key];}
    }
    scopes.push({name:fn.name+'@'+fn.start.line+':'+fn.start.column,coverage:copy});
  }
  output[name] = scopes.map(scope => {
    const summary = coverage.createFileCoverage(scope.coverage).toSummary().data;
    return {scope:scope.name, lines:{covered:summary.lines.covered,total:summary.lines.total},
      functions:{covered:summary.functions.covered,total:summary.functions.total}};
  });
}
process.stdout.write(JSON.stringify({provider:'istanbul-lib-coverage@'+require('./app/node_modules/istanbul-lib-coverage/package.json').version,files:output},null,2)+'\n');
