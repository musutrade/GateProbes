#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),parse=require('./strict-json.cjs'),p=require('./protocol.cjs');
try {
 const args=process.argv.slice(2);
 if(args[0]==='generate') { const bytes=fs.readFileSync(args[1]);fs.writeFileSync(args[3],require('./measure.cjs').generate(parse(bytes.toString()),args[2],p.sha(bytes))); }
 else if(args[0]==='--version') console.log('harness-gate-http-contract-collector '+p.COLLECTOR.version);
 else if(args[0]==='project') console.log(p.canonical(require('./project.cjs')(parse(fs.readFileSync(0,'utf8')),args)));
 else {
  const request=parse(fs.readFileSync(args[1],'utf8'));
  console.log(p.canonical(args[0]==='discover'?{...p.discover(request),series:p.series(request)}:p.collect(request)));
 }
} catch(error) { console.error(error.message);process.exitCode=1; }
