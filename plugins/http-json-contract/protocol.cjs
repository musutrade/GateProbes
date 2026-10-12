'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {canonical,measure,consumerInventory,generate}=require('./measure.cjs'),parse=require('./strict-json.cjs');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const COLLECTOR={name:'http-json-contract',version:'0.1.0-rc.5'};
const TYPES={'contract.breaking_changes':'count','contract.client_drift':'boolean','contract.compatible':'boolean'};
function file(root,name) {
 assert(typeof name==='string'&&name&&!path.isAbsolute(name)&&!name.includes('\\')&&!name.split('/').some(p=>['','.','..'].includes(p)),'unsafe input path');
 let p=root;for(const part of name.split('/')) {p=path.join(p,part);assert(!fs.lstatSync(p).isSymbolicLink(),'symlink input');}
 assert(fs.statSync(p).isFile());return fs.readFileSync(p);
}
function discover(request) {
 const p=request.parameters;
 const inputs=p.receipt?.consumer_sources || {[p.client]:null};
 const sources=Object.fromEntries(Object.keys(inputs).map(name=>[name,file(request.workspace_root,name).toString()]));
 const consumers=[...new Set(require('./clients.cjs').inventory(sources).map(call=>call.file))].sort();
 assert(consumers.includes(p.client),'missing expected production HTTP consumer');
 const subjects=[[request.component,p.boundary,p.contract],...consumers.map(name=>[p.consumer,p.consumer_boundary,name])].map(([component,boundary,name])=>{
  const value={identity_version:'subject-identity/v1',component,target:request.context.target,boundary,kind:component===request.component?'contract/v1':'file/v1',path:name,discriminator:'http-json-operation-set/v1',source_sha256:sha(file(request.workspace_root,name))};
  return {id:'subject-identity/v1:'+sha(canonical({project:request.project,...value})),...value,metadata:{}};
 });
 return {subjects};
}
function series(request) {
 const implementation=Object.fromEntries(['measure.cjs','schema.cjs','clients.cjs','legacy-measure.cjs','protocol.cjs','project.cjs','cli.cjs','strict-json.cjs','npm-shrinkwrap.json'].map(p=>[p,sha(fs.readFileSync(path.join(__dirname,p)))]));
 const value={name:'http-json-contract',collector:COLLECTOR,tool:{name:'typescript-ast-http-observations',version:require('typescript/package.json').version},rule:{name:'closed-json-business-contract/v2',version:sha(canonical(implementation))},runtime:{name:'node',version:process.versions.node},target:request.context.target,source_identity:{name:'http-json-operation-set/v1',version:'1'},normalization:{name:'strict-existing-operation-compatibility',version:'1'},metrics:Object.entries(TYPES).map(([name,type])=>({name,type}))};
 return {id:'measurement-series/v1:'+sha(canonical(value)),...value};
}
function collect(request) {
 assert.equal(request.schema,'harness-collector-request/v1');assert.equal(canonical(request.collector),canonical(COLLECTOR));
 assert.deepEqual([...request.requested_capabilities].sort(),Object.keys(TYPES).sort());
 const p=request.parameters,root=request.workspace_root,receipt=p.receipt;
 assert.equal(fs.realpathSync(root),root);assert.equal(receipt.schema,'http-json-capture/v1');assert.deepEqual(receipt.context,request.context);
 assert.equal(canonical(discover(request).subjects),canonical(p.subjects),'contract subject drift');
 assert(receipt.inputs[p.contract]&&receipt.inputs[p.client]&&receipt.inputs[p.type_file],'incomplete capture source binding');
 for(const [name,digest] of Object.entries(receipt.inputs)) assert.equal(sha(file(root,name)),digest,'capture source changed');
 const sourceFiles={};
 function walk(directory) {
  for(const entry of fs.readdirSync(path.join(root,directory),{withFileTypes:true})) {
   const name=directory+'/'+entry.name;assert(!entry.isSymbolicLink(),'symlink consumer inventory');
   if(entry.isDirectory()) walk(name);
   else if(name.endsWith('.ts')&&!name.endsWith('.d.ts')&&!p.exclude.includes(name)) sourceFiles[name]=file(root,name).toString();
  }
 }
 assert(p.consumer_source_root&&!path.isAbsolute(p.consumer_source_root)&&!p.consumer_source_root.includes('\\')&&!p.consumer_source_root.split('/').some(part=>['','.','..'].includes(part)),'unsafe consumer root');
 let directory=root;for(const part of p.consumer_source_root.split('/')) {directory=path.join(directory,part);assert(!fs.lstatSync(directory).isSymbolicLink(),'symlink consumer root');}
 assert(Array.isArray(p.exclude)&&new Set(p.exclude).size===p.exclude.length);
 for(const name of p.exclude) {assert(name.startsWith(p.consumer_source_root+'/'),'excluded source outside boundary');file(root,name);}
 walk(p.consumer_source_root);
 assert.deepEqual(Object.keys(sourceFiles).sort(),Object.keys(receipt.consumer_sources).sort(),'incomplete consumer inventory');
 for(const [name,text] of Object.entries(sourceFiles)) assert.equal(sha(text),receipt.consumer_sources[name],'consumer source changed');
 consumerInventory(sourceFiles,p.client,parse(file(root,p.contract).toString()));
 const base=fs.readFileSync(receipt.baseline.path);
 assert.equal(sha(base),receipt.baseline.sha256,'trusted baseline changed');
 const observations=file(root,p.observations);assert.equal(sha(observations),receipt.observations_sha256,'HTTP observations changed');
 const head=file(root,p.contract),type=file(root,p.type_file),client=file(root,p.client);
 const values=measure(parse(base.toString()),parse(head.toString()),type.toString(),client.toString(),p.type_name,parse(observations.toString()),sourceFiles);
 const stamps=[...type.toString().matchAll(/^\/\/ harness-contract-sha256: ([a-f0-9]{64})$/gm)];assert.equal(stamps.length,1,'missing/ambiguous generated contract stamp');
 const origin=stamps[0][1];assert([sha(base),sha(head)].includes(origin),'unrecognized generated-client origin');
 const originSpec=parse((origin===sha(head)?head:base).toString());
 const expectedGenerated=generate(originSpec,p.type_name,origin);
 const clients=require('./clients.cjs');
 clients.checkTypes(type.toString(),expectedGenerated,[...new Set(clients.inventory(sourceFiles).map(call=>call.typeName))]);
 values['contract.client_drift'].value ||= origin!==sha(head);
 values['contract.compatible'].value &&= origin===sha(head);
 const generated=Buffer.from(generate(parse(head.toString()),p.type_name,sha(head)));
 const output=request.output_root,prefix=p.artifact_subdir;
 assert.equal(fs.realpathSync(output),output);assert(/^[a-z][a-z0-9-]*$/.test(prefix));
 const target=path.join(output,prefix);assert(!fs.existsSync(target),'artifact directory must be fresh');
 fs.mkdirSync(target,{mode:0o700});
 const evidence=[],allArtifacts=[];
 for(const owner of p.subjects) {
 const source={path:owner.path,sha256:owner.source_sha256},artifacts=[];
 const tag=owner.id.split(':')[1];
 for(const [name,bytes] of [['head.json',head],['baseline.json',base],['observations.json',observations],['receipt.json',Buffer.from(canonical(receipt))],['response.ts',type],['client.ts',owner.component===p.consumer?file(root,owner.path):client],['consumer-sources.json',Buffer.from(canonical(sourceFiles))],['expected-generated.ts',generated]]) {
  fs.writeFileSync(path.join(target,tag+'-'+name),bytes,{flag:'wx',mode:0o600});
  artifacts.push({id:'http-contract-'+tag+'-'+name.replace('.','-'),kind:'raw',media_type:name.endsWith('.json')?'application/json':'text/plain',path:prefix+'/'+tag+'-'+name,sha256:sha(bytes),bytes:bytes.length,context:request.context,source});
 }
 const refs=artifacts.map(a=>a.id),identity=series(request);
 const record={schema:'harness-evidence/v1',id:'http-contract-'+owner.id.split(':')[1],project:request.project,component:owner.component,collector:COLLECTOR,series:identity,subject:owner,source,context:request.context,
 metrics:Object.entries(values).map(([name,value])=>({name,value,artifacts:refs})),capabilities:Object.keys(TYPES).map(metric=>({metric,state:'supported',reason:'complete declared JSON operation response variants and consumer AST',artifacts:refs})),artifacts,status:'measured',
 contract:{relationship:p.relationship,producer:request.component,consumer:p.consumer,contract_artifact:artifacts[0].id,baseline:{artifact:artifacts[1].id,commit:receipt.baseline.commit,series_id:identity.id},consumer_artifact:artifacts[5].id,generated_client:{artifact:artifacts[4].id,contract_sha256:origin}}};
 evidence.push(record);allArtifacts.push(...artifacts);
 }
 return {schema:'harness-collector-response/v1',evidence,artifacts:allArtifacts,error:null};
}
module.exports={canonical,sha,COLLECTOR,TYPES,discover,series,collect};
