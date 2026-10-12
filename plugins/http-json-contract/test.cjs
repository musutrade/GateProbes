'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {measure,operations,consumer}=require('./measure.cjs');
function fixture() {
 const responses={};for(const [status,word] of [[200,'ok'],[503,'unavailable']]) responses[status]={description:word,content:{'application/json':{schema:{type:'object',additionalProperties:false,required:['status','database'],properties:Object.fromEntries(['status','database'].map(k=>[k,{type:'string',enum:[word]}]))}}}};
 const spec={openapi:'3.0.3',info:{title:'Fixture',version:'1'},paths:{'/api/health':{get:{operationId:'health',responses}}}};
 return {spec,type:"export interface HealthResponse { status: 'ok' | 'unavailable'; database: 'ok' | 'unavailable'; }",client:"import {httpResource} from '@angular/common/http'; const value=httpResource<HealthResponse>(()=>'/api/health');",observations:[{method:'GET',path:'/api/health',status:200,content_type:'application/json',body:{status:'ok',database:'ok'}},{method:'GET',path:'/api/health',status:503,content_type:'application/json',body:{status:'unavailable',database:'unavailable'}}]};
}
function run(f,base=f.spec) {return measure(base,f.spec,f.type,f.client,'HealthResponse',f.observations);}
test('matching provider variants, consumer AST and baseline produce facts',()=>{const values=run(fixture());assert.equal(values['contract.compatible'].value,true);assert.equal(values['contract.client_drift'].value,false);assert.equal(values['contract.breaking_changes'].value,0);});
test('existing operation changes are conservatively incompatible',()=>{const f=fixture(),base=structuredClone(f.spec);base.paths['/api/health'].get.operationId='previous';assert.equal(run(f,base)['contract.breaking_changes'].value,1);});
test('consumer field and route changes are drift',()=>{const f=fixture();f.type=f.type.replace('database:','db:');assert.equal(run(f)['contract.client_drift'].value,true);f.client=f.client.replace('/api/health','/wrong');assert.equal(run(f)['contract.compatible'].value,false);});
test('provider field/value drift and missing variants fail closed',()=>{for(const change of [f=>f.observations.pop(),f=>delete f.observations[0].body.database,f=>f.observations[0].body.status='secret']) {const f=fixture();change(f);assert.throws(()=>run(f));}});
test('unknown schema features cannot silently disappear',()=>{const f=fixture();f.spec.paths['/api/health'].get.callbacks={};assert.throws(()=>run(f));});
test('dynamic or aliased clients cannot silently disappear',()=>{const f=fixture();assert.throws(()=>consumer(f.type,f.client.replace("()=>'/api/health'",'()=>url'),'HealthResponse'));assert.throws(()=>consumer(f.type,f.client.replace('{httpResource}','{httpResource as call}'),'HealthResponse'));});
test('duplicate observations cannot replace an uncovered status',()=>{const f=fixture();f.observations[1]=f.observations[0];assert.throws(()=>run(f),/duplicate/);});

test('extra production HTTP consumers and unsupported imports are rejected',()=>{const {consumerInventory}=require('./measure.cjs'),f=fixture();consumerInventory({'client.ts':f.client},'client.ts');assert.throws(()=>consumerInventory({'client.ts':f.client,'extra.ts':f.client},'client.ts'));assert.throws(()=>consumerInventory({'client.ts':f.client,'extra.ts':"import { HttpClient as Hidden } from '@angular/common/http';"},'client.ts'));});

test('strict CLI collection retains actual generated-client provenance',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
 const protocol=require('./protocol.cjs'),{generate}=require('./measure.cjs');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'http-contract-'));
 try {
  fs.mkdirSync(path.join(root,'api'));fs.mkdirSync(path.join(root,'web/angular/src'),{recursive:true});fs.mkdirSync(path.join(root,'evidence'));
  const f=fixture(),head=JSON.stringify(f.spec),hash=protocol.sha(head),type=generate(f.spec,'HealthResponse',hash);
  const files={'api/openapi.json':head,'web/angular/src/response.ts':type,'web/angular/src/client.ts':f.client,'observations.json':JSON.stringify(f.observations)};
  for(const [name,bytes] of Object.entries(files)) fs.writeFileSync(path.join(root,name),bytes);
  fs.writeFileSync(path.join(root,'baseline.json'),head);
  const context={commit:'1'.repeat(40),base_commit:'1'.repeat(40),target:'node',run:'test'};
  const request={schema:'harness-collector-request/v1',project:'fixture',component:'backend',collector:protocol.COLLECTOR,context,workspace_root:root,output_root:path.join(root,'evidence'),requested_capabilities:Object.keys(protocol.TYPES),parameters:{boundary:'contract',consumer_boundary:'production',consumer:'frontend',relationship:'api',contract:'api/openapi.json',type_file:'web/angular/src/response.ts',client:'web/angular/src/client.ts',type_name:'HealthResponse',consumer_source_root:'web/angular/src',exclude:[],observations:'observations.json',artifact_subdir:'contract'}};
  request.parameters.receipt={schema:'http-json-capture/v1',context,inputs:Object.fromEntries(Object.entries(files).map(([k,v])=>[k,protocol.sha(v)])),consumer_sources:Object.fromEntries(Object.entries(files).filter(([k])=>k.endsWith('.ts')).map(([k,v])=>[k,protocol.sha(v)])),baseline:{path:path.join(root,'baseline.json'),sha256:hash,commit:context.base_commit},observations_sha256:protocol.sha(files['observations.json'])};
  request.parameters.subjects=protocol.discover(request).subjects;
  fs.writeFileSync(path.join(root,'request.json'),JSON.stringify(request));
  const result=spawnSync(process.execPath,[path.join(__dirname,'cli.cjs'),'collect',path.join(root,'request.json')],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);const response=JSON.parse(result.stdout);assert.equal(response.evidence.length,2);
  assert(response.evidence.every(r=>r.contract.generated_client.contract_sha256===hash));
  request.parameters.artifact_subdir='tampered';files['web/angular/src/response.ts']=type.replace('database:','other:');
  fs.writeFileSync(path.join(root,'web/angular/src/response.ts'),files['web/angular/src/response.ts']);
  request.parameters.receipt.inputs['web/angular/src/response.ts']=protocol.sha(files['web/angular/src/response.ts']);request.parameters.receipt.consumer_sources['web/angular/src/response.ts']=protocol.sha(files['web/angular/src/response.ts']);
  assert.throws(()=>protocol.collect(request),/without regeneration/);
 } finally {fs.rmSync(root,{recursive:true,force:true});}
});
