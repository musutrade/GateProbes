'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const S=require('./schema.cjs'),C=require('./clients.cjs'),M=require('./measure.cjs');
function fixture(){
 const contract={type:'object',additionalProperties:false,required:['title','acceptance_criteria'],properties:{title:{type:'string',minLength:1},acceptance_criteria:{type:'array',minItems:1,items:{type:'object',additionalProperties:false,required:['id','expected'],properties:{id:{type:'string'},expected:{type:'string'}}}}}};
 const result={type:'object',additionalProperties:false,required:['id','version','contract'],properties:{id:{type:'string'},version:{type:'integer',minimum:1},contract:{$ref:'#/components/schemas/Contract'}}};
 const response={description:'Created',content:{'application/json':{schema:result}}};
 const post={operationId:'createRequirement',requestBody:{required:true,content:{'application/json':{schema:contract}}},responses:{201:response}};
 const patch={...post,operationId:'updateRequirement',parameters:[{in:'path',name:'id',required:true,schema:{type:'string'}}],responses:{200:response}};
 const spec={openapi:'3.0.3',info:{title:'Business',version:'1'},components:{schemas:{Contract:contract}},paths:{'/api/requirements':{post},'/api/requirements/{id}':{patch}}};
 const body={title:'A',acceptance_criteria:[{id:'AC-1',expected:'Works'}]};
 const observations=[{method:'POST',path:'/api/requirements',status:201,content_type:'application/json',request_body:body,body:{id:'one',version:1,contract:body}},{method:'PATCH',path:'/api/requirements/one',operation_path:'/api/requirements/{id}',status:200,content_type:'application/json',request_body:body,body:{id:'one',version:2,contract:body}}];
 const client="import {HttpClient} from '@angular/common/http'; class Client { private http=inject(HttpClient); create(body: CreateRequirementRequest){return this.http.post<CreateRequirementResponse>('/api/requirements',body);} update(id:string,body:UpdateRequirementRequest){return this.http.patch<UpdateRequirementResponse>(`/api/requirements/${id}`,body);} }";
 return {spec,client,observations,type:S.generate(spec,'HealthResponse','fixture')};
}
test('POST/PATCH nested contracts, path parameters and integer versions are measured',()=>{const f=fixture();const v=M.measure(f.spec,f.spec,f.type,f.client,'HealthResponse',f.observations);assert(v['contract.compatible'].value);assert.equal(C.inventory({'client.ts':f.client}).length,2);});
test('client response type widening is drift even with an unchanged generated stamp',()=>{const f=fixture();const v=M.measure(f.spec,f.spec,f.type.replaceAll('version: number','version: number | string'),f.client,'HealthResponse',f.observations);assert(v['contract.client_drift'].value);});
test('business provider failures and omitted variants remain hard failures',()=>{for(const change of [f=>f.observations.pop(),f=>f.observations[0].body.version=1.5,f=>f.observations[0].body.contract.title='',f=>delete f.observations[0].request_body,f=>f.observations[1].path='/api/other/one']){const f=fixture();change(f);assert.throws(()=>M.measure(f.spec,f.spec,f.type,f.client,'HealthResponse',f.observations));}});
test('nested schema changes count as breaking changes',()=>{const f=fixture(),base=structuredClone(f.spec);base.components.schemas.Contract.properties.title.minLength=2;const v=M.measure(base,f.spec,f.type,f.client,'HealthResponse',f.observations);assert.equal(v['contract.breaking_changes'].value,2);});
test('unbound routes, aliases, external schema references and duplicate IDs fail closed',()=>{const f=fixture();assert.throws(()=>C.inventory({'x.ts':f.client.replace('`/api/requirements/${id}`','unknownUrl')}));assert.throws(()=>C.inventory({'x.ts':f.client.replace('{HttpClient}','{HttpClient as Other}')}));for(const mutate of [s=>s.components.schemas.Contract={$ref:'https://example.com/schema'},s=>s.paths['/api/requirements/{id}'].patch.operationId='createRequirement',s=>s.paths['/api/requirements/{id}'].patch.parameters=[]]){const s=structuredClone(f.spec);mutate(s);assert.throws(()=>S.operations(s));}});
test('a new production consumer must map to the declared contract',()=>{const f=fixture();assert.throws(()=>M.consumerInventory({'client.ts':f.client,'extra.ts':f.client.replaceAll('/api/requirements','/api/missing')},'client.ts',f.spec));});
test('type-checker suppressions and indirect HttpClient uses cannot hide drift',()=>{const f=fixture();for(const text of [f.type.replaceAll('version: number','version: any'),'// @ts-nocheck\n'+f.type])assert.throws(()=>M.measure(f.spec,f.spec,text,f.client,'HealthResponse',f.observations));for(const client of [f.client.replace('return this.http.post','const alias=this.http;return alias.post'),f.client.replace('this.http.post','this.http["post"]')])assert.throws(()=>C.inventory({'client.ts':client}));});
module.exports={fixture};

test('business collection binds every production client and rejects changed capture bytes',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),P=require('./protocol.cjs');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'business-contract-'));
 try {
  fs.mkdirSync(path.join(root,'api'));fs.mkdirSync(path.join(root,'web/angular/src'),{recursive:true});fs.mkdirSync(path.join(root,'evidence'));
  const f=fixture(),head=JSON.stringify(f.spec),hash=P.sha(head);
  const files={'api/openapi.json':head,'web/angular/src/response.ts':S.generate(f.spec,'HealthResponse',hash),'web/angular/src/client.ts':f.client,'web/angular/src/second.ts':f.client,'observations.json':JSON.stringify(f.observations)};
  for(const [name,bytes] of Object.entries(files))fs.writeFileSync(path.join(root,name),bytes);
  fs.writeFileSync(path.join(root,'baseline.json'),head);
  const context={commit:'2'.repeat(40),base_commit:'2'.repeat(40),target:'node',run:'business-test'};
  const request={schema:'harness-collector-request/v1',project:'fixture',component:'backend',collector:P.COLLECTOR,context,workspace_root:root,output_root:path.join(root,'evidence'),requested_capabilities:Object.keys(P.TYPES),parameters:{boundary:'contract',consumer_boundary:'production',consumer:'frontend',relationship:'api',contract:'api/openapi.json',type_file:'web/angular/src/response.ts',client:'web/angular/src/client.ts',type_name:'HealthResponse',consumer_source_root:'web/angular/src',exclude:[],observations:'observations.json',artifact_subdir:'contract'}};
  request.parameters.receipt={schema:'http-json-capture/v1',context,inputs:Object.fromEntries(Object.entries(files).map(([k,v])=>[k,P.sha(v)])),consumer_sources:Object.fromEntries(Object.entries(files).filter(([k])=>k.endsWith('.ts')).map(([k,v])=>[k,P.sha(v)])),baseline:{path:path.join(root,'baseline.json'),sha256:hash,commit:context.base_commit},observations_sha256:P.sha(files['observations.json'])};
  request.parameters.subjects=P.discover(request).subjects;
  assert.equal(request.parameters.subjects.length,3);
  const response=P.collect(request);assert.equal(response.evidence.length,3);
  assert(response.evidence.every(r=>r.contract.generated_client.contract_sha256===hash));
  request.parameters.artifact_subdir='changed';fs.appendFileSync(path.join(root,'observations.json'),' ');
  assert.throws(()=>P.collect(request),/hash|digest|changed|mismatch/i);
 } finally {fs.rmSync(root,{recursive:true,force:true});}
});

// Functional interceptor types/providers are not HTTP calls. Their bodies still
// undergo the same recursive inventory and unsupported-client checks.
test('canonical functional interceptors retain the complete HTTP call inventory',()=>{
 const f=fixture();
 const config="import {provideHttpClient,withInterceptors} from '@angular/common/http'; const providers=[provideHttpClient(withInterceptors([authInterceptor]))];";
 const interceptor="import {HttpInterceptorFn,HttpClient,HttpErrorResponse} from '@angular/common/http'; const authInterceptor:HttpInterceptorFn=(request,next)=>{const http=inject(HttpClient);http.post<CreateRequirementResponse>('/api/requirements',{});return next(request.clone({setHeaders:{'x-csrf':'proof'}}));};";
 const sources={'client.ts':f.client,'auth.ts':interceptor,'config.ts':config};
 const calls=C.inventory(sources);assert.equal(calls.length,3);
 assert.deepEqual(calls.filter(c=>c.file==='auth.ts'),[{file:'auth.ts',method:'POST',path:'/api/requirements',typeName:'CreateRequirementResponse'}]);
 assert(M.measure(f.spec,f.spec,f.type,f.client,'HealthResponse',f.observations,sources)['contract.compatible'].value);
 const bad={...sources,'auth.ts':interceptor.replace('/api/requirements','/api/undeclared')};
 assert.throws(()=>M.consumerInventory(bad,'client.ts',f.spec),/undeclared/);
 assert(M.measure(f.spec,f.spec,f.type,f.client,'HealthResponse',f.observations,bad)['contract.client_drift'].value);
 for(const changed of [interceptor.replace('return next(',"fetch('/api/hidden');return next("),interceptor.replace('http.post', 'http["post"]')])
  assert.throws(()=>C.inventory({...sources,'auth.ts':changed}));
});
test('interceptor support does not permit aliased or unknown HTTP imports',()=>{
 for(const imports of ['HttpInterceptorFn as Interceptor','withInterceptors as middleware','HttpBackend','HttpInterceptorFn,JsonpClientBackend'])
  assert.throws(()=>C.inventory({'auth.ts':"import {"+imports+"} from '@angular/common/http';"}),/unsupported HTTP client import/);
 const source="import type {HttpInterceptorFn} from '@angular/common/http'; const interceptor:HttpInterceptorFn=(request,next)=>next(request);";
 assert.deepEqual(C.inventory({'auth.ts':source}),[]);
});

// Each mutation rewrites the capture receipt as well as the actual input bytes:
// rejection must reach inventory/type integrity, rather than an obsolete hash.
function withCliCapture(f,body){
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),P=require('./protocol.cjs');
 const retained=process.env.HARNESS_GATE_HTTP_TEST_EVIDENCE;
 if(retained)fs.mkdirSync(retained,{recursive:true});
 const root=fs.mkdtempSync(path.join(retained||os.tmpdir(),'http-integrity-'));
 const context={commit:'2'.repeat(40),base_commit:'2'.repeat(40),target:'node',run:'integrity-test'};
 const head=JSON.stringify(f.spec),hash=P.sha(head);
 const files={'api/openapi.json':head,'web/angular/src/response.ts':S.generate(f.spec,'HealthResponse',hash),'web/angular/src/client.ts':f.client,'observations.json':JSON.stringify(f.observations)};
 fs.mkdirSync(path.join(root,'web/angular/src'),{recursive:true});fs.mkdirSync(path.join(root,'api'));fs.mkdirSync(path.join(root,'evidence'));
 fs.writeFileSync(path.join(root,'baseline.json'),head);
 const request={schema:'harness-collector-request/v1',project:'fixture',component:'backend',collector:P.COLLECTOR,context,workspace_root:root,output_root:path.join(root,'evidence'),requested_capabilities:Object.keys(P.TYPES),parameters:{boundary:'contract',consumer_boundary:'production',consumer:'frontend',relationship:'api',contract:'api/openapi.json',type_file:'web/angular/src/response.ts',client:'web/angular/src/client.ts',type_name:'HealthResponse',consumer_source_root:'web/angular/src',exclude:[],observations:'observations.json',artifact_subdir:'contract'}};
 const written=new Set();
 function bind(){
  for(const name of written)if(!Object.hasOwn(files,name)){fs.unlinkSync(path.join(root,name));written.delete(name);}
  for(const [name,bytes]of Object.entries(files)){fs.writeFileSync(path.join(root,name),bytes);written.add(name);}
  request.parameters.receipt={schema:'http-json-capture/v1',context,inputs:Object.fromEntries(Object.entries(files).map(([k,v])=>[k,P.sha(v)])),consumer_sources:Object.fromEntries(Object.entries(files).filter(([k])=>k.endsWith('.ts')).map(([k,v])=>[k,P.sha(v)])),baseline:{path:path.join(root,'baseline.json'),sha256:hash,commit:context.base_commit},observations_sha256:P.sha(files['observations.json'])};
  fs.writeFileSync(path.join(root,'request.json'),JSON.stringify(request));
 }
 let invocation=0;
 function cli(mode){
  bind();
  const result=require('node:child_process').spawnSync(process.execPath,[path.join(__dirname,'cli.cjs'),mode,path.join(root,'request.json')],{encoding:'utf8'});
  const log=path.join(root,`${++invocation}-${mode}`);
  fs.writeFileSync(log+'.request.json',JSON.stringify(request,null,2));fs.writeFileSync(log+'.stdout',result.stdout||'');fs.writeFileSync(log+'.stderr',result.stderr||'');
  fs.writeFileSync(log+'.inputs.json',JSON.stringify({files,baseline:head},null,2));
  fs.writeFileSync(log+'.status.json',JSON.stringify({status:result.status,signal:result.signal,error:result.error?.message||null},null,2));
  assert.ifError(result.error);return result;
 }
 bind();
 request.parameters.subjects=P.discover(request).subjects;
 try{body({files,request,cli,root});}
 catch(error){console.error('Retained HTTP integrity fixture: '+root);throw error;}
 if(!retained)fs.rmSync(root,{recursive:true,force:true});
}

test('real discover and collect reject every indirect httpResource use across the scanned inventory',()=>{
 const f={spec:{openapi:'3.0.3',info:{title:'Resource',version:'1'},paths:{'/api/public':{get:{operationId:'getHealth',responses:{200:{description:'OK',content:{'application/json':{schema:{type:'object',additionalProperties:false,required:['state'],properties:{state:{type:'string',enum:['ok','other']}}}}}}}}}}},observations:[{method:'GET',path:'/api/public',status:200,content_type:'application/json',body:{state:'ok'}}],client:"import {httpResource} from '@angular/common/http'; const health=httpResource<HealthResponse>(()=>'/api/public');"};
 withCliCapture(f,({files,request,cli})=>{
  const canonical=files['web/angular/src/client.ts'],imports="import {httpResource} from '@angular/common/http';";
  assert.equal(cli('discover').status,0);
  assert.equal(cli('collect').status,0);
  for(const use of ["const alias=httpResource;alias<HealthResponse>(()=>'/api/public');",'consume(httpResource);','const stored={resource:httpResource};',"httpResource.call(null,()=>'/api/public');",'function shadow(httpResource:unknown){return httpResource;}','export {httpResource};']){
   for(const placement of ['alongside','other-file','only-indirect']){
    files['web/angular/src/client.ts']=placement==='only-indirect'?imports+use:canonical+(placement==='alongside'?use:'');
    delete files['web/angular/src/extra.ts'];
    if(placement==='other-file')files['web/angular/src/extra.ts']=imports+use;
    for(const mode of ['discover','collect']){
     const result=cli(mode);
     assert.equal(result.status,1,`${placement}: ${use}: ${result.stderr}`);
     assert.match(result.stderr,/unsupported (?:httpResource alias or indirect use|HTTP resource variant)/);
    }
   }
  }
  files['web/angular/src/client.ts']=canonical;delete files['web/angular/src/extra.ts'];
  request.parameters.artifact_subdir='restored';
  assert.equal(cli('discover').status,0);
  const restored=cli('collect');assert.equal(restored.status,0,restored.stderr);
 });
});

test('real CLI checks Request and uncalled Response structures with rebound receipts and unchanged stamps',()=>{
 const f=fixture(),contract=f.spec.components.schemas.Contract;
 contract.required.push('mode');contract.properties.mode={type:'string',enum:['public','other']};
 // The POST request uses the same contract object; the PATCH is a copy sharing it.
 for(const observation of f.observations){observation.request_body.mode='public';observation.body.contract.mode='public';}
 f.spec.paths['/api/unread']={get:{operationId:'unread',responses:{200:{description:'Unread',content:{'application/json':{schema:{type:'object',additionalProperties:false,required:['title','mode'],properties:{title:{type:'string'},mode:{type:'string',enum:['public','other']}}}}}}}}};
 f.observations.push({method:'GET',path:'/api/unread',status:200,content_type:'application/json',body:{title:'A',mode:'public'}});
 withCliCapture(f,({files,request,cli})=>{
  const generated=files[request.parameters.type_file],stamp=generated.split('\n')[0];
  for(const declaration of ['CreateRequirementRequest','UnreadResponse']){
   assert(!C.inventory({'client.ts':f.client}).some(call=>call.typeName===declaration));
   for(const [name,change]of [['field-type',line=>line.replace('title: string','title: number')],['required',line=>line.replace('title: string','title?: string')],['enum',line=>line.replace(/mode: ([^;]+);/,'mode: $1 | "unexpected";')]]){
    const changed=generated.split('\n').map(line=>line.startsWith('export type '+declaration+' = ')?change(line):line).join('\n');
    assert.notEqual(changed,generated,`${declaration} ${name} must change the fixture`);
    assert.equal(changed.split('\n')[0],stamp);
    files[request.parameters.type_file]=changed;
    const discovery=cli('discover');assert.equal(discovery.status,0,discovery.stderr);
    assert.deepEqual(JSON.parse(discovery.stdout).subjects,request.parameters.subjects);
    const result=cli('collect');assert.equal(result.status,1,result.stderr);
    assert.match(result.stderr,/generated type was edited without regeneration/);
   }
  }
  // Structural equivalence allows whitespace changes in the complete declarations.
  files[request.parameters.type_file]=generated.split('\n').map((line,index)=>index?'  '+line+'  ':line).join('\n');
  assert.equal(cli('discover').status,0);
  const result=cli('collect');assert.equal(result.status,0,result.stderr);
  assert.equal(JSON.parse(result.stdout).evidence.length,request.parameters.subjects.length);
 });
});
